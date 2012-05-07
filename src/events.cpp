// Copyright (c) 2012 BTCLook.com
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "headers.h"
#include "db.h"
#include "net.h"
#include "init.h"
#include "events.h"
#include <poll.h>

#undef printf
#define printf OutputDebugStringF

// We track only a socket # for each client
#define MAX_CLIENTS		8
static SOCKET	clients[MAX_CLIENTS];
static int numClients;

// Send a message at least this often
#define HEARTBEAT_RATE		30			// seconds

static void broadcast(const char *fmt, ...)
{
	char *msg = NULL;
	va_list ap;

	// Broadcast the same message to all clients. It's few lines of text.

	// render it
	va_start(ap, fmt);
	int len = vasprintf(&msg, fmt, ap);
	va_end(ap);

	if(!msg) return;			// too long!? no memory!

	//printf("EVENT: %s\n", msg);

	int left = numClients;
	for(int i=0; i<MAX_CLIENTS && left; i++) {
		if(clients[i] == SOCKET_ERROR) continue;

		left--;
		if(::write(clients[i], msg, len) != len) {
			// error, so hang up
			close(clients[i]);
			clients[i] = SOCKET_ERROR;
		}
	}

	free(msg);
}

static void eventNewTxn(const CTransaction& txn)
{
	std::string hash = txn.GetHash().ToString();
	int len = txn.GetSerializeSize();

	// take a copy of the txn bit's in base64 format
    CDataStream ss(SER_NETWORK);
    ss.reserve(1000);
    ss << txn;
	std::string b64 = EncodeBase64((unsigned char*)&ss[0], ss.size());

	broadcast("txn %s %d %s\n", hash.c_str(), len, b64.c_str());
}

static void eventTxnReplaced(uint256 txnHash)
{
	std::string hash = txnHash.ToString();

	broadcast("replaced %s\n", hash.c_str());
}

static void eventNewBlock(const CBlock& block)
{
	std::string hash = block.GetHash().ToString();
	int len = block.GetSerializeSize();
    const CBlockIndex* index = pblockstore->GetBestBlockIndex();

	broadcast("block %s %d\nheight %d %s\n", hash.c_str(), len, 
		index->nHeight, index->GetBlockHash().ToString().c_str());
}


static void ThreadEvents2(void* parg)
{
	//
	// Startup and main loop for event server.
	//

    int nOne = 1;
    printf("Events server thread started\n");

	int port = GetArg("-eventsport", 0);
	assert(port);			// or should not have gotten here

	// Setup classic socket server... no auth, localhost only. Use SSH if you want
	// authetication; would be easy to extend this a little to take a challenge/response.
	SOCKET listenFd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(listenFd == INVALID_SOCKET) {
	fail:
		printf("Unable to setup events port: %s\n", strerror(errno));
		if(listenFd != INVALID_SOCKET) close(listenFd);

		return;
	}

#ifdef SO_NOSIGPIPE
    // Different way of disabling SIGPIPE on BSD
    setsockopt(listenFd, SOL_SOCKET, SO_NOSIGPIPE, (void*)&nOne, sizeof(int));
#endif

#ifndef WIN32
    // Allow binding if the port is still in TIME_WAIT state after
    // the program was closed and restarted.  Not an issue on windows.
    setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, (void*)&nOne, sizeof(int));
#endif

#ifdef WIN32
    // Set to nonblocking, incoming connections will also inherit this
    if(ioctlsocket(listenFd, FIONBIO, (u_long*)&nOne) == SOCKET_ERROR)
#else
    if(fcntl(listenFd, F_SETFL, O_NONBLOCK) == SOCKET_ERROR)
#endif
	{
		goto fail;
	}

    // The sockaddr_in structure specifies the address family,
    // IP address, and port for the socket that is being bound.
    struct sockaddr_in sockaddr;
    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); 		// == 127.0.0.1 == localhost
    sockaddr.sin_port = htons(port);
    if(::bind(listenFd, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == SOCKET_ERROR) {
		// this one could fail if some else is using the port.
		printf("Port %d seems busy?\n", port);

        goto fail;
    }

    // Listen for incoming connections
    if(listen(listenFd, SOMAXCONN) == SOCKET_ERROR) goto fail;


	// Just need to track a socket for each client. Stateless.
	for(int i=0; i<MAX_CLIENTS; i++) {
		clients[i] = SOCKET_ERROR;
	}

	// Poll stucture used only for incoming connections, because all other
	// sockets are write-only, and will close on any error.
	struct pollfd		listenPoll;
	listenPoll.fd = listenFd;
	listenPoll.events = POLLIN;

	// Setup callbacks for events which we report.
    pblockstore->RegisterCommitTransactionToMemoryPool(&eventNewTxn);
    pblockstore->RegisterTransactionReplaced(&eventTxnReplaced);
    pblockstore->RegisterCommitBlock(&eventNewBlock);
	
    printf("Events server thread running, listening on port %d\n", port);
	int heartbeat = HEARTBEAT_RATE;
	while(!fShutdown) {
		// block for a while waiting for connections.
		int count = poll(&listenPoll, 1, 1000);			// keep at one second, please

		if(count == 1) {
			// accept a new client.
			int slot = 0;
			for(; slot<MAX_CLIENTS; slot++) {
				if(clients[slot] == SOCKET_ERROR) break;
			}
			if(slot == MAX_CLIENTS) {
				// no space: kill them all.. just because I'm like that
				for(int i=0; i<MAX_CLIENTS; i++) {
					close(clients[i]);

					clients[i] = SOCKET_ERROR;
				}

				slot = 0;
			}
				
			// accept new socket
			int fd = accept(listenFd, NULL, NULL);
			if(fd == SOCKET_ERROR) continue;

			// Set socket to non-blocking
#ifdef WIN32
			u_long nOne = 1;
			ioctlsocket(fd, FIONBIO, &nOne);
#else
			fcntl(fd, F_SETFL, O_NONBLOCK);
#endif

			// we won't ever need to read it, ever; so close that half
			shutdown(fd, SHUT_RD);

			// send a welcome message, and some basic stats to start
			char welcome[256];
			sprintf(welcome, "welcome 1\ntestnet %d\npeers %d\n", !!fTestNet, (int)vNodes.size());
			::write(fd, welcome, strlen(welcome));

			// do this last, in case of concurrency issues.
			clients[slot] = fd;
			numClients++;

			printf("Events clients now: %d\n", numClients);

			continue;
		}
		if(count != 0) continue;

		// we waited. show some heartbeat
		heartbeat--;
		if(heartbeat <= 0) {
			broadcast("peers %d\npoolsize %d\n",
					(int)vNodes.size(), (int)pblockstore->GetPooledTxSize());

			heartbeat = HEARTBEAT_RATE;

			// update # of clients
			int active = 0, oldActive = numClients;
			for(int i=0; i<MAX_CLIENTS; i++) {
				if(clients[i] != SOCKET_ERROR) active++;
			}
			numClients = active;

			if(oldActive && !active) {
				printf("No more listening events clients.\n");
			}
		}
	}

	broadcast("stop\n");

	// shutdown sockets
	close(listenFd);
	for(int i=0; i<MAX_CLIENTS; i++) {
		if(clients[i] == SOCKET_ERROR) continue;
		close(clients[i]);
	}
}

void ThreadEvents(void* parg)
{
	// Entry point for thread startup
	//

    IMPLEMENT_RANDOMIZE_STACK(ThreadEvents(parg));
    try
    {
        vnThreadsRunning[THREAD_EVENTS]++;
        ThreadEvents2(parg);
        vnThreadsRunning[THREAD_EVENTS]--;
    }
    catch (std::exception& e) {
        vnThreadsRunning[THREAD_EVENTS]--;
        PrintException(&e, "ThreadEvents()");
    } catch (...) {
        vnThreadsRunning[THREAD_EVENTS]--;
        PrintException(NULL, "ThreadEvents()");
    }

    printf("ThreadEvents exiting\n");
}

// EOF
