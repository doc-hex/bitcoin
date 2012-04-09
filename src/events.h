// Copyright (c) 2012 BTCLook.com
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

// Config file settings
//
//   -eventsport=1234			TCP port to use, set to zero to disable feature (the default)
//

// Protocol spec:
//
//	- text only. messages separated by newline (unix: \n)
//  - server transmits only. never receives nothing. localhost port only
//  - do not rely on messages order
//	- expect at least one message every minute
//	- ignore lines you don't understand
//
// Messages:
//
//		welcome V			- welcome message, always first. V is a version number (integer)
//		peers N				- number of connected bitcoin peers
//		poolsize C			- number of transactions in memory pool right now
//		testnet T			- are we on testnet? if yes, then T=1, else 0
//		height HEIGHT HASH 	- reports current height/depth (distance to genesis), plus top-block hash
//		replaced HASH		- a transaction has been replaced. (rare?)
// 		block HASH len		- new block has been accepted. probably new top of chain
// 		txn HASH len		- new transaction accepted into mempool
//

// Starts a thread to do this. Call if configured to start..
void ThreadEvents(void* parg);

// EOF
