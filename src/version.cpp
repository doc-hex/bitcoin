// Copyright (c) 2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
#include <string>

#include "version.h"

// Name of client reported in the 'version' message. Report the same name
// for both bitcoind and bitcoin-qt, to make it harder for attackers to
// target servers or GUI users specifically.
const std::string CLIENT_NAME("Satoshi");

// Client version number
#define CLIENT_VERSION_MAJOR          0
#define CLIENT_VERSION_MINOR          6
#define CLIENT_VERSION_REVISION       0
#define CLIENT_VERSION_BUILD         99
#define CLIENT_VERSION_SUFFIX   "-beta"

const int CLIENT_VERSION = 1000000 * CLIENT_VERSION_MAJOR
                         +   10000 * CLIENT_VERSION_MINOR 
                         +     100 * CLIENT_VERSION_REVISION
                         +       1 * CLIENT_VERSION_BUILD;

#ifdef HAVE_BUILD_INFO
#    include "build.h"
#endif

// git will put "#define GIT_ARCHIVE 1" on the next line inside archives. $Format:%n#define GIT_ARCHIVE 1$
#ifdef GIT_ARCHIVE
#    define GIT_COMMIT "$Format:%h$"
#endif

#define STRINGIFY(s) #s

#define BUILD_STRING_FROM_COMMIT(maj,min,rev,build,commit) \
    "v" STRINGIFY(maj) "." STRINGIFY(min) "." STRINGIFY(rev) "." STRINGIFY(build) "-g" commit

#define BUILD_STRING_FROM_UNKNOWN(maj,min,rev,build) \
    "v" STRINGIFY(maj) "." STRINGIFY(min) "." STRINGIFY(rev) "." STRINGIFY(build) "-unk"

#define BUILD_STRING_FROM_DESC(desc) \
    desc

#ifndef BUILD_STRING
#    ifdef BUILD_DESC
#        define BUILD_STRING BUILD_STRING_FROM_DESC(BUILD_DESC)
#    else
#        ifdef GIT_COMMIT
#            define BUILD_STRING BUILD_STRING_FROM_COMMIT(CLIENT_VERSION_MAJOR, CLIENT_VERSION_MINOR, CLIENT_VERSION_REVISION, CLIENT_VERSION_BUILD, GIT_COMMIT)
#        else
#            define BUILD_STRING BUILD_STRING_FROM_UNKNOWN(CLIENT_VERSION_MAJOR, CLIENT_VERSION_MINOR, CLIENT_VERSION_REVISION, CLIENT_VERSION_BUILD)
#        endif
#    endif
#endif

const std::string CLIENT_BUILD(BUILD_STRING CLIENT_VERSION_SUFFIX);
