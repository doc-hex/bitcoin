// Copyright (c) 2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include <stdio.h>
#include <unistd.h>

#include "logdb.h"

using namespace std;

// Compact integers: least-significant digit first base-128 encoding.
// The high bit in each byte signifies whether another digit follows.
// To avoid redundancy, one is subtracted from all but the first digit.
// Thus, byte sequence a[] where all but the last has bit 128 set,
// encodes the number (a[0] & 0x7F) + sum(i=1..n, 128^i*((a[i] & 0x7F)+1))

size_t static WriteInt(FILE* file, uint64 n)
{
    int nRet = 0;
    do
    {
        nRet++;
        putc((n % 128) | (n>127)*128, file);
        if (n<128)
            break;
        n = (n / 128)-1;
    } while(1);
    return nRet;
}

int static ReadInt(FILE *file)
{
    uint64_t nRet = 0;
    uint64_t nBase = 1;
    while (nBase)
    {
        int nByte = getc(file);
        nRet += nBase * ((nByte & 127) + (nBase>1));
        if (nByte < 128)
            break;
        nBase *= 128;
    }
    return nRet;
}

// File format
// 
// The file consists of a list of frames, each of which consists of:
// 4 bytes magic: 0xCC 0xC4 0xE6 0xB0
// N records, each of which consists of:
//   1 byte mode: 1=insert/overwrite, 2=erase
//   integer: key length (max 4 KiB)
//   key
//   if mode==1: integer: data length (max 1 MiB)
//   if mode==1: data
// 0 byte
// 8 bytes checksum: first 8 bytes of running SHA256

class CModEntry
{
public:
    unsigned char nMode;
    data_t key;
    data_t value;
};

bool CLogDB::Load_()
{
    do
    {
        if (feof(file))
            return true;

        if (getc(file) != 0xCC) return feof(file);
        if (getc(file) != 0xC4) return false;
        if (getc(file) != 0xE6) return false;
        if (getc(file) != 0xB0) return false;

        printf("CLogDB::Load(): frame header found\n");

        vector<CModEntry> vMod;

        // update a copy of the state, so we can revert in case of error
        SHA256_CTX ctx = ctxState;

        do
        {
            if (feof(file))
            {
                printf("CLogDB::Load(): unexpected eof at record start\n");
                return false;
            }

            CModEntry entry;
            entry.nMode = getc(file);
            if (entry.nMode > 2)
            {
                printf("CLogDB::Load(): unknown record mode\n");
                return false;
            }

            SHA256_Update(&ctx, &entry.nMode, 1);

            if (entry.nMode == 0)
                break;

            printf("CLogDB::Load(): loading record mode %i\n", entry.nMode);

            uint32_t nKeySize = ReadInt(file);
            if (nKeySize >= 0x1000)
            {
                printf("CLogDB::Load(): oversizes key (%lu bytes)\n", (unsigned long)nKeySize);
                return false;
            }
            entry.key.resize(nKeySize);
            if (fread(&entry.key[0], nKeySize, 1, file) != 1)
            {
                printf("CLogDB::Load(): unable to read key (%lu bytes)\n", (unsigned long)nKeySize);
                return false;
            }

            printf("CLogDB::load(): loading key (%.*s)\n", nKeySize, &entry.key[0]);

            SHA256_Update(&ctx, &nKeySize, 4);
            SHA256_Update(&ctx, &entry.key[0], nKeySize);

            if (entry.nMode == 1)
            {
                int nValueSize = ReadInt(file);
                if (nValueSize >= 0x100000)
                {
                    printf("CLogDB::Load(): oversized value (%lu bytes)\n", (unsigned long)nValueSize);
                    return false;
                }
                entry.value.resize(nValueSize);
                if (fread(&entry.value[0], nValueSize, 1, file) != 1)
                {
                    printf("CLogDB::Load(): unable to read value (%lu bytes)\n", (unsigned long)nValueSize);
                    return false;
                }

                SHA256_Update(&ctx, &nValueSize, 4);
                SHA256_Update(&ctx, &entry.value[0], nValueSize);
            }

            vMod.push_back(entry);
        } while(true);

        unsigned char check[8];
        if (fread(check, 8, 1, file)!=1)
        {
            printf("CLogDB::Load(): unable to read checksum\n");
            return false;
        }

        SHA256_CTX ctxFinal = ctx;

        unsigned char checkx[32];
        SHA256_Final(checkx, &ctxFinal);
        if (memcmp(check,checkx,8))
        {
            printf("CLogDB::Load(): checksum failed\n");
            return false;
        }

        // if we reach this point, the entire read frame was valid
        ctxState = ctx;

        for (vector<CModEntry>::iterator it = vMod.begin(); it != vMod.end(); it++)
        {
            CModEntry &mod = *it;
            nWritten += mod.key.size() + mod.value.size();
            switch (mod.nMode)
            {
                case 1:
                    Write_(mod.key, mod.value, true, true);
                    break;

                case 2:
                    Erase_(mod.key, true);
                    break;
            }
        }

    } while(true);

    printf("CLogDB::Load(): done\n");
}

bool CLogDB::Flush_()
{
    printf("CLogDB::Flush_()\n");

    if (setDirty.empty())
        return true;

    printf("CLogDB::Flush_(): not dirty\n");

    unsigned char magic[4]={0xCC,0xC4,0xE6,0xB0};

    if (fwrite(magic, 4, 1, file) != 1)
    {
        printf("CLogDB::Flush_(): error writing magic: %s\n", strerror(errno));
    }

    SHA256_CTX ctx = ctxState;

    for (set<data_t>::iterator it = setDirty.begin(); it != setDirty.end(); it++)
    {
        map<data_t, data_t>::iterator it2 = mapData.find(*it);

        if (it2 != mapData.end())
        {
            // update
            unsigned char nMode = 1;
            uint32_t nKeySize = (*it).size();
            uint32_t nDataSize = (*it2).second.size();
            nWritten += nKeySize + nDataSize;

            printf("CLogDB::Flush(): writing update(%.*s)\n", nKeySize, &(*it)[0]);

            putc(nMode, file);
            WriteInt(file, nKeySize);
            fwrite(&(*it)[0], nKeySize, 1, file);
            WriteInt(file, nDataSize);
            fwrite(&(*it2).second[0], nDataSize, 1, file);

            SHA256_Update(&ctx, &nMode, 1);
            SHA256_Update(&ctx, &nKeySize, 4);
            SHA256_Update(&ctx, &(*it)[0], nKeySize);
            SHA256_Update(&ctx, &nDataSize, 4);
            SHA256_Update(&ctx, &(*it2).second[0], nDataSize);
        }
        else
        {
            // erase
            unsigned char nMode = 2;
            uint32_t nKeySize = (*it).size();
            nWritten += nKeySize;

            printf("CLogDB::Flush(): writing erase(%.*s)\n", nKeySize, &(*it)[0]);

            putc(nMode, file);
            WriteInt(file, nKeySize);
            fwrite(&(*it)[0], nKeySize, 1, file);

            SHA256_Update(&ctx, &nMode, 1);
            SHA256_Update(&ctx, &nKeySize, 4);
            SHA256_Update(&ctx, &(*it)[0], nKeySize);
        }
    }

    unsigned char nMode = 0;
    putc(nMode, file);
    SHA256_Update(&ctx, &nMode, 1);

    SHA256_CTX ctxFinal = ctx;
    unsigned char buf[32];
    SHA256_Final(buf, &ctxFinal);
    fwrite(buf, 8, 1, file);
    fflush(file);
    fdatasync(fileno(file));
    ctxState = ctx;

    printf("CLogDB::Flush(): wrote frame\n");

    setDirty.clear();

    return true;
}
