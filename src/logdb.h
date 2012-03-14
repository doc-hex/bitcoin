// Copyright (c) 2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef _BITCOIN_LOGDB_H_
#define _BITCOIN_LOGDB_H_

#include "util.h"
#include "serialize.h"

#include <map>
#include <set>

typedef std::vector<unsigned char> data_t;

class CLogDB
{
public:
    typedef data_t key_type;
    typedef data_t value_type;
    typedef std::map<key_type, value_type>::iterator iterator;
    typedef std::map<key_type, value_type>::const_iterator const_iterator;

private:
    mutable CCriticalSection cs;
    FILE *file;
    bool fReadOnly;
    SHA256_CTX ctxState;

    // database
    std::map<data_t, data_t> mapData;
    size_t nUsed; // continuously updated
    size_t nWritten; // updated when writing a new block

    // cached changes
    std::set<data_t> setDirty;


protected:
    void Init_()
    {
        file = NULL;
        fReadOnly = false;
        SHA256_Init(&ctxState);
        mapData.clear();
        nUsed = 0;
        nWritten = 0;
        setDirty.clear();
    }

    bool Load_();
    bool Write_(const data_t &key, const data_t &value, bool fOverwrite = true, bool fLoad = false)
    {
        if (fReadOnly && !fLoad)
            return false;

        // update nUsed
        std::map<data_t, data_t>::iterator it = mapData.find(key);
        if (it != mapData.end())
        {
            if ((*it).second == value)
                return true;

            if (!fOverwrite)
                return false;
            nUsed -= (*it).first.size() + (*it).second.size();
        }
        nUsed += key.size() + value.size();

        // update data
        mapData.insert(make_pair(key, value));
        if (!fLoad)
            setDirty.insert(key);

        return true;
    }
    bool Read_(const data_t &key, data_t &value) const
    {
        std::map<data_t, data_t>::const_iterator it = mapData.find(key);
        if (it == mapData.end())
            return false;

        value = (*it).second;

        return true;
    }
    bool Exists_(const data_t &key) const
    {
        return mapData.count(key) > 0;
    }
    bool Erase_(const data_t &key, bool fLoad = false)
    {
        if (fReadOnly && !fLoad)
            return false;

        std::map<data_t, data_t>::iterator it = mapData.find(key);
        if (it != mapData.end())
        {
            nUsed -= (*it).first.size() + (*it).second.size();
            mapData.erase(it);
            if (!fLoad)
                setDirty.insert(key);
        }

        return true;
    }
    bool Flush_();
    bool Close_()
    {
        if (file)
        {
            Flush_();
            fclose(file);
            Init_();
        }
        return true;
    }

public:
    CLogDB()
    {
        Init_();
    }

    ~CLogDB()
    {
        Close_();
    }

    bool Open(const char *pszFile, bool fCreate = true, bool fReadOnlyIn = false)
    {
        CRITICAL_BLOCK(cs)
        {
            Close_();

            fReadOnly = fReadOnlyIn;

            file = fopen(pszFile, fReadOnly ? "rb" : (fCreate ? "a+b" : "r+b"));

            if (file == NULL)
            {
                printf("Error opening %s: %s\n", pszFile, strerror(errno));
                return false;
            }

            return Load_();
        }
        return true;
    }

    template<typename K, typename V>
    bool Write(const K &key, const V &value, bool fOverwrite = true)
    {
        CDataStream ssk(SER_DISK);
        ssk << key;
        data_t datak(ssk.begin(), ssk.end());
        CDataStream ssv(SER_DISK);
        ssv << value;
        data_t datav(ssv.begin(), ssv.end());
        CRITICAL_BLOCK(cs)
            return Write_(datak, datav, fOverwrite);
        return false;
    }

    template<typename K, typename V>
    bool Read(const K &key, V &value) const
    {
        CDataStream ssk(SER_DISK);
        ssk << key;
        data_t datak(ssk.begin(), ssk.end());
        data_t datav;
        CRITICAL_BLOCK(cs)
            if (!Read_(datak,datav))
                return false;
        CDataStream ssv(datav, SER_DISK);
        ssv >> value;
        return true;
    }

    template<typename K>
    bool Exists(const K &key) const
    {
        CDataStream ssk(SER_DISK);
        ssk << key;
        data_t datak(ssk.begin(), ssk.end());
        CRITICAL_BLOCK(cs)
            return Exists_(datak);
        return false;
    }

    template<typename K>
    bool Erase(const K &key)
    { 
        CDataStream ssk(SER_DISK);
        ssk << key;
        data_t datak(ssk.begin(), ssk.end());
        CRITICAL_BLOCK(cs)
            return Erase_(datak);
        return false;
    }

    bool Flush()            { CRITICAL_BLOCK(cs) return Flush_();          return false; }
    bool Close()            { CRITICAL_BLOCK(cs) return Close_();          return false; }
    bool IsDirty() const    { CRITICAL_BLOCK(cs) return !setDirty.empty(); return false; }
    bool IsOpen() const     { return file != NULL; }
    bool IsReadOnly() const { return fReadOnly; }

    const_iterator begin() const { return mapData.begin(); }
    const_iterator end() const   { return mapData.end(); }
};

#endif
