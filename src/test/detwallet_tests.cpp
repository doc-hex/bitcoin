#include <boost/test/unit_test.hpp>

#include "key.h"
#include "util.h"
#include "base58.h"

using namespace std;

BOOST_AUTO_TEST_SUITE(detwallet_tests)

// derive [master=0]/0/0/0/...
BOOST_AUTO_TEST_CASE(hdw_testvector0)
{
    vector<unsigned char> vchMaster = ParseHex("0000000000000000000000000000000000000000000000000000000000000000");
    CDetKey keyPrivate;
    BOOST_CHECK(keyPrivate.SetMaster(vchMaster, true));
    CDetKey keyPublic;
    BOOST_CHECK(keyPrivate.Neuter(keyPublic));

    static const string vszPubKeys[] =
    {
        "03f67b44df55f564f3f9f36a77c8465de190cc1dba6366e0c1ce18f62752f1f597",
        "036dc03b2f07370b5baaef9ba73e9453baef255f375775c4de1540f7271c98d1eb",
        "024b807d0a3c355a838c4b7774757dd0ee45d6f1136f687538cf5059dcbb38ef38",
        "0307d04ba407eef7b1eda56926005cf6b8bb54747129088ef3db8d4e7dcdc1dc25",
        "03598d41b7763cc8d3f1817f5fcc4dc12cc9a57824fada72f7077aa28689da459f",
        "0341d28aeebe1d4b4bd33d4a44e2e445f0b8cb342dc4b92af266d07f1833b993c7",
        "0355adba16eff5436c17e8c587f375b1feb1ec3ca45c52f55c7e3e9afd93e8b4fb",
        "03027e4cd81b5f43f7ee0c6c2e4538b2451bac2424c03861ae93caa9ccab608133",
    };
    for (int n=0; n<sizeof(vszPubKeys)/sizeof(vszPubKeys[0]); n++)
    {
        vector<unsigned char> vchCheck = ParseHex(vszPubKeys[n]);
        CSecret secret;
        bool fCompressed;
        BOOST_CHECK(keyPrivate.GetSecret(secret, fCompressed));
        CKey key;
        key.SetSecret(secret, fCompressed);
        BOOST_CHECK(key.GetPubKey() == vchCheck);
        vector<unsigned char> vchPubKey;
        BOOST_CHECK(keyPublic.GetPubKey(vchPubKey));
        BOOST_CHECK(vchPubKey == vchCheck);
        BOOST_CHECK(keyPrivate.Derive(keyPrivate, 0));
        BOOST_CHECK(keyPublic.Derive(keyPublic, 0));
    }
}

// derive [master=0x0123...]/0x12345678/0x12345678/...
BOOST_AUTO_TEST_CASE(hdw_testvector1)
{
    vector<unsigned char> vchMaster = ParseHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CDetKey keyPrivate;
    BOOST_CHECK(keyPrivate.SetMaster(vchMaster, false));
    CDetKey keyPublic;
    BOOST_CHECK(keyPrivate.Neuter(keyPublic));

    static const string vszPubKeys[] =
    {
        "0465232f8c57947d0bee67187603ecb435902f569b71f5c5b31fdad42f2b60fea3bbe783b7e6269913fc3721310e7e0983577c00e38fa591d88f075cc7e6664e47",
        "040cb57582e37f42635cf2b9ee21e7c120ea5629208d02f5f722be0684e8c450dd84fa4b4531f98453ee056f84ecd394a4ae27f9100f6bb0e5ea35baf8d2135d4b",
        "04943756a7874e79b840383ba9f2fc37d93ed9837f4e1fcc1732ac6592f4194d879a02bbaeb20018c9c23c6d045d99488b444cb44a424c35ec47a75641a1a1710d",
        "04e2db6b4a01f9a02f546fad07b4254a2c466cea48b67bb3d9da4a91c8aabf381a780b4f2a55c3974432c159396f500f4a7cb31f26017c45414edba68a589f87c6",
        "04232f630be015302f57078b5d448d5565c7ea1b8a2d9bea4effee42a8e210c3965e01327ff2e1854494a68d3705d0017a4974e27c260b6485bcd166534929b7c5",
        "04024ee378d4fedb3ef021acafaf5af459543354d44e88a783b55c0be96c43922ad2465ca608cb3520351a1b3fe5bbce60f4c6a6550647d893bdfb5acf94eaa6e0",
        "047373f6c56672a01bd227b5b088dbf200735ad851adadec4f9d3b4fd833bead671e8856610f8fcae9d64e04f3fd04c84826f9a193f4a58a3b178ce180f9eb42a1",
        "04179e3a5763b0cd1b0e4fa2edb077fb12cc3d84aca89f9951b5c6183aeeb7a3e8e116b94e94c98d07bb118d3a54b1c57282f5ea2ff680461c857dd374e608f1f3",
    };
    for (int n=0; n<sizeof(vszPubKeys)/sizeof(vszPubKeys[0]); n++)
    {
        vector<unsigned char> vchCheck = ParseHex(vszPubKeys[n]);
        CSecret secret;
        bool fCompressed;
        BOOST_CHECK(keyPrivate.GetSecret(secret, fCompressed));
        CKey key;
        key.SetSecret(secret, fCompressed);
        BOOST_CHECK(key.GetPubKey() == vchCheck);
        vector<unsigned char> vchPubKey;
        BOOST_CHECK(keyPublic.GetPubKey(vchPubKey));
        BOOST_CHECK(vchPubKey == vchCheck);
        BOOST_CHECK(keyPrivate.Derive(keyPrivate, 0x12345678));
        BOOST_CHECK(keyPublic.Derive(keyPublic, 0x12345678));
    }
}

BOOST_AUTO_TEST_SUITE_END()
