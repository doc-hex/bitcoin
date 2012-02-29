// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include <openssl/ec.h>
#include <openssl/ecdsa.h>

#include "key.h"

// Generate a private key from just the secret parameter
int EC_KEY_regenerate_key(EC_KEY *eckey, BIGNUM *priv_key)
{
    int ok = 0;
    BN_CTX *ctx = NULL;
    EC_POINT *pub_key = NULL;

    if (!eckey) return 0;

    const EC_GROUP *group = EC_KEY_get0_group(eckey);

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;

    pub_key = EC_POINT_new(group);

    if (pub_key == NULL)
        goto err;

    if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx))
        goto err;

    EC_KEY_set_private_key(eckey,priv_key);
    EC_KEY_set_public_key(eckey,pub_key);

    ok = 1;

err:

    if (pub_key)
        EC_POINT_free(pub_key);
    if (ctx != NULL)
        BN_CTX_free(ctx);

    return(ok);
}

// Perform ECDSA key recovery (see SEC1 4.1.6) for curves over (mod p)-fields
// recid selects which key is recovered
// if check is nonzero, additional checks are performed
int ECDSA_SIG_recover_key_GFp(EC_KEY *eckey, ECDSA_SIG *ecsig, const unsigned char *msg, int msglen, int recid, int check)
{
    if (!eckey) return 0;

    int ret = 0;
    BN_CTX *ctx = NULL;

    BIGNUM *x = NULL;
    BIGNUM *e = NULL;
    BIGNUM *order = NULL;
    BIGNUM *sor = NULL;
    BIGNUM *eor = NULL;
    BIGNUM *field = NULL;
    EC_POINT *R = NULL;
    EC_POINT *O = NULL;
    EC_POINT *Q = NULL;
    BIGNUM *rr = NULL;
    BIGNUM *zero = NULL;
    int n = 0;
    int i = recid / 2;

    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    if ((ctx = BN_CTX_new()) == NULL) { ret = -1; goto err; }
    BN_CTX_start(ctx);
    order = BN_CTX_get(ctx);
    if (!EC_GROUP_get_order(group, order, ctx)) { ret = -2; goto err; }
    x = BN_CTX_get(ctx);
    if (!BN_copy(x, order)) { ret=-1; goto err; }
    if (!BN_mul_word(x, i)) { ret=-1; goto err; }
    if (!BN_add(x, x, ecsig->r)) { ret=-1; goto err; }
    field = BN_CTX_get(ctx);
    if (!EC_GROUP_get_curve_GFp(group, field, NULL, NULL, ctx)) { ret=-2; goto err; }
    if (BN_cmp(x, field) >= 0) { ret=0; goto err; }
    if ((R = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
    if (!EC_POINT_set_compressed_coordinates_GFp(group, R, x, recid % 2, ctx)) { ret=0; goto err; }
    if (check)
    {
        if ((O = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
        if (!EC_POINT_mul(group, O, NULL, R, order, ctx)) { ret=-2; goto err; }
        if (!EC_POINT_is_at_infinity(group, O)) { ret = 0; goto err; }
    }
    if ((Q = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
    n = EC_GROUP_get_degree(group);
    e = BN_CTX_get(ctx);
    if (!BN_bin2bn(msg, msglen, e)) { ret=-1; goto err; }
    if (8*msglen > n) BN_rshift(e, e, 8-(n & 7));
    zero = BN_CTX_get(ctx);
    if (!BN_zero(zero)) { ret=-1; goto err; }
    if (!BN_mod_sub(e, zero, e, order, ctx)) { ret=-1; goto err; }
    rr = BN_CTX_get(ctx);
    if (!BN_mod_inverse(rr, ecsig->r, order, ctx)) { ret=-1; goto err; }
    sor = BN_CTX_get(ctx);
    if (!BN_mod_mul(sor, ecsig->s, rr, order, ctx)) { ret=-1; goto err; }
    eor = BN_CTX_get(ctx);
    if (!BN_mod_mul(eor, e, rr, order, ctx)) { ret=-1; goto err; }
    if (!EC_POINT_mul(group, Q, eor, R, sor, ctx)) { ret=-2; goto err; }
    if (!EC_KEY_set_public_key(eckey, Q)) { ret=-2; goto err; }

    ret = 1;

err:
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (R != NULL) EC_POINT_free(R);
    if (O != NULL) EC_POINT_free(O);
    if (Q != NULL) EC_POINT_free(Q);
    return ret;
}

bool CDetKey::CalcPubKey()
{
    if (!fHavePubKey)
    {
        if (!fHaveSecret)
            return false;
        CKey key;
        key.SetSecret(secret, fCompressed);
        vchPubKey = key.GetPubKey();
        fHavePubKey = true;
    }
    return true;
}


bool CDetKey::SetMaster(const std::vector<unsigned char>& vchMaster, bool fCompressedIn)
{
    fCompressed = fCompressedIn;
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    SHA512_Update(&ctx, &vchMaster[0], vchMaster.size());
    unsigned char vchBuffer[64];
    SHA512_Final(vchBuffer, &ctx);
    secret.resize(32);
    vchChaincode.resize(32);
    memcpy(&secret[0], &vchBuffer[0], 32);
    memcpy(&vchChaincode[0], &vchBuffer[32], 32);
    vchPubKey.clear();
    fHaveSecret = true;
    fHavePubKey = false;
    return true;
}

bool CDetKey::SetPublic(const std::vector<unsigned char>& vchChaincodeIn, const std::vector<unsigned char>& vchPubKeyIn)
{
    fCompressed = (vchPubKeyIn.size() < 65);
    vchChaincode = vchChaincodeIn;
    vchPubKey = vchPubKeyIn;
    secret.clear();
    fHaveSecret = false;
    fHavePubKey = true;
    return true;
}

bool CDetKey::SetSecret(const std::vector<unsigned char>& vchChaincodeIn, const CSecret &secretIn, const std::vector<unsigned char> *pvchPubKeyIn, bool fCompressedIn)
{
    fCompressed = fCompressedIn;
    vchChaincode = vchChaincodeIn;
    secret = secretIn;
    fHaveSecret = true;
    if (pvchPubKeyIn)
    {
        vchPubKey = *pvchPubKeyIn;
        fHavePubKey = true;
    }
    else
    {
        vchPubKey.clear();
        fHavePubKey = false;
    }
    return true;
}

bool CDetKey::GetPubKey(std::vector<unsigned char> &vchPubKeyOut)
{
    if (!CalcPubKey())
        return false;
    vchPubKeyOut = vchPubKey;
    return true;
}

bool CDetKey::GetSecret(CSecret& secretOut, bool &fCompressedOut) const
{
    if (!fHaveSecret)
        return false;
    fCompressedOut = fCompressed;
    secretOut = secret;
    return true;
}

bool CDetKey::Neuter(CDetKey& keyOut)
{
    if (!CalcPubKey())
        return false;
    keyOut.vchChaincode = vchChaincode;
    keyOut.fCompressed = fCompressed;
    keyOut.vchPubKey = vchPubKey;
    keyOut.fHavePubKey = fHavePubKey;
    keyOut.secret.clear();
    keyOut.fHaveSecret = false;
    return true;
}

bool CDetKey::Derive(CDetKey& keyOut, int n)
{
    // make sure we have the public key
    if (!CalcPubKey())
        return false;

    // calculate vchChain = HMAC-SHA512(key=vchChaincode, msg=vchPubKey+n)
    unsigned char vchChain[64];
    unsigned char vchNum[4];
    vchNum[3] = n & 0xFF; n >>= 8; vchNum[2] = n & 0xFF; n >>= 8; vchNum[1] = n & 0xFF; n >>= 8; vchNum[0] = n & 0xFF;
    HMAC_SHA512_CTX ctxHmac;
    HMAC_SHA512_Init(&ctxHmac, &vchChaincode[0], vchChaincode.size());
    HMAC_SHA512_Update(&ctxHmac, &vchPubKey[0], vchPubKey.size());
    HMAC_SHA512_Update(&ctxHmac, vchNum, 4);
    HMAC_SHA512_Final(vchChain, &ctxHmac);

    // Copy fCompressed
    keyOut.fCompressed = fCompressed;

    // set new vchChaincode = vchChain[32..64]
    keyOut.vchChaincode.resize(32);
    memcpy(&keyOut.vchChaincode[0], &vchChain[32], 32);

    // derive new vchPubKey or secret
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *bnM = BN_bin2bn(&vchChain[0],32,BN_CTX_get(ctx));
    const EC_GROUP *group = EC_KEY_get0_group(key);
    if (fHaveSecret)
    {
        // Derive new secret using known secret
        BIGNUM *bn = BN_bin2bn(&secret[0],32,BN_CTX_get(ctx));
        BIGNUM *order = BN_CTX_get(ctx);
        EC_GROUP_get_order(group, order, ctx);
        BN_mod_mul(bn, bnM, bn, order, ctx);
        keyOut.secret.clear();
        keyOut.secret.resize(32);
        keyOut.fHaveSecret = true;
        int nBytes = BN_num_bytes(bn);
        BN_bn2bin(bn,&keyOut.secret[32 - nBytes]);
        keyOut.vchPubKey.clear();
        keyOut.fHavePubKey = false;
    }
    else
    {
        // Derive new pubkey using known pubkey
        const unsigned char *pbegin = &vchPubKey[0];
        o2i_ECPublicKey(&key, &pbegin, vchPubKey.size());
        const EC_POINT *point1 = EC_KEY_get0_public_key(key);
        EC_POINT *point2 = EC_POINT_new(group);
        EC_POINT_mul(group, point2, NULL, point1, bnM, ctx);
        EC_KEY_set_public_key(key, point2);
        if (fCompressed)
            EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);
        unsigned int nSize = i2o_ECPublicKey(key, NULL);
        keyOut.vchPubKey.resize(nSize);
        unsigned char *pbeginOut = &keyOut.vchPubKey[0];
        i2o_ECPublicKey(key, &pbeginOut);
        keyOut.fHavePubKey = true;
        keyOut.secret.clear();
        keyOut.fHaveSecret = false;
        EC_POINT_free(point2);
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EC_KEY_free(key);
    return true;
}
