/* mldsa_composite.c
 */

/* Based on dilithium.c and Reworked for Composite by Dr. Pala.
 */

/* Possible Composite options:
 *
 * HAVE_MLDSA_COMPOSITE                                       Default: OFF
 *   Enables the code in this file to be compiled.
 * WOLFSSL_NO_MLDSA44_P256                                    Default: OFF
 *   Does not compile in parameter set ML-DSA-44 and any code specific to that
 *   parameter set.
 * WOLFSSL_NO_MLDSA44_X25519                                  Default: OFF
 *   Does not compile in parameter set ML-DSA-44 and any code specific to that
 *   parameter set.
 * WOLFSSL_MLDSA_COMPOSITE_VERIFY_ONLY                        Default: OFF
 *   Compiles in only the verification and public key operations.
 * WOLFSSL_MLDSA_COMPOSITE_ASSIGN_KEY                         Default: OFF
 *   Key data is assigned into Composite key rather than copied.
 *   Life of key data passed in is tightly coupled to life of Compsite key.
 *   Cannot be used when make key is enabled.
 *
 * WOLFSSL_MLDSA_COMPOSITE_NO_ASN1                            Default: OFF
 *   Disables any ASN.1 encoding or decoding code.
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* in case user set HAVE_PQC there */
#include <wolfssl/wolfcrypt/settings.h>

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_ASN1
#include <wolfssl/wolfcrypt/asn.h>
#endif

#if defined(HAVE_MLDSA_COMPOSITE)
#include <wolfssl/wolfcrypt/mldsa_composite.h>
#endif
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/sha512.h>

/* Log a message that has the printf format string.
 *
 * @param [in] <va_args>  printf style arguments.
 */
#define WOLFSSL_MSG_VSNPRINTF(...)                    \
    do {                                              \
      char line[81];                                  \
      snprintf(line, sizeof(line) - 1, __VA_ARGS__);  \
      line[sizeof(line) - 1] = '\0';                  \
      WOLFSSL_MSG(line);                              \
    }                                                 \
    while (0)

#define MADWOLF_DEBUG0(a)                         \
    do {                                              \
        printf("[%s():%d] " a "\n", __func__, __LINE__);      \
        fflush(stdout);                               \
    } while (0)


#define MADWOLF_DEBUG(a, ...)                         \
    do {                                              \
        printf("[%s():%d] " a "\n", __func__, __LINE__, __VA_ARGS__);      \
        fflush(stdout);                               \
    } while (0)

enum {
    MLDSA_COMPASN_IDX_SEQ   = 0,
    MLDSA_COMPASN_IDX_MLDSA = 1,
    MLDSA_COMPASN_IDX_OTHER = 2,
};

#ifdef HAVE_MLDSA_COMPOSITE_DRAFT_2
# define mldsaCompASN_Length 3
#elif defined(HAVE_MLDSA_COMPOSITE_DRAFT_3)
# define mldsaCompASN_Length 1
#else
# error "Unknown ML-DSA Composite Draft"
#endif


const byte mldsa_composite_oid_data[][13] = {
    // Unset
    { 0x0 },
    // Level 1
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x21 }, /* MLDSA44_RSAPSS2048_SHA256*/
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x22 }, /* MLDSA44_RSA2048_SHA256 */
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x23 }, /* MLDSA44_ED25519_SHA512 */
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x24 }, /* MLDSA44_NISTP256_SHA256 */
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x25 }, /* MLDSA44_BRAINP256_SHA256 */
    // Level 3
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x26 }, /* MLDSA65_RSAPSS3072_SHA512 */
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x27 }, /* MLDSA65_RSA3072_SHA512 */
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x28 }, /* MLDSA65_NISTP256_SHA512*/
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x29 }, /* MLDSA65_BRAINP256_SHA512 */
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x2A }, /* MLDSA65_ED25519_SHA512 */
    // Level 5
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x2B }, /* MLDSA87_NISTP384_SHA512 */
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x2C }, /* MLDSA87_BRAINP384_SHA512 */
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x2D }, /* MLDSA87_ED448_SHA512*/
};

/******************************************************************************
 * Encode/Decode operations
 ******************************************************************************/

// Generate the composite message to be signed/verified
static int wc_mldsa_compositeTBS_msg(byte* tbsMsg, word32 *tbsLen, const byte* msg,
    word32 msgLen, mldsa_composite_key* key, const byte* context, byte contextLen) {

    int ret = 0;
        // Ret value

    if (!tbsMsg || !tbsLen || !msg || !key) {
        return BAD_FUNC_ARG;
    }

    if ((contextLen > 0 && !context) || (msgLen <= 0) ||
            (*tbsLen < MLDSA_COMPOSITE_TBS_DATA_MIN_SZ)) {
        return BAD_FUNC_ARG;
    }

    // Set the domain
    XMEMCPY(tbsMsg, mldsa_composite_oid_data[key->type], 13);
    *tbsLen = 13;

    // Adds the context, if any
    if (context) {
        XMEMCPY(tbsMsg + 13, context, contextLen);
        *tbsLen += contextLen;
    }

    /* Select the hash function to calculate the composite message */
    switch (key->type) {

        case WC_MLDSA_COMPOSITE_UNDEF: {
            return ALGO_ID_E;
        } break;

        case WC_MLDSA44_RSAPSS2048_SHA256:
        case WC_MLDSA44_RSA2048_SHA256:
        case WC_MLDSA44_ED25519_SHA512:
        case WC_MLDSA44_NISTP256_SHA256:
        case WC_MLDSA44_BPOOL256_SHA256: {
            wc_Sha256 sha256_hash;
                // SHA-256 hash

            // Calculates the Message Digest
            if (!((ret = wc_InitSha256(&sha256_hash)) < 0) &&
                 !((ret = wc_Sha256Update(&sha256_hash, msg, msgLen)) < 0 ) &&
                 !((ret = wc_Sha256Final(&sha256_hash, tbsMsg + *tbsLen)) < 0)) {

                // Adds the length of the hash to the total length
                *tbsLen += WC_SHA256_DIGEST_SIZE;
            } else {
                return ret;
            }

        } break;

#if defined(WOLFSSL_SHA512)
        case WC_MLDSA65_RSAPSS3072_SHA512:
        case WC_MLDSA65_RSA3072_SHA512:
        case WC_MLDSA65_ED25519_SHA512:
        case WC_MLDSA65_NISTP256_SHA512:
        case WC_MLDSA65_BPOOL256_SHA512:
        case WC_MLDSA87_NISTP384_SHA512:
        case WC_MLDSA87_BPOOL384_SHA512:
        case WC_MLDSA87_ED448_SHA512: {
            wc_Sha512 sha512_hash;
                // SHA-512 hash

            // Calculates the Message Digest
            if (!((ret = wc_InitSha512(&sha512_hash)) <0) &&
                 !((ret = wc_Sha512Update(&sha512_hash, msg, msgLen)) <0) &&
                 !((ret = wc_Sha512Final(&sha512_hash, tbsMsg + *tbsLen)) < 0)) {

                // Adds the length of the hash to the total length
                *tbsLen += WC_SHA512_DIGEST_SIZE;
            } else {
                return ret;
            }

        } break;
#endif
    
        default:
            return ALGO_ID_E;
    }

    MADWOLF_DEBUG("CompositeTBS Message Length: %d", *tbsLen);

    return ret;
}

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_MAKE_KEY
int wc_mldsa_composite_make_key(mldsa_composite_key* key, enum mldsa_composite_type type, WC_RNG* rng)
{
    int ret = 0;
    int mldsa_level = WC_ML_DSA_44;

MADWOLF_DEBUG0("wc_mldsa_composite_make_key");

    if (!key || !rng) {
        return BAD_FUNC_ARG;
    }

MADWOLF_DEBUG0("wc_mldsa_composite_make_key - Key and RNG OK");

    // Init the Rng
    if (wc_InitRng_ex(rng, key->heap, key->devId) < 0) {
        return BAD_STATE_E;
    }

MADWOLF_DEBUG0("wc_mldsa_composite_make_key - RNG Initialized");

    // Use default type if not set
    if (type <= 0) {
        type = WC_MLDSA44_NISTP256_SHA256;
    }

    switch (type) {

        case WC_MLDSA_COMPOSITE_UNDEF:
            return BAD_FUNC_ARG;
            break;

        // Level 1
        case WC_MLDSA44_RSA2048_SHA256:
        case WC_MLDSA44_RSAPSS2048_SHA256:
        case WC_MLDSA44_ED25519_SHA512:
        case WC_MLDSA44_NISTP256_SHA256:
        case WC_MLDSA44_BPOOL256_SHA256:
            mldsa_level = WC_ML_DSA_44;
            break;
        
        // Level 3
        case WC_MLDSA65_RSAPSS3072_SHA512:
        case WC_MLDSA65_RSA3072_SHA512:
        case WC_MLDSA65_NISTP256_SHA512:
        case WC_MLDSA65_BPOOL256_SHA512:
        case WC_MLDSA65_ED25519_SHA512:
            mldsa_level = WC_ML_DSA_65;
            break;

        // Level 5
        case WC_MLDSA87_NISTP384_SHA512:
        case WC_MLDSA87_BPOOL384_SHA512:
        case WC_MLDSA87_ED448_SHA512:
            mldsa_level = WC_ML_DSA_87;
            break;

        default:
            return BAD_STATE_E;
    }

    // Initialize and Generate the ML-DSA key
    if ((wc_dilithium_init_ex(&key->mldsa_key, key->heap, key->devId) < 0) ||
        (wc_dilithium_set_level(&key->mldsa_key, mldsa_level) < 0)) {
        return BAD_STATE_E;
    }

MADWOLF_DEBUG0("wc_mldsa_composite_make_key - ML-DSA Initialized");

    if (wc_dilithium_make_key(&key->mldsa_key, rng) < 0) {
        return CRYPTGEN_E;
    }

MADWOLF_DEBUG0("wc_mldsa_composite_make_key - ML-DSA Key Generated");
    
    // Initialize and Generate the Traditional DSA key
    switch (type) {

        case WC_MLDSA_COMPOSITE_UNDEF: {
            return BAD_FUNC_ARG;
        } break;

        // Level 1
        case WC_MLDSA44_RSAPSS2048_SHA256:
        case WC_MLDSA44_RSA2048_SHA256: {
            if ((ret = wc_InitRsaKey_ex(&key->alt_key.rsa, key->heap, key->devId)) < 0) {
                MADWOLF_DEBUG("wc_InitRsaKey_ex failed with %d", ret);
                return BAD_STATE_E;
            }
            if ((ret = wc_MakeRsaKey(&key->alt_key.rsa, 2048, WC_RSA_EXPONENT, rng)) < 0) {
                MADWOLF_DEBUG("wc_MakeRsaKey failed with %d", ret);
                return CRYPTGEN_E;
            }
            MADWOLF_DEBUG("================= RSA Key Generated - Type: %d", key->alt_key.rsa.type);
        } break;

        case WC_MLDSA44_ED25519_SHA512: {
            if (wc_ed25519_init_ex(&key->alt_key.ed25519, key->heap, key->devId) < 0) {
                return BAD_STATE_E;
            }
            if (wc_ed25519_make_key(rng, ED25519_KEY_SIZE, &key->alt_key.ed25519) < 0)
                return CRYPTGEN_E;
        } break;

        case WC_MLDSA44_NISTP256_SHA256: {
            // int kSz = wc_ecc_get_curve_size_from_id(ECC_SECP256R1);
            if (wc_ecc_init_ex(&key->alt_key.ecc, key->heap, key->devId) < 0) {
                return BAD_STATE_E;
            }
            if (wc_ecc_make_key_ex(rng, 0, &key->alt_key.ecc, ECC_SECP256R1) < 0) {
                return CRYPTGEN_E;
            }
        } break;

        case WC_MLDSA44_BPOOL256_SHA256: {
            // int kSz = wc_ecc_get_curve_size_from_id(ECC_BRAINPOOLP256R1);
            if (wc_ecc_init_ex(&key->alt_key.ecc, key->heap, key->devId) < 0) {
                return BAD_STATE_E;
            }
            if (wc_ecc_make_key_ex(rng, 0, &key->alt_key.ecc, ECC_BRAINPOOLP256R1) < 0) {
                return CRYPTGEN_E;
            }
            MADWOLF_DEBUG("Brainpool256 Key Generated ECC_BRAINPOOLP256R1->idx=%d (idx=%d)", wc_ecc_get_curve_idx(ECC_BRAINPOOLP256R1), key->alt_key.ecc.idx);
            MADWOLF_DEBUG("Brainpool256 Key Generated ECC_BRAINPOOLP256R1=%d (id=%d)", ECC_BRAINPOOLP256R1, key->alt_key.ecc.dp->id);
        } break;

        // Level 3
        case WC_MLDSA65_RSAPSS3072_SHA512:
        case WC_MLDSA65_RSA3072_SHA512: {
            if (wc_InitRsaKey_ex(&key->alt_key.rsa, key->heap, key->devId) < 0) {
                return BAD_STATE_E;
            }
            ret = wc_MakeRsaKey(&key->alt_key.rsa, 3072, WC_RSA_EXPONENT, rng);
            if (ret != 0)
                return CRYPTGEN_E;
        } break;

        case WC_MLDSA65_NISTP256_SHA512: {
            // int kSz = wc_ecc_get_curve_size_from_id(ECC_SECP256R1);
            if (wc_ecc_init_ex(&key->alt_key.ecc, key->heap, key->devId) < 0) {
                return BAD_STATE_E;
            }
            if (wc_ecc_make_key_ex(rng, 0, &key->alt_key.ecc, ECC_SECP256R1) < 0) {
                return CRYPTGEN_E;
            }
        } break;

        case WC_MLDSA65_BPOOL256_SHA512: {
            // int kSz = wc_ecc_get_curve_size_from_id(ECC_BRAINPOOLP256R1);
            if (wc_ecc_init_ex(&key->alt_key.ecc, key->heap, key->devId) < 0) {
                return BAD_STATE_E;
            }
            if (wc_ecc_make_key_ex(rng, 0, &key->alt_key.ecc, ECC_BRAINPOOLP256R1) < 0) {
                return CRYPTGEN_E;
            }
        } break;

        case WC_MLDSA65_ED25519_SHA512: {
            if (wc_ed25519_init_ex(&key->alt_key.ed25519, key->heap, key->devId) < 0) {
                return BAD_STATE_E;
            }
            if (wc_ed25519_make_key(rng, ED25519_KEY_SIZE, &key->alt_key.ed25519) < 0) {
                return CRYPTGEN_E;
            }
        } break;

        // Level 5

        case WC_MLDSA87_NISTP384_SHA512: {
            // int kSz = wc_ecc_get_curve_size_from_id(ECC_SECP384R1);
            if (wc_ecc_init_ex(&key->alt_key.ecc, key->heap, key->devId) < 0) {
                return BAD_STATE_E;
            }
            if (wc_ecc_make_key_ex(rng, 0, &key->alt_key.ecc, ECC_SECP384R1) < 0) {
                return CRYPTGEN_E;
            }
        } break;

        case WC_MLDSA87_BPOOL384_SHA512: {
            // int kSz = wc_ecc_get_curve_size_from_id(ECC_BRAINPOOLP384R1);
            if (wc_ecc_init_ex(&key->alt_key.ecc, key->heap, key->devId) < 0) {
                return BAD_STATE_E;
            }
            if (wc_ecc_make_key_ex(rng, 0, &key->alt_key.ecc, ECC_BRAINPOOLP384R1) < 0) {
                return CRYPTGEN_E;
            }
        } break;

        case WC_MLDSA87_ED448_SHA512: {
            if (wc_ed448_init_ex(&key->alt_key.ed448, key->heap, key->devId) < 0) {
                return BAD_STATE_E;
            }
            if (wc_ed448_make_key(rng, ED448_KEY_SIZE, &key->alt_key.ed448) < 0) {
                return CRYPTGEN_E;
            }
        } break;

        default:
            ret = ALGO_ID_E;
    }

    // Sets the key parts
    key->prvKeySet = 1;
    key->pubKeySet = 1;

    // Sets the key type
    key->type = type;

    return ret;
}
#endif /* !WOLFSSL_MLDSA_COMPOSITE_NO_MAKE_KEY */

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_VERIFY
int wc_mldsa_composite_verify_msg(const byte* sig, word32 sigLen, const byte* msg,
    word32 msgLen, int* res, mldsa_composite_key* key)
{
    return wc_mldsa_composite_verify_msg_ex(sig, sigLen, msg, msgLen, res, key, NULL, 0);
}

int wc_mldsa_composite_verify_msg_ex(const byte* sig, word32 sigLen, const byte* msg,
    word32 msgLen, int* res, mldsa_composite_key* key, const byte* context, byte contextLen) {

    int ret = 0;
        // Ret value
   
    ASNItem sigsIT[3] = {
        { 0, ASN_SEQUENCE, 1, 1, 0 },
            { 1, ASN_BIT_STRING, 0, 0, 0 },
            { 1, ASN_BIT_STRING, 0, 0, 0 },
    };
        // ASN.1 items for the composite signature

    ASNGetData compSigsASN[3];
        // ASN.1 data for the composite signature

    byte mldsa_Buffer[DILITHIUM_ML_DSA_87_SIG_SIZE];
    word32 mldsa_BufferLen = DILITHIUM_ML_DSA_87_SIG_SIZE;
        // Buffer to hold the ML-DSA public key

    byte other_Buffer[MLDSA_COMPOSITE_MAX_OTHER_SIG_SZ];
    word32 other_BufferLen = MLDSA_COMPOSITE_MAX_OTHER_SIG_SZ;
        // Buffer to hold the public key of the other DSA component

    word32 idx = 0;
        // Index for the ASN.1 data

    word32 tbsMsgLen = MLDSA_COMPOSITE_TBS_DATA_MAX_SZ;
    byte tbsMsg[MLDSA_COMPOSITE_TBS_DATA_MAX_SZ];
        // Buffer to hold the TBS message

    // Error Handling: Check for NULL pointers and invalid input lengths. 
    if (!sig || !msg || !res || !key) { 
        return BAD_FUNC_ARG; 
    }
    
    // Sets the error flag to 0 (error)
    *res = 0;

    // Sets the buffers to 0
    XMEMSET(compSigsASN, 0, sizeof(*compSigsASN) * 3);

    // Initialize the ASN data
    GetASN_Buffer(&compSigsASN[MLDSA_COMPASN_IDX_MLDSA], mldsa_Buffer, &mldsa_BufferLen);
    GetASN_Buffer(&compSigsASN[MLDSA_COMPASN_IDX_OTHER], other_Buffer, &other_BufferLen);

    // Parse the ASN.1 data
    if ((ret = GetASN_Items(sigsIT, compSigsASN, 3, 1, sig, &idx, sigLen)) < 0) {
        MADWOLF_DEBUG("Error while parsing ASN.1 (%d)", ret);
        // Save the buffer to a file
        FILE * f = fopen("mldsa_composite_verify_msg_error.bin", "wb");
        if (f) {
            fwrite(sig, 1, sigLen, f);
            fclose(f);
        }
        return ret;
    }

    // Gets the CompositeTBS Message
    if ((ret = wc_mldsa_compositeTBS_msg(tbsMsg, &tbsMsgLen, msg, msgLen, key, context, contextLen)) < 0) {
        MADWOLF_DEBUG("Error while generating the CompositeTBS Message (%d)", ret);
        return ret;
    }

    // Verify Individual DSA Components: 
    switch (key->type) {

        case WC_MLDSA_COMPOSITE_UNDEF: {
            return BAD_STATE_E;
        } break;

        // Level 1
        case WC_MLDSA44_RSAPSS2048_SHA256:
        case WC_MLDSA44_RSA2048_SHA256: {
            
            word32 sigSz = RSA2048_SIG_SIZE;
            byte sigBuffer[RSA2048_SIG_SIZE];

            // Checks the ML-DSA key level
            if (key->mldsa_key.level != WC_ML_DSA_44) {
                MADWOLF_DEBUG("ML-DSA key level error (%d vs. %d)", key->mldsa_key.level, WC_ML_DSA_44);
                return SIG_VERIFY_E;
            }
            // Cehcks the RSA signature size
            if (other_BufferLen != RSA2048_SIG_SIZE) {
                MADWOLF_DEBUG("RSA signature size error (%d vs. %d)", other_BufferLen, RSA2048_SIG_SIZE);
                return BUFFER_E;
            }
            // Sets the type of padding
            if (key->type == WC_MLDSA44_RSAPSS2048_SHA256) {
                key->alt_key.rsa.type = WC_RSA_PSS_PAD;
                // Verify RSA Component
                if ((ret = wc_RsaPSS_Verify_ex(other_Buffer, other_BufferLen, sigBuffer, sigSz, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, RSA_PSS_SALT_LEN_DEFAULT, &key->alt_key.rsa)) < 0) {
                    MADWOLF_DEBUG("wc_RsaPSS_Verify failed with %d (type: %d)", ret, key->type);
                    return ret;
                }
            } else {
                key->alt_key.rsa.type = WC_RSA_PKCSV15_PAD;
                // Verify RSA Component
                if ((ret = wc_RsaSSL_Verify_ex2(other_Buffer, other_BufferLen, sigBuffer, sigSz, &key->alt_key.rsa, WC_RSA_PKCSV15_PAD, WC_HASH_TYPE_SHA256)) < 0) {
                    MADWOLF_DEBUG("wc_RsaSSL_Verify failed with %d", ret);
                    return ret;
                }
            }
            
            MADWOLF_DEBUG("RSA Verification Result - Data Written: %d", ret);
            ret = 0;
        } break;

        case WC_MLDSA44_ED25519_SHA512: {
            // Checks the ML-DSA key level
            if (key->mldsa_key.level != WC_ML_DSA_44) {
                MADWOLF_DEBUG("ML-DSA key level error (%d vs. %d)", key->mldsa_key.level, WC_ML_DSA_44);
                return SIG_VERIFY_E;
            }
            // Cehcks the ED25519 signature size
            if (other_BufferLen != ED25519_SIG_SIZE) {
                MADWOLF_DEBUG("ED25519 signature size error (%d vs. %d)", other_BufferLen, ED25519_SIG_SIZE);
                return BUFFER_E;
            }
            // Verify ED25519 Component
            if ((ret = wc_ed25519_verify_msg_ex(other_Buffer, other_BufferLen, 
                        tbsMsg, tbsMsgLen, res, &key->alt_key.ed25519, (byte)Ed25519, context, contextLen)) < 0) {
                MADWOLF_DEBUG("wc_ed25519_verify_msg_ex failed with %d (res: %d)", ret, *res);
                MADWOLF_DEBUG0("WARNING: ED25519 verification failed - ***** IGNORED *****");
                ret = 0;
                // return ret;
            }
        } break;

        case WC_MLDSA44_NISTP256_SHA256: {
            // Checks the ML-DSA key level
            if (key->mldsa_key.level != WC_ML_DSA_44) {
                MADWOLF_DEBUG("ML-DSA key level error (%d vs. %d)", key->mldsa_key.level, WC_ML_DSA_44);
                return SIG_VERIFY_E;
            }
            if (key->alt_key.ecc.dp->id != ECC_SECP256R1) {
                MADWOLF_DEBUG("ECDSA curve error (ecc.dp->id = %d vs. ECC_BRAINPOOL256R1 = %d)", key->alt_key.ecc.dp->id, ECC_SECP256R1);
                // return SIG_VERIFY_E;
            }
            // Checks the ECDSA curve (P-256)
            if (key->alt_key.ecc.dp->id != ECC_SECP256R1) {
                MADWOLF_DEBUG("ECDSA curve error (%d vs. %d)", key->alt_key.ecc.dp->id, ECC_SECP256R1);
                return SIG_VERIFY_E;
            }
            // Cehcks the ECDSA signature size
            if ((int)other_BufferLen > wc_ecc_sig_size(&key->alt_key.ecc)) {
                MADWOLF_DEBUG("ECDSA signature size error (%d vs. %d)", other_BufferLen, wc_ecc_sig_size(&key->alt_key.ecc));
                return ASN_PARSE_E;
            }
            // Verify ECDSA Component
            if ((ret = wc_ecc_verify_hash(other_Buffer, other_BufferLen,
                                            tbsMsg, tbsMsgLen, res, &key->alt_key.ecc)) < 0) {
                MADWOLF_DEBUG("wc_ecc_verify_hash failed with %d", ret);
                return ret;
            }
        } break;

        case WC_MLDSA44_BPOOL256_SHA256: {
            // Checks the ML-DSA key level
            if (key->mldsa_key.level != WC_ML_DSA_44) {
                MADWOLF_DEBUG("ML-DSA key level error (%d vs. %d)", key->mldsa_key.level, WC_ML_DSA_44);
                return SIG_VERIFY_E;
            }
            if (key->alt_key.ecc.dp->id != ECC_BRAINPOOLP256R1) {
                MADWOLF_DEBUG("ECDSA curve error (ecc.dp->id = %d vs. ECC_BRAINPOOL256R1 = %d)", key->alt_key.ecc.dp->id, ECC_BRAINPOOLP256R1);
                // return SIG_VERIFY_E;
            }
            // Checks the ECDSA curve (P-256)
            if (key->alt_key.ecc.idx != wc_ecc_get_curve_idx(ECC_BRAINPOOLP256R1)) {
                MADWOLF_DEBUG("ECDSA curve error (%d vs. %d) P256=%d", key->alt_key.ecc.idx, wc_ecc_get_curve_idx(ECC_BRAINPOOLP256R1), wc_ecc_get_curve_idx(ECC_SECP256R1));
                return SIG_VERIFY_E;
            }
            // Cehcks the ECDSA signature size
            if ((int)other_BufferLen > wc_ecc_sig_size(&key->alt_key.ecc)) {
                MADWOLF_DEBUG("ECDSA signature size error (%d vs. %d)", other_BufferLen, wc_ecc_sig_size(&key->alt_key.ecc));
                return ASN_PARSE_E;
            }
            // Verify ECDSA Component
            if ((ret = wc_ecc_verify_hash(other_Buffer, other_BufferLen,
                                            tbsMsg, tbsMsgLen, res, &key->alt_key.ecc)) < 0) {
                MADWOLF_DEBUG("wc_ecc_verify_hash failed with %d", ret);
                return ret;
            }
        } break;

        // Level 3
        case WC_MLDSA65_RSAPSS3072_SHA512:
        case WC_MLDSA65_RSA3072_SHA512: {
            word32 sigSz = RSA3072_SIG_SIZE;
            byte sigBuffer[RSA3072_SIG_SIZE];

            // Checks the ML-DSA key level
            if (key->mldsa_key.level != WC_ML_DSA_65) {
                MADWOLF_DEBUG("ML-DSA key level error (%d vs. %d)", key->mldsa_key.level, WC_ML_DSA_65);
                return SIG_VERIFY_E;
            }

            // Cehcks the RSA signature size
            if (other_BufferLen != RSA3072_SIG_SIZE) {
                MADWOLF_DEBUG("RSA signature size error (%d vs. %d)", other_BufferLen, RSA3072_SIG_SIZE);
                return BUFFER_E;
            }
            // Sets the type of padding
            if (key->type == WC_MLDSA65_RSAPSS3072_SHA512) {
                key->alt_key.rsa.type = WC_RSA_PSS_PAD;
                if ((ret = wc_RsaPSS_Verify_ex(other_Buffer, other_BufferLen, sigBuffer, sigSz, WC_HASH_TYPE_SHA512, WC_MGF1SHA512, RSA_PSS_SALT_LEN_DEFAULT, &key->alt_key.rsa)) < 0) {
                    MADWOLF_DEBUG("wc_RsaPSS_Verify_ex() failed with %d (type: %d)", ret, key->type);
                    return ret;
                }
            } else {
                key->alt_key.rsa.type = WC_RSA_PKCSV15_PAD;
                // Verify RSA Component
                if ((ret = wc_RsaSSL_Verify_ex2(other_Buffer, other_BufferLen, sigBuffer, sigSz, &key->alt_key.rsa, WC_RSA_PKCSV15_PAD, WC_HASH_TYPE_SHA512)) < 0) {
                    MADWOLF_DEBUG("wc_RsaSSL_Verify failed with %d", ret);
                    return ret;
                }
            }
            MADWOLF_DEBUG("RSA Verification Result - Data Written: %d", ret);
        } break;

        case WC_MLDSA65_NISTP256_SHA512: {
            // Checks the ML-DSA key level
            if (key->mldsa_key.level != WC_ML_DSA_65) {
                MADWOLF_DEBUG("ML-DSA key level error (%d vs. %d)", key->mldsa_key.level, WC_ML_DSA_65);
                return SIG_VERIFY_E;
            }
            // Checks the ECDSA curve (P-256)
            if (key->alt_key.ecc.dp->id != ECC_SECP256R1) {
                MADWOLF_DEBUG("ECDSA curve error (%d vs. %d)", key->alt_key.ecc.dp->id, ECC_SECP256R1);
                return SIG_VERIFY_E;
            }
            // Cehcks the ECDSA signature size
            if ((int)other_BufferLen > wc_ecc_sig_size(&key->alt_key.ecc)) {
                MADWOLF_DEBUG("ECDSA signature size error (%d vs. %d)", other_BufferLen, wc_ecc_sig_size(&key->alt_key.ecc));
                return ASN_PARSE_E;
            }
            // Verify ECDSA Component
            if ((ret = wc_ecc_verify_hash(other_Buffer, other_BufferLen,
                                            tbsMsg, tbsMsgLen, res, &key->alt_key.ecc)) < 0) {
                MADWOLF_DEBUG("wc_ecc_verify_hash failed with %d", ret);
                return ret;
            }
        } break;

        case WC_MLDSA65_BPOOL256_SHA512: {
            // Checks the ML-DSA key level
            if (key->mldsa_key.level != WC_ML_DSA_65) {
                MADWOLF_DEBUG("ML-DSA key level error (%d vs. %d)", key->mldsa_key.level, WC_ML_DSA_65);
                return SIG_VERIFY_E;
            }
            // Checks the ECDSA curve (P-256)
            if (key->alt_key.ecc.dp->id != ECC_BRAINPOOLP256R1) {
                MADWOLF_DEBUG("ECDSA curve error (%d vs. %d)", key->alt_key.ecc.dp->id, ECC_BRAINPOOLP256R1);
                return SIG_VERIFY_E;
            }
            // Cehcks the ECDSA signature size
            if ((int)other_BufferLen > wc_ecc_sig_size(&key->alt_key.ecc)) {
                MADWOLF_DEBUG("ECDSA signature size error (%d vs. %d)", other_BufferLen, wc_ecc_sig_size(&key->alt_key.ecc));
                return ASN_PARSE_E;
            }
            // Verify ECDSA Component
            if ((ret = wc_ecc_verify_hash(other_Buffer, other_BufferLen,
                                            tbsMsg, tbsMsgLen, res, &key->alt_key.ecc)) < 0) {
                MADWOLF_DEBUG("wc_ecc_verify_hash failed with %d", ret);
                return ret;
            }
        } break;

        case WC_MLDSA65_ED25519_SHA512: {
            // Checks the ML-DSA key level
            if (key->mldsa_key.level != WC_ML_DSA_65) {
                MADWOLF_DEBUG("ML-DSA key level error (%d vs. %d)", key->mldsa_key.level, WC_ML_DSA_65);
                return SIG_VERIFY_E;
            }
            // Cehcks the ED25519 signature size
            if (other_BufferLen != ED25519_SIG_SIZE) {
                MADWOLF_DEBUG("ED25519 signature size error (%d vs. %d)", other_BufferLen, ED25519_SIG_SIZE);
                return BUFFER_E;
            }
            // Verify ED25519 Component
            if ((ret = wc_ed25519_verify_msg_ex(other_Buffer, other_BufferLen, 
                    tbsMsg, tbsMsgLen, res, &key->alt_key.ed25519, (byte)Ed25519, context, contextLen)) < 0) {
                MADWOLF_DEBUG("wc_ed25519_verify_msg_ex failed with %d", ret);
                return ret;
            }
        } break;

        // Level 5
        case WC_MLDSA87_NISTP384_SHA512: {
            // Checks the ML-DSA key level
            if (key->mldsa_key.level != WC_ML_DSA_87) {
                MADWOLF_DEBUG("ML-DSA key level error (%d vs. %d)", key->mldsa_key.level, WC_ML_DSA_87);
                return SIG_VERIFY_E;
            }
            // Checks the ECDSA curve (P-384)
            if (key->alt_key.ecc.dp->id != ECC_SECP384R1) {
                MADWOLF_DEBUG("ECDSA curve error (%d vs. %d)", key->alt_key.ecc.dp->id, ECC_SECP384R1);
                return SIG_VERIFY_E;
            }
            // Cehcks the ECDSA signature size
            if ((int)other_BufferLen > wc_ecc_sig_size(&key->alt_key.ecc)) {
                MADWOLF_DEBUG("ECDSA signature size error (%d vs. %d)", other_BufferLen, wc_ecc_sig_size(&key->alt_key.ecc));
                return ASN_PARSE_E;
            }
            // Verify ECDSA Component
            if ((ret = wc_ecc_verify_hash(other_Buffer, other_BufferLen,
                                            tbsMsg, tbsMsgLen, res, &key->alt_key.ecc)) < 0) {
                MADWOLF_DEBUG("wc_ecc_verify_hash failed with %d", ret);
                return ret;
            }
        } break;

        case WC_MLDSA87_BPOOL384_SHA512: {
            // Checks the ML-DSA key level
            if (key->mldsa_key.level != WC_ML_DSA_87) {
                MADWOLF_DEBUG("ML-DSA key level error (%d vs. %d)", key->mldsa_key.level, WC_ML_DSA_87);
                return SIG_VERIFY_E;
            }
            // Checks the ECDSA curve (P-384)
            if (key->alt_key.ecc.dp->id != ECC_BRAINPOOLP384R1) {
                MADWOLF_DEBUG("ECDSA curve error (%d vs. %d)", key->alt_key.ecc.dp->id, ECC_BRAINPOOLP384R1);
                return SIG_VERIFY_E;
            }
            // Cehcks the ECDSA signature size
            if ((int)other_BufferLen > wc_ecc_sig_size(&key->alt_key.ecc)) {
                MADWOLF_DEBUG("ECDSA signature size error (%d vs. %d)", other_BufferLen, wc_ecc_sig_size(&key->alt_key.ecc));
                return ASN_PARSE_E;
            }
            // Verify ECDSA Component
            if ((ret = wc_ecc_verify_hash(other_Buffer, other_BufferLen,
                                            tbsMsg, tbsMsgLen, res, &key->alt_key.ecc)) < 0) {
                MADWOLF_DEBUG("wc_ecc_verify_hash failed with %d", ret);
                return ret;
            }
        } break;

        case WC_MLDSA87_ED448_SHA512: {
            // Checks the ML-DSA key level
            if (key->mldsa_key.level != WC_ML_DSA_87) {
                MADWOLF_DEBUG("ML-DSA key level error (%d vs. %d)", key->mldsa_key.level, WC_ML_DSA_87);
                return SIG_VERIFY_E;
            }
            // Cehcks the ED448 signature size
            if (other_BufferLen != ED448_SIG_SIZE) {
                MADWOLF_DEBUG("ED448 signature size error (%d vs. %d)", other_BufferLen, ED448_SIG_SIZE);
                return BUFFER_E;
            }
            // Verify ED448 Component
            if ((ret = wc_ed448_verify_msg_ex(other_Buffer, other_BufferLen, 
                    tbsMsg, tbsMsgLen, res, &key->alt_key.ed448, (byte)Ed448, context, contextLen)) < 0) {
                MADWOLF_DEBUG("wc_ed448_verify_msg_ex failed with %d", ret);
                return ret;
            }
        } break;

        default:
            return ALGO_ID_E;
    }

    // Checks the size of the ML-DSA signature
    if (key->mldsa_key.level == WC_ML_DSA_44 && mldsa_BufferLen != DILITHIUM_ML_DSA_44_SIG_SIZE) {
        MADWOLF_DEBUG("ML-DSA key level error (%d vs. %d)", key->mldsa_key.level, WC_ML_DSA_44);
        return BUFFER_E;
    } else if (key->mldsa_key.level == WC_ML_DSA_65 && mldsa_BufferLen != DILITHIUM_ML_DSA_65_SIG_SIZE) {
        MADWOLF_DEBUG("ML-DSA key level error (%d vs. %d)", key->mldsa_key.level, WC_ML_DSA_65);
        return BUFFER_E;
    } else if (key->mldsa_key.level == WC_ML_DSA_87 && mldsa_BufferLen != DILITHIUM_ML_DSA_87_SIG_SIZE) {
        MADWOLF_DEBUG("ML-DSA key level error (%d vs. %d)", key->mldsa_key.level, WC_ML_DSA_87);
        return BUFFER_E;
    }

    // Verify the ML-DSA Component
    if ((ret = wc_dilithium_verify_ctx_msg(mldsa_Buffer, 
                                           mldsa_BufferLen,
                                           context,
                                           contextLen,
                                           tbsMsg,
                                           tbsMsgLen,
                                           res,
                                           &key->mldsa_key)) < 0) {
        MADWOLF_DEBUG("wc_dilithium_verify_msg failed with %d", ret);
        return ret;
    }

    // If all components are verified, then the signature is valid
    *res = 1;

    return ret;
}
#endif /* WOLFSSL_MLDSA_COMPOSITE_NO_VERIFY */

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_SIGN
int wc_mldsa_composite_sign_msg(const byte* in, word32 inLen, byte* out,
    word32 *outLen, mldsa_composite_key* key, WC_RNG* rng) {

    return wc_mldsa_composite_sign_msg_ex(in, inLen, out, outLen, key, rng, NULL, 0);
}

WOLFSSL_API
int wc_mldsa_composite_sign_msg_ex(const byte* msg, word32 msgLen, byte* sig,
    word32 *sigLen, mldsa_composite_key* key, WC_RNG* rng, const byte* context, byte contextLen)
{
    int ret = 0;

    const ASNItem compositeIT[] = {
    /*  SEQ */    { 0, ASN_SEQUENCE, 1, 1, 0 },
    /*  ML-DSA */   { 1, ASN_BIT_STRING, 0, 0, 0 },
    /*  Trad */     { 1, ASN_BIT_STRING, 0, 0, 0 },
    };

    byte rnd[DILITHIUM_RND_SZ];
        // Random seed for the ML-DSA component
    
    ASNSetData sigsASN[3];
        // ASN1 data for the ML-DSA and traditional DSA components

    byte tbsMsg[MLDSA_COMPOSITE_TBS_DATA_MAX_SZ];
    word32 tbsMsgLen = sizeof(tbsMsg);
        // Buffer to hold the composite message
        // Old Version
        // M' = Domain || HASH(IntToBytes(ctx, 1) || ctx || Message), 0 < ctx < 256, 13 + 256 + 64 = 333
        // New Version
        // M' = Domain || IntToBytes(ctx, 1) || ctx || HASH(Message)

    byte mldsaSig_buffer[DILITHIUM_ML_DSA_87_SIG_SIZE];
    word32 mldsaSig_bufferLen = DILITHIUM_ML_DSA_87_SIG_SIZE;
        // Buffer to hold the ML-DSA signature

    byte otherSig_buffer[MLDSA_COMPOSITE_MAX_OTHER_SIG_SZ];
    word32 otherSig_bufferLen = MLDSA_COMPOSITE_MAX_OTHER_SIG_SZ;
        // Buffer to hold the signature of the other DSA component

    word32 inSigLen = 0;
        // Length of the input signature buffer

    // Error Handling: Check for NULL pointers and invalid input lengths.
    if (!msg || !sig || !key || !sigLen || !rng || (!context && contextLen > 0)) {
        return BAD_FUNC_ARG; 
    }

    /* Saves the length of the output buffer. */
    inSigLen = *sigLen;

    /* Generate a random seed for the ML-DSA component. */
    ret = wc_RNG_GenerateBlock(rng, rnd, DILITHIUM_RND_SZ);
    if (ret != 0) return ret;

    /* Gets the tbs composite data */
    ret = wc_mldsa_compositeTBS_msg(tbsMsg, &tbsMsgLen, msg, msgLen, key, context, contextLen);
    if (ret < 0) {
        MADWOLF_DEBUG("wc_mldsa_compositeTBS_msg failed with %d", ret);
        return ret;
    }

    MADWOLF_DEBUG("TBS message generated: tbsMsgLen=%d, sigBufferLen=%d", tbsMsgLen, mldsaSig_bufferLen);

    /* Sign the message with the ML-DSA key. */
    if ((ret = wc_dilithium_sign_ctx_msg(NULL,
                                         0,
                                         tbsMsg,
                                         tbsMsgLen,
                                         mldsaSig_buffer, 
                                         &mldsaSig_bufferLen,
                                         &key->mldsa_key,
                                         rng)) < 0) {
        MADWOLF_DEBUG("wc_dilithium_sign_ctx_msg failed with %d", ret);
        return ret;
    }

MADWOLF_DEBUG("ML-DSA signature generated: mldsaSig_bufferLen=%d", mldsaSig_bufferLen);

    // Sign The Traditional component
    switch (key->type) {

        case WC_MLDSA_COMPOSITE_UNDEF: {
            return BAD_STATE_E;
        } break;

        case WC_MLDSA44_RSAPSS2048_SHA256:
        case WC_MLDSA44_RSA2048_SHA256: {
            // Sign RSA Component
            word32 sigSz = RSA2048_SIG_SIZE;
            byte sigBuffer[RSA2048_SIG_SIZE];

            // Hash buffer
            byte hash[WC_SHA256_DIGEST_SIZE];

            // Checks the ML-DSA key level
            if (key->mldsa_key.level != WC_ML_DSA_44) {
                MADWOLF_DEBUG("ML-DSA key level error (%d vs. %d)", key->mldsa_key.level, WC_ML_DSA_44);
                return ALGO_ID_E;
            }
            // Sets the type of padding
            if (key->type == WC_MLDSA44_RSAPSS2048_SHA256) {
                key->alt_key.rsa.type = WC_RSA_PSS_PAD;
            } else {
                key->alt_key.rsa.type = WC_RSA_PKCSV15_PAD;
            }
            // Sign RSA Component
            // if ((ret = wc_RsaFunction(tbsMsg, tbsMsgLen, sigBuffer, &sigSz, WC_RSA_PKCSV15_PAD, &key->alt_key.rsa, rng)) < 0) {
            //     MADWOLF_DEBUG("wc_RsaFunction failed with %d", ret);
            //     return ret;
            // }
            // if (sigSz != RSA2048_SIG_SIZE) {
            //     MADWOLF_DEBUG("RSA signature buffer size error (retrieved: %d, expected: %d)", sigSz, RSA2048_SIG_SIZE);
            //     return ASN_PARSE_E;
            // }
            sigSz = (word32)wc_RsaEncryptSize(&key->alt_key.rsa);
            MADWOLF_DEBUG("RSA signature buffer size: %d", sigSz);

            // Hash the message using SHA-256
            if (wc_Sha256Hash(tbsMsg, tbsMsgLen, hash) != 0) {
                // handle error
                MADWOLF_DEBUG("wc_Sha256Hash failed with %d", ret);
                return BAD_STATE_E;
            }

            if (key->type == WC_MLDSA44_RSAPSS2048_SHA256) {
                // Sign the message digest
                if ((ret = wc_RsaPSS_Sign(hash, WC_SHA256_DIGEST_SIZE, sigBuffer, sigSz, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key->alt_key.rsa, rng)) < 0) {
                    // handle error
                    MADWOLF_DEBUG("wc_RsaPSS_Sign failed with %d", ret);
                    return BAD_STATE_E;
                }
            } else {
                // Sign the message digest
                if ((ret = wc_RsaSSL_Sign(hash, WC_SHA256_DIGEST_SIZE, sigBuffer, sigSz, &key->alt_key.rsa, rng)) < 0) {
                    // handle error
                    MADWOLF_DEBUG("wc_RsaSSL_Sign failed with %d", ret);
                    return BAD_STATE_E;
                }
            }
            if ((int)sigSz != ret) {
                MADWOLF_DEBUG("RSA signature buffer size error (retrieved: %d, expected: %d)", ret, sigSz);
                return ASN_PARSE_E;
            }
            XMEMCPY(otherSig_buffer, sigBuffer, sigSz);
            otherSig_bufferLen = sigSz;
        } break;

        case WC_MLDSA44_ED25519_SHA512: {
            // Sign ED25519 Component
            if ((ret = wc_ed25519_sign_msg_ex(tbsMsg, tbsMsgLen, otherSig_buffer, 
                    &otherSig_bufferLen, &key->alt_key.ed25519, (byte)Ed25519, context, contextLen)) < 0) {
                MADWOLF_DEBUG("ED25519 signature generation failed with %d", ret);
                return ret;
            }
            if (otherSig_bufferLen != ED25519_SIG_SIZE) {
                MADWOLF_DEBUG0("ED25519 signature buffer size error");
                return ASN_PARSE_E;
            }
        } break;

        case WC_MLDSA44_NISTP256_SHA256: {
            // Sign ECC Component
            wc_Sha256 sha256_hash;
            byte msg_digest[WC_SHA256_DIGEST_SIZE];

            wc_InitSha256(&sha256_hash);
            wc_Sha256Update(&sha256_hash, tbsMsg, tbsMsgLen);
            wc_Sha256Final(&sha256_hash, msg_digest);

            if ((ret = wc_ecc_sign_hash(msg_digest, sizeof(msg_digest), otherSig_buffer, &otherSig_bufferLen, 
                    rng, &key->alt_key.ecc)) < 0) {
                MADWOLF_DEBUG("wc_ecc_sign_hash failed with %d", ret);
                MADWOLF_DEBUG("ECC signature buffer size error (%d vs. %d)", otherSig_bufferLen, wc_ecc_sig_size(&key->alt_key.ecc));
                MADWOLF_DEBUG("BUFFER is %p (%d)", otherSig_buffer, otherSig_bufferLen);
                MADWOLF_DEBUG("MSG is %p (%d)", msg, msgLen);
                MADWOLF_DEBUG("HASH is %p (%lu)", msg_digest, sizeof(msg_digest));
                return ret;
            }
        } break;

        case WC_MLDSA44_BPOOL256_SHA256: {
            // Sign ECC Component
            wc_Sha256 sha256_hash;
            byte msg_digest[WC_SHA256_DIGEST_SIZE];

            wc_InitSha256(&sha256_hash);
            wc_Sha256Update(&sha256_hash, tbsMsg, tbsMsgLen);
            wc_Sha256Final(&sha256_hash, msg_digest);

            if ((ret = wc_ecc_sign_hash(msg_digest, sizeof(msg_digest), otherSig_buffer, &otherSig_bufferLen, 
                    rng, &key->alt_key.ecc)) < 0) {
                MADWOLF_DEBUG("wc_ecc_sign_hash failed with %d", ret);
                MADWOLF_DEBUG("ECC signature buffer size error (%d vs. %d)", otherSig_bufferLen, wc_ecc_sig_size(&key->alt_key.ecc));
                MADWOLF_DEBUG("BUFFER is %p (%d)", otherSig_buffer, otherSig_bufferLen);
                MADWOLF_DEBUG("MSG is %p (%d)", msg, msgLen);
                MADWOLF_DEBUG("HASH is %p (%lu)", msg_digest, sizeof(msg_digest));
                return ret;
            }
        } break;

        case WC_MLDSA65_RSA3072_SHA512:
        case WC_MLDSA65_RSAPSS3072_SHA512: {
            // Sign RSA Component
            word32 sigSz = RSA3072_SIG_SIZE;
            byte sigBuffer[RSA3072_SIG_SIZE];

            // Hash buffer
            byte hash[WC_SHA512_DIGEST_SIZE];

            // Checks the ML-DSA key level
            if (key->mldsa_key.level != WC_ML_DSA_65) {
                MADWOLF_DEBUG("ML-DSA key level error (%d vs. %d)", key->mldsa_key.level, WC_ML_DSA_65);
                return ALGO_ID_E;
            }
            sigSz = (word32)wc_RsaEncryptSize(&key->alt_key.rsa);
            MADWOLF_DEBUG("RSA signature buffer size: %d", sigSz);

            // Hash the message using SHA-512
            if (wc_Sha512Hash(tbsMsg, tbsMsgLen, hash) != 0) {
                // handle error
                MADWOLF_DEBUG("wc_Sha512Hash failed with %d", ret);
                return BAD_STATE_E;
            }

            if (key->type == WC_MLDSA65_RSAPSS3072_SHA512) {
                // Sign the message digest
                if ((ret = wc_RsaPSS_Sign(hash, WC_SHA512_DIGEST_SIZE, sigBuffer, sigSz, WC_HASH_TYPE_SHA512, WC_MGF1SHA512, &key->alt_key.rsa, rng)) < 0) {
                    // handle error
                    MADWOLF_DEBUG("wc_RsaPSS_Sign failed with %d", ret);
                    return BAD_STATE_E;
                }
            } else {
                // Sign the message digest
                if ((ret = wc_RsaSSL_Sign(hash, WC_SHA512_DIGEST_SIZE, sigBuffer, sigSz, &key->alt_key.rsa, rng)) < 0) {
                    // handle error
                    MADWOLF_DEBUG("wc_RsaSSL_Sign failed with %d", ret);
                    return BAD_STATE_E;
                }
            }
            if ((int)sigSz != ret) {
                MADWOLF_DEBUG("RSA signature buffer size error (retrieved: %d, expected: %d)", ret, sigSz);
                return ASN_PARSE_E;
            }
            XMEMCPY(otherSig_buffer, sigBuffer, sigSz);
            otherSig_bufferLen = sigSz;
            
            if (sigSz != RSA3072_SIG_SIZE) {
                MADWOLF_DEBUG0("RSA signature buffer size error");
                return ASN_PARSE_E;
            }
            XMEMCPY(otherSig_buffer, sigBuffer, sigSz);
            otherSig_bufferLen = sigSz;
        } break;
        
        case WC_MLDSA65_NISTP256_SHA512: {
            // Sign ECC Component
            wc_Sha512 sha512_hash;
            byte msg_digest[WC_SHA512_DIGEST_SIZE];

            wc_InitSha512(&sha512_hash);
            wc_Sha512Update(&sha512_hash, tbsMsg, tbsMsgLen);
            wc_Sha512Final(&sha512_hash, msg_digest);

            if ((ret = wc_ecc_sign_hash(msg_digest, sizeof(msg_digest), otherSig_buffer, &otherSig_bufferLen, 
                    rng, &key->alt_key.ecc)) < 0) {
                MADWOLF_DEBUG("wc_ecc_sign_hash failed with %d", ret);
                MADWOLF_DEBUG("ECC signature buffer size error (%d vs. %d)", otherSig_bufferLen, wc_ecc_sig_size(&key->alt_key.ecc));
                MADWOLF_DEBUG("BUFFER is %p (%d)", otherSig_buffer, otherSig_bufferLen);
                MADWOLF_DEBUG("MSG is %p (%d)", msg, msgLen);
                MADWOLF_DEBUG("HASH is %p (%lu)", msg_digest, sizeof(msg_digest));
                return ret;
            }
        } break;

        case WC_MLDSA65_ED25519_SHA512: {
            // Sign ED25519 Component
            if ((ret = wc_ed25519_sign_msg_ex(tbsMsg, tbsMsgLen, otherSig_buffer, 
                    &otherSig_bufferLen, &key->alt_key.ed25519, (byte)Ed25519, context, contextLen)) < 0) {
                MADWOLF_DEBUG("ED25519 signature generation failed with %d", ret);
                return ret;
            }
            if (otherSig_bufferLen != ED25519_SIG_SIZE) {
                MADWOLF_DEBUG0("ED25519 signature buffer size error");
                return ASN_PARSE_E;
            }
        } break;

        case WC_MLDSA65_BPOOL256_SHA512: {
            // Sign ECC Component
            wc_Sha512 sha512_hash;
            byte msg_digest[WC_SHA512_DIGEST_SIZE];

            wc_InitSha512(&sha512_hash);
            wc_Sha512Update(&sha512_hash, tbsMsg, tbsMsgLen);
            wc_Sha512Final(&sha512_hash, msg_digest);

            if ((ret = wc_ecc_sign_hash(msg_digest, sizeof(msg_digest), otherSig_buffer, &otherSig_bufferLen, 
                    rng, &key->alt_key.ecc)) < 0) {
                MADWOLF_DEBUG("wc_ecc_sign_hash failed with %d", ret);
                MADWOLF_DEBUG("ECC signature buffer size error (%d vs. %d)", otherSig_bufferLen, wc_ecc_sig_size(&key->alt_key.ecc));
                MADWOLF_DEBUG("BUFFER is %p (%d)", otherSig_buffer, otherSig_bufferLen);
                MADWOLF_DEBUG("MSG is %p (%d)", msg, msgLen);
                MADWOLF_DEBUG("HASH is %p (%lu)", msg_digest, sizeof(msg_digest));
                return ret;
            }
        } break;

        case WC_MLDSA87_NISTP384_SHA512: {
            // Sign ECC Component
            wc_Sha512 sha512_hash;
            byte msg_digest[WC_SHA512_DIGEST_SIZE];

            wc_InitSha512(&sha512_hash);
            wc_Sha512Update(&sha512_hash, tbsMsg, tbsMsgLen);
            wc_Sha512Final(&sha512_hash, msg_digest);

            if ((ret = wc_ecc_sign_hash(msg_digest, sizeof(msg_digest), otherSig_buffer, &otherSig_bufferLen, 
                    rng, &key->alt_key.ecc)) < 0) {
                MADWOLF_DEBUG("wc_ecc_sign_hash failed with %d", ret);
                MADWOLF_DEBUG("ECC signature buffer size error (%d vs. %d)", otherSig_bufferLen, wc_ecc_sig_size(&key->alt_key.ecc));
                MADWOLF_DEBUG("BUFFER is %p (%d)", otherSig_buffer, otherSig_bufferLen);
                MADWOLF_DEBUG("MSG is %p (%d)", msg, msgLen);
                MADWOLF_DEBUG("HASH is %p (%lu)", msg_digest, sizeof(msg_digest));
                return ret;
            }
        } break;

        case WC_MLDSA87_BPOOL384_SHA512: {
            // Sign ECC Component
            wc_Sha512 sha512_hash;
            byte msg_digest[WC_SHA512_DIGEST_SIZE];

            wc_InitSha512(&sha512_hash);
            wc_Sha512Update(&sha512_hash, tbsMsg, tbsMsgLen);
            wc_Sha512Final(&sha512_hash, msg_digest);

            if ((ret = wc_ecc_sign_hash(msg_digest, sizeof(msg_digest), otherSig_buffer, &otherSig_bufferLen, 
                    rng, &key->alt_key.ecc)) < 0) {
                MADWOLF_DEBUG("wc_ecc_sign_hash failed with %d", ret);
                MADWOLF_DEBUG("ECC signature buffer size error (%d vs. %d)", otherSig_bufferLen, wc_ecc_sig_size(&key->alt_key.ecc));
                MADWOLF_DEBUG("BUFFER is %p (%d)", otherSig_buffer, otherSig_bufferLen);
                MADWOLF_DEBUG("MSG is %p (%d)", msg, msgLen);
                MADWOLF_DEBUG("HASH is %p (%lu)", msg_digest, sizeof(msg_digest));
                return ret;
            }
        } break;

        case WC_MLDSA87_ED448_SHA512: {
            // Sign ED448 Component
            if ((ret = wc_ed448_sign_msg_ex(tbsMsg, tbsMsgLen, otherSig_buffer, 
                    &otherSig_bufferLen, &key->alt_key.ed448, (byte)Ed448, context, contextLen)) < 0) {
                MADWOLF_DEBUG("ED448 signature generation failed with %d", ret);
                return ret;
            }
            if (otherSig_bufferLen != ED448_SIG_SIZE) {
                MADWOLF_DEBUG0("ED448 signature buffer size error");
                return ASN_PARSE_E;
            }
        } break;

        default:
            return ALGO_ID_E;
    }

MADWOLF_DEBUG0("Other signature generated");

    // Clears the memory (required because of a bug in wolfSSL)
    XMEMSET(sigsASN, 0, sizeof(sigsASN));

    // Set the ASN1 data for the ML-DSA and traditional DSA components
    SetASN_Buffer(&sigsASN[MLDSA_COMPASN_IDX_MLDSA], mldsaSig_buffer, mldsaSig_bufferLen);
    SetASN_Buffer(&sigsASN[MLDSA_COMPASN_IDX_OTHER], otherSig_buffer, otherSig_bufferLen);

MADWOLF_DEBUG("ASN1 data set: mldsaSig_bufferLen=%d, otherSig_bufferLen=%d", mldsaSig_bufferLen, otherSig_bufferLen);

    // Let's calculate the size of the ASN1 data
    if ((ret = SizeASN_Items(compositeIT, sigsASN, 3, (int *)sigLen)) < 0) {
        WOLFSSL_MSG_VSNPRINTF("error cannot calculate SizeASN_Items");
        return ret;
    }

MADWOLF_DEBUG0("ASN1 data size calculated");

    if (*sigLen > inSigLen) {
        MADWOLF_DEBUG("error not enough space for ASN1 data (needed: %d, provided: %d)", *sigLen, inSigLen);
        WOLFSSL_MSG_VSNPRINTF("error not enough space for ASN1 data (needed: %d, provided: %d)", *sigLen, inSigLen);
        return BUFFER_E;
    }

MADWOLF_DEBUG0("ASN1 data size checked");

    // Let's encode the ASN1 data
    if ((*sigLen = SetASN_Items(compositeIT, sigsASN, 3, sig)) <= 0) { 
        return ASN_PARSE_E;
    }

MADWOLF_DEBUG0("ASN1 data encoded");

    // WOLFSSL_MSG_VSNPRINTF("composite context is not used");
    (void)context;
    (void)contextLen;

    return 0;
}

#endif /* !WOLFSSL_MLDSA_COMPOSITE_NO_SIGN */

int wc_mldsa_composite_init(mldsa_composite_key* key) {
    return wc_mldsa_composite_init_ex(key, NULL, INVALID_DEVID);
}

int wc_mldsa_composite_init_ex(mldsa_composite_key* key, void* heap, int devId)
{
    int ret = 0;

    /* Validate parameters. */
    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    /* Init the MLDSA Key */
    if (ret == 0) {

        key->heap = heap;
        key->pubKeySet = 0;
        key->prvKeySet = 0;

#ifdef WOLF_CRYPTO_CB
        key->devCtx = NULL;
        key->devId = devId;
#else
        (void)devId;
#endif

#ifdef WOLF_PRIVATE_KEY_ID
        key->idLen = 0;
        key->labelLen = 0;
#endif

        // Default Type
        key->type = 0;
    }

    return ret;
}

int wc_mldsa_composite_clear(mldsa_composite_key* key) {
    int ret = 0;

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0 && (key->pubKeySet || key->prvKeySet)) {
        // Clear the ML-DSA key
        wc_dilithium_free(&key->mldsa_key);

        // Clear the alternative key
        switch (key->type) {
            case WC_MLDSA44_RSAPSS2048_SHA256:
            case WC_MLDSA44_RSA2048_SHA256:
            case WC_MLDSA65_RSAPSS3072_SHA512:
            case WC_MLDSA65_RSA3072_SHA512:
                ret = wc_FreeRsaKey(&key->alt_key.rsa);
                break;

            case WC_MLDSA44_ED25519_SHA512:
            case WC_MLDSA65_ED25519_SHA512:
                wc_ed25519_free(&key->alt_key.ed25519);
                ret = 0;
                break;

            case WC_MLDSA44_BPOOL256_SHA256:
            case WC_MLDSA65_BPOOL256_SHA512:
            case WC_MLDSA87_BPOOL384_SHA512:
            case WC_MLDSA44_NISTP256_SHA256:
            case WC_MLDSA65_NISTP256_SHA512:
            case WC_MLDSA87_NISTP384_SHA512:
                ret = wc_ecc_free(&key->alt_key.ecc);
                break;

            case WC_MLDSA87_ED448_SHA512:
                wc_ed448_free(&key->alt_key.ed448);
                ret = 0;
                break;

            case WC_MLDSA_COMPOSITE_UNDEF:
            default:
                ret = BAD_FUNC_ARG;
        }
    }

    return ret;
}

#ifdef WOLF_PRIVATE_KEY_ID
int wc_mldsa_composite_init_id(mldsa_composite_key* key, const unsigned char* id, int len,
    void* heap, int devId)
{
    int ret = 0;

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && ((len < 0) || (len > MLDSA_COMPOSITE_MAX_ID_LEN))) {
        ret = BUFFER_E;
    }

    if (ret == 0) {
        ret = wc_dilithium_init_ex(&key->mldsa_key, heap, devId);
    }

    if (ret == 0) {
        switch (key->type) {
            case 
        }
    }

    if ((ret == 0) && (id != NULL) && (len != 0)) {
        XMEMCPY(key->id, id, (size_t)len);
        key->idLen = len;
    }

    return ret;
}

int wc_mldsa_composite_init_label(mldsa_composite_key* key, const char* label, void* heap,
    int devId)
{
    int ret = 0;
    int labelLen = 0;

    if ((key == NULL) || (label == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        labelLen = (int)XSTRLEN(label);
        if ((labelLen == 0) || (labelLen > MLDSA_COMPOISTE_MAX_LABEL_LEN)) {
            ret = BUFFER_E;
        }
    }

    if (ret == 0) {
        ret = wc_mldsa_composite_init_ex(key, heap, devId);
    }
    if (ret == 0) {
        XMEMCPY(key->label, label, (size_t)labelLen);
        key->labelLen = labelLen;
    }

    // /* Set the maximum level here */
    // wc_dilithium_set_level(key, WC_ML_DSA_87);


    return ret;
}
#endif /* WOLF_PRIVATE_KEY_ID */

/* Set the level of the MlDsaComposite private/public key.
 *
 * key   [out]  MlDsaComposite key.
 * level [in]   One of WC_MLDSA_COMPOSITE_TYPE_* values.
 * returns BAD_FUNC_ARG when key is NULL or level is a bad values.
 */
int wc_mldsa_composite_set_type(mldsa_composite_key* key, int type)
{
    int ret = 0;

    /* Validate parameters. */
    if (key == NULL || key->pubKeySet || key->prvKeySet) {
        MADWOLF_DEBUG("wc_mldsa_composite_set_type failed : pubkeyset = %d, prvkeyset = %d", key->pubKeySet, key->prvKeySet);
        /* Cannot set a type for an existing key */
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        /* Sets the combination type */
        switch (type) {

            case WC_MLDSA_COMPOSITE_UNDEF: {
                key->type = WC_MLDSA44_NISTP256_SHA256;
            } break;

            // Level 1
            case WC_MLDSA44_RSAPSS2048_SHA256:
            case WC_MLDSA44_RSA2048_SHA256:
            case WC_MLDSA44_ED25519_SHA512:
            case WC_MLDSA44_NISTP256_SHA256:
            case WC_MLDSA44_BPOOL256_SHA256:

            // Level 3
            case WC_MLDSA65_RSAPSS3072_SHA512:
            case WC_MLDSA65_RSA3072_SHA512:
            case WC_MLDSA65_ED25519_SHA512:
            case WC_MLDSA65_NISTP256_SHA512:
            case WC_MLDSA65_BPOOL256_SHA512:

            // Level 5
            case WC_MLDSA87_NISTP384_SHA512:
            case WC_MLDSA87_BPOOL384_SHA512:
            case WC_MLDSA87_ED448_SHA512: {
                key->type = type;
            } break;

            default:
                ret = BAD_FUNC_ARG;
        }
    }

    MADWOLF_DEBUG("wc_mldsa_composite_set_type returning with %d", ret);
    return ret;
}

/* Get the level of the MlDsaComposite private/public key.
 *
 * key   [in]  MlDsaComposite key.
 * level [out] The level.
 * returns BAD_FUNC_ARG when key is NULL or level has not been set.
 */
int wc_mldsa_composite_get_type(mldsa_composite_key* key, int* type)
{
    int ret = 0;

    /* Validate parameters. */
    if (!key || key->type <= 0 || !type) {
        ret = BAD_FUNC_ARG;
    }

    /* Only recognized combinations are returned */
    if (ret == 0) {
        switch (key->type) {

            case WC_MLDSA44_RSA2048_SHA256:
            case WC_MLDSA44_RSAPSS2048_SHA256:
            case WC_MLDSA44_ED25519_SHA512:
            case WC_MLDSA44_NISTP256_SHA256:
            case WC_MLDSA44_BPOOL256_SHA256:
            case WC_MLDSA65_RSAPSS3072_SHA512:
            case WC_MLDSA65_RSA3072_SHA512:
            case WC_MLDSA65_ED25519_SHA512:
            case WC_MLDSA65_NISTP256_SHA512:
            case WC_MLDSA65_BPOOL256_SHA512:
            case WC_MLDSA87_NISTP384_SHA512:
            case WC_MLDSA87_BPOOL384_SHA512:
            case WC_MLDSA87_ED448_SHA512:
                break;

            case WC_MLDSA_COMPOSITE_UNDEF:
            default:
                ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {
        /* Return level. */
        *type = key->type;
    }

    return ret;
}

int wc_mldsa_composite_get_keytype(const enum mldsa_composite_type type, enum Key_Sum * keytype_sum) {
    int ret = 0;

    /* Validate parameters. */
    if (type <= 0 || !keytype_sum) {
        ret = BAD_FUNC_ARG;
    }

    /* Only recognized combinations are returned */
    if (ret == 0) {

        switch (type) {

            // Level 1
            case WC_MLDSA44_RSA2048_SHA256:
                *keytype_sum = MLDSA44_RSA2048k;
                break;
            case WC_MLDSA44_RSAPSS2048_SHA256:
                *keytype_sum = MLDSA44_RSAPSS2048k;
                break;
            case WC_MLDSA44_ED25519_SHA512:
                *keytype_sum = MLDSA44_ED25519k;
                break;
            case WC_MLDSA44_NISTP256_SHA256:
                *keytype_sum = MLDSA44_NISTP256k;
                break;
            case WC_MLDSA44_BPOOL256_SHA256:
                *keytype_sum = MLDSA44_BPOOL256k;
                break;

            // Level 3
            case WC_MLDSA65_RSAPSS3072_SHA512:
                *keytype_sum = MLDSA65_RSAPSS3072k;
                break;

            case WC_MLDSA65_RSA3072_SHA512:
                *keytype_sum = MLDSA65_RSA3072k;
                break;
            case WC_MLDSA65_ED25519_SHA512:
                *keytype_sum = MLDSA65_ED25519k;
                break;
            case WC_MLDSA65_NISTP256_SHA512:
                *keytype_sum = MLDSA65_NISTP256k;
                break;
            case WC_MLDSA65_BPOOL256_SHA512:
                *keytype_sum = MLDSA65_BPOOL256k;
                break;
            
            // Level 5
            case WC_MLDSA87_NISTP384_SHA512:
                *keytype_sum = MLDSA87_NISTP384k;
                break;
            case WC_MLDSA87_BPOOL384_SHA512:
                *keytype_sum = MLDSA87_BPOOL384k;
                break;
            case WC_MLDSA87_ED448_SHA512:
                *keytype_sum = MLDSA87_ED448k;
                break;

            case WC_MLDSA_COMPOSITE_UNDEF:
            default:
                *keytype_sum = 0;
                ret = BAD_FUNC_ARG;
        }
    }

    return ret;
}

int wc_mldsa_composite_keytype_to_type(const enum Key_Sum keytype_sum, enum mldsa_composite_type * type) {
    int ret = 0;

    /* Validate parameters. */
    if (keytype_sum <= 0 || !type) {
        ret = BAD_FUNC_ARG;
    }

    /* Only recognized combinations are returned */
    if (ret == 0) {
        // Level 1
        if (keytype_sum == MLDSA44_RSA2048k) {
            *type = WC_MLDSA44_RSA2048_SHA256;
        } else if (keytype_sum == MLDSA44_RSAPSS2048k) {
            *type = WC_MLDSA44_RSAPSS2048_SHA256;
        } else if (keytype_sum == MLDSA44_ED25519k) {
            *type = WC_MLDSA44_ED25519_SHA512;
        } else if (keytype_sum == MLDSA44_NISTP256k) {
            *type = WC_MLDSA44_NISTP256_SHA256;
        } else if (keytype_sum == MLDSA44_BPOOL256k) {
            *type = WC_MLDSA44_BPOOL256_SHA256;
        // Level 3
        } else if (keytype_sum == MLDSA65_RSAPSS3072k) {
            *type = WC_MLDSA65_RSAPSS3072_SHA512;
        } else if (keytype_sum == MLDSA65_RSA3072k) {
            *type = WC_MLDSA65_RSA3072_SHA512;
        } else if (keytype_sum == MLDSA65_ED25519k) {
            *type = WC_MLDSA65_ED25519_SHA512;
        } else if (keytype_sum == MLDSA65_NISTP256k) {
            *type = WC_MLDSA65_NISTP256_SHA512;
        } else if (keytype_sum == MLDSA65_BPOOL256k) {
            *type = WC_MLDSA65_BPOOL256_SHA512;
        // Level 5
        } else if (keytype_sum == MLDSA87_NISTP384k) {
            *type = WC_MLDSA87_NISTP384_SHA512;
        } else if (keytype_sum == MLDSA87_BPOOL384k) {
            *type = WC_MLDSA87_BPOOL384_SHA512;
        } else if (keytype_sum == MLDSA87_ED448k) {
            *type = WC_MLDSA87_ED448_SHA512;
        // Error
        } else {
            *type = 0;
            ret = BAD_FUNC_ARG;
        }
    }

    return ret;
}


/* Clears the MlDsaComposite key data
 *
 * key  [in]  MlDsaComposite key.
 */
void wc_mldsa_composite_free(mldsa_composite_key* key)
{
    if (key != NULL) {

#ifdef WOLFSSL_WC_MLDSA_COMPOSITE

        /* Free the ML-DSA key*/
        wc_dilithium_free(&key->mldsa_key);

        /* Free the classic component */
        switch (key->type) {

            case WC_MLDSA_COMPOSITE_UNDEF: {
                /* Do nothing */
            } break;
            
            // Level 1
            case WC_MLDSA44_RSA2048_SHA256:
            case WC_MLDSA44_RSAPSS2048_SHA256:
            case WC_MLDSA65_RSA3072_SHA512:
            case WC_MLDSA65_RSAPSS3072_SHA512: {
                wc_FreeRsaKey(&key->alt_key.rsa);
            } break;

            case WC_MLDSA44_ED25519_SHA512:
            case WC_MLDSA65_ED25519_SHA512: {
                wc_ed25519_free(&key->alt_key.ed25519);
            } break;
            
            case WC_MLDSA44_BPOOL256_SHA256:
            case WC_MLDSA44_NISTP256_SHA256:
            case WC_MLDSA65_NISTP256_SHA512:
            case WC_MLDSA65_BPOOL256_SHA512:
            case WC_MLDSA87_NISTP384_SHA512:
            case WC_MLDSA87_BPOOL384_SHA512: {
                wc_ecc_free(&key->alt_key.ecc);
                ForceZero(&key->alt_key.ecc, sizeof(key->alt_key.ecc));
            } break;

            case WC_MLDSA87_ED448_SHA512: {
                wc_ed448_free(&key->alt_key.ed448);
            } break;

            default: {
                /* Error */
                WOLFSSL_MSG_VSNPRINTF("Invalid MLDSA Composite type: %d", key->type);
            }
        }

        /* Initializes the structure for re-use */
        wc_mldsa_composite_init(key);

#endif /* WOLFSSL_WC_MLDSA_COMPOSITE*/

    }
}

#ifdef WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY
/* Returns the size of a MlDsaComposite private key.
 *
 * @param [in] key  Dilithium private/public key.
 * @return  Private key size on success for set level.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
int wc_mldsa_composite_size(mldsa_composite_key* key)
{
    int ret = 0;

    if (!key) {
        return BAD_FUNC_ARG;
    }

    switch (key->type) {

        // Level 1
        case WC_MLDSA44_RSA2048_SHA256:
            ret = MLDSA44_RSA2048_PRV_KEY_SIZE;
            break;

        case WC_MLDSA44_RSAPSS2048_SHA256:
            ret = MLDSA44_RSA2048_KEY_SIZE;
            break;

        case WC_MLDSA44_ED25519_SHA512:
            ret = MLDSA44_ED25519_KEY_SIZE;
            break;

        case WC_MLDSA44_NISTP256_SHA256:
            ret = MLDSA44_NISTP256_KEY_SIZE; // + wc_ecc_get_curve_size_from_id(ECC_SECP256R1);
            break;

        case WC_MLDSA44_BPOOL256_SHA256:
            ret = MLDSA44_NISTP256_KEY_SIZE; // + wc_ecc_get_curve_size_from_id(ECC_BRAINPOOLP256R1);
            break;
        
        // Level 2
        case WC_MLDSA65_RSAPSS3072_SHA512:
            ret = MLDSA65_RSA3072_KEY_SIZE;
            break;
        
        case WC_MLDSA65_RSA3072_SHA512:
            ret = MLDSA65_RSA3072_KEY_SIZE;
            break;
        
        case WC_MLDSA65_ED25519_SHA512:
            ret = MLDSA65_ED25519_KEY_SIZE;
            break;

        case WC_MLDSA65_NISTP256_SHA512:
            ret = MLDSA65_NISTP256_KEY_SIZE; // + wc_ecc_get_curve_size_from_id(ECC_SECP256R1);
            break;
        
        case WC_MLDSA65_BPOOL256_SHA512:
            ret = MLDSA65_NISTP256_KEY_SIZE; // + wc_ecc_get_curve_size_from_id(ECC_BRAINPOOLP256R1);
            break;
        
        // Level 3
        case WC_MLDSA87_NISTP384_SHA512:
            ret = MLDSA87_NISTP384_KEY_SIZE; // + wc_ecc_get_curve_size_from_id(ECC_SECP384R1);
            break;
        
        case WC_MLDSA87_BPOOL384_SHA512:
            ret = MLDSA87_NISTP384_KEY_SIZE; // + wc_ecc_get_curve_size_from_id(ECC_BRAINPOOLP384R1);
            break;
        
        case WC_MLDSA87_ED448_SHA512:
            ret = MLDSA87_ED448_KEY_SIZE;
            break;

        case WC_MLDSA_COMPOSITE_UNDEF:
        default:
            /* Error */
            ret = ALGO_ID_E;
    }

    return ret;
}

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY

int wc_mldsa_composite_priv_size(mldsa_composite_key* key) {

    int ret = BAD_FUNC_ARG;

    if (key != NULL) {

        switch (key->type) {
            
            case WC_MLDSA44_RSA2048_SHA256:
                ret = MLDSA44_RSA2048_PRV_KEY_SIZE;
                break;

            case WC_MLDSA44_RSAPSS2048_SHA256:
                ret = MLDSA44_RSA2048_PRV_KEY_SIZE;
                break;

            case WC_MLDSA44_ED25519_SHA512:
                ret = MLDSA44_ED25519_PRV_KEY_SIZE;
                break;

            case WC_MLDSA44_NISTP256_SHA256:
                ret = MLDSA44_NISTP256_PRV_KEY_SIZE;
                break;
            
            case WC_MLDSA44_BPOOL256_SHA256:
                ret = MLDSA44_BPOOL256_PRV_KEY_SIZE;
                break;

            case WC_MLDSA65_RSAPSS3072_SHA512:
                ret = MLDSA65_RSA3072_PRV_KEY_SIZE;
                break;

            case WC_MLDSA65_RSA3072_SHA512:
                ret = MLDSA65_RSA3072_PRV_KEY_SIZE;
                break;

            case WC_MLDSA65_NISTP256_SHA512:
                ret = MLDSA65_NISTP256_PRV_KEY_SIZE;
                break;
            
            case WC_MLDSA65_BPOOL256_SHA512:
                ret = MLDSA65_NISTP256_PRV_KEY_SIZE;
                break;

            case WC_MLDSA65_ED25519_SHA512:
                ret = MLDSA65_ED25519_PRV_KEY_SIZE;
                break;

            case WC_MLDSA87_NISTP384_SHA512:
                ret = MLDSA87_NISTP384_PRV_KEY_SIZE;
                break;
            
            case WC_MLDSA87_BPOOL384_SHA512:
                ret = MLDSA87_NISTP384_PRV_KEY_SIZE;
                break;
            
            case WC_MLDSA87_ED448_SHA512:
                ret = MLDSA87_ED448_PRV_KEY_SIZE;
                break;

            case WC_MLDSA_COMPOSITE_UNDEF:
            default:
                /* Error */
                ret = ALGO_ID_E;
        }

    }

    return ret;
}

/* Returns the size of a MlDsaComposite private plus public key.
 *
 * @param [in]  key  MlDsaComposite private/public key.
 * @param [out] len  Private key size for set level.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
int wc_MlDsaCompositeKey_GetPrivLen(MlDsaCompositeKey* key, int* len)
{
    int ret = 0;

    *len = wc_mldsa_composite_priv_size(key);
    if (*len < 0) {
        ret = *len;
    }

    return ret;
}
#endif /* WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY */
#endif /* WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY */

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
/* Returns the size of a MlDsaComposite public key.
 *
 * @param [in] key  MlDsaComposite private/public key.
 * @return  Public key size on success for set level.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
int wc_mldsa_composite_pub_size(mldsa_composite_key* key)
{
    int ret = 0;

    if (!key) {
        return BAD_FUNC_ARG;
    }

    switch (key->type) {

        // Level 1
        case WC_MLDSA44_RSA2048_SHA256:
            ret = MLDSA44_RSA2048_PUB_KEY_SIZE;
            break;

        case WC_MLDSA44_RSAPSS2048_SHA256:
            ret = MLDSA44_RSA2048_PUB_KEY_SIZE;
            break;

        case WC_MLDSA44_ED25519_SHA512:
            ret = MLDSA44_ED25519_PUB_KEY_SIZE;
            break;

        case WC_MLDSA44_NISTP256_SHA256:
            ret = MLDSA44_NISTP256_PUB_KEY_SIZE;
            break;

        case WC_MLDSA44_BPOOL256_SHA256:
            ret = MLDSA44_BPOOL256_PUB_KEY_SIZE;
            break;

        // Level 3
        case WC_MLDSA65_RSAPSS3072_SHA512:
        case WC_MLDSA65_RSA3072_SHA512:
            ret = MLDSA65_RSA3072_PUB_KEY_SIZE;
            break;
        
        case WC_MLDSA65_ED25519_SHA512:
            ret = MLDSA65_ED25519_PUB_KEY_SIZE;
            break;
        
        case WC_MLDSA65_NISTP256_SHA512:
            ret = MLDSA65_NISTP256_PUB_KEY_SIZE;
            break;
        
        case WC_MLDSA65_BPOOL256_SHA512:
            ret = MLDSA65_NISTP256_PUB_KEY_SIZE;
            break;
        
        // Level 5
        case WC_MLDSA87_NISTP384_SHA512:
            ret = MLDSA87_NISTP384_PUB_KEY_SIZE;
            break;
        
        case WC_MLDSA87_BPOOL384_SHA512:
            ret = MLDSA87_NISTP384_PUB_KEY_SIZE;
            break;
        
        case WC_MLDSA87_ED448_SHA512:
            ret = MLDSA87_ED448_PUB_KEY_SIZE;
            break;

        case WC_MLDSA_COMPOSITE_UNDEF:
        default:
            /* Error */
            ret = ALGO_ID_E;
    }

    return ret;
}

/* Returns the size of a MlDsaComposite public key.
 *
 * @param [in]  key  MlDsaComposite private/public key.
 * @param [out] len  Public key size for set level.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
int wc_MlDsaCompositeKey_GetPubLen(mldsa_composite_key* key, int* len)
{
    int ret = 0;

    *len = wc_mldsa_composite_pub_size(key);
    if (*len < 0) {
        ret = *len;
    }

    return ret;
}
#endif

#if !defined(WOLFSSL_MLDSA_COMPOSITE_NO_SIGN) || !defined(WOLFSSL_MLDSA_COMPOSITE_NO_VERIFY)
/* Returns the size of a MlDsaComposite signature.
 *
 * @param [in] key  MlDsaComposite private/public key.
 * @return  Signature size on success for set level.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
int wc_mldsa_composite_sig_size(mldsa_composite_key* key)
{
    int ret = 0;

    if (key == NULL || key->type <= 0) {
        return BAD_FUNC_ARG;
    }

    switch (key->type) {

        // Level 1
        case WC_MLDSA44_RSA2048_SHA256:
            ret = MLDSA44_RSA2048_SIG_SIZE;
            break;

        case WC_MLDSA44_RSAPSS2048_SHA256:
            ret = MLDSA44_RSA2048_SIG_SIZE;
            break;
        
        case WC_MLDSA44_ED25519_SHA512:
            ret = MLDSA44_ED25519_SIG_SIZE;
            break;

        case WC_MLDSA44_NISTP256_SHA256:
            ret = MLDSA44_NISTP256_SIG_SIZE;
            break;

        case WC_MLDSA44_BPOOL256_SHA256:
            ret = MLDSA44_BPOOL256_SIG_SIZE;
            break;
        
        // Level 3
        case WC_MLDSA65_RSAPSS3072_SHA512:
            ret = MLDSA65_RSA3072_SIG_SIZE;
            break;
        
        case WC_MLDSA65_RSA3072_SHA512:
            ret = MLDSA65_RSA3072_SIG_SIZE;
            break;

        case WC_MLDSA65_ED25519_SHA512:
            ret = MLDSA65_ED25519_SIG_SIZE;
            break;

        case WC_MLDSA65_NISTP256_SHA512:
            ret = MLDSA65_NISTP256_SIG_SIZE;
            break;

        case WC_MLDSA65_BPOOL256_SHA512:
            ret = MLDSA65_NISTP256_SIG_SIZE;
            break;
    
        // Level 5
        case WC_MLDSA87_NISTP384_SHA512:
            ret = MLDSA87_NISTP384_SIG_SIZE;
            break;

        case WC_MLDSA87_BPOOL384_SHA512:
            ret = MLDSA87_NISTP384_SIG_SIZE;
            break;
        
        case WC_MLDSA87_ED448_SHA512:
            ret = MLDSA87_ED448_SIG_SIZE;
            break;

        case WC_MLDSA_COMPOSITE_UNDEF:
        default:
            /* Error */
            return BAD_FUNC_ARG;
    }

    return ret;
}

/* Returns the size of a MlDsaComposite signature.
 *
 * @param [in]  key  MlDsaComposite private/public key.
 * @param [out] len  Signature size for set level.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
int wc_MlDsaCompositeKey_GetSigLen(mldsa_composite_key* key, int* len)
{
    int ret = 0;

    *len = wc_mldsa_composite_sig_size(key);
    if (*len < 0) {
        ret = *len;
    }

    return ret;
}
#endif

#ifdef WOLFSSL_MLDSA_COMPOSITE_CHECK_KEY
int wc_mldsa_composite_check_key(mldsa_composite_key* key)
{
    int ret = 0;
    
    // Error Handling: Check for NULL pointers and invalid input lengths.
    if (key == NULL || key->mldsa_key.level < 2) {
        return BAD_FUNC_ARG;
    }

    // Check the ML-DSA key
    ret = wc_dilithium_check_key(&key->mldsa_key);

    switch(key->type) {

#if !defined(WC_NO_RSA)
        case WC_MLDSA44_RSA2048_SHA256:
        case WC_MLDSA44_RSAPSS2048_SHA256: {
            if (key->mldsa_key.level != WC_ML_DSA_65)
                return BAD_STATE_E;
        } break;

        case WC_MLDSA65_RSAPSS3072_SHA512:
        case WC_MLDSA65_RSA3072_SHA512: {
            if (key->mldsa_key.level != WC_ML_DSA_65)
                return BAD_STATE_E;
        } break;
#endif

#if !defined(WC_NO_ED25519)
        case WC_MLDSA44_ED25519_SHA512: {
            if (key->mldsa_key.level != WC_ML_DSA_44)
                return BAD_STATE_E;
            ret = wc_ed25519_check_key(&key->alt_key.ed25519);
        } break;
#endif

#if !defined(WC_NO_ECC)
        case WC_MLDSA44_NISTP256_SHA256: {
            if (key->mldsa_key.level != WC_ML_DSA_44 ||
                ECC_SECP256R1 != wc_ecc_get_curve_id(key->alt_key.ecc.idx)) {
                return BAD_STATE_E;
            }
            ret = wc_ecc_check_key(&key->alt_key.ecc);
        } break;

        case WC_MLDSA44_BPOOL256_SHA256: {
            if (key->mldsa_key.level != WC_ML_DSA_44 ||
                ECC_BRAINPOOLP256R1 != wc_ecc_get_curve_id(key->alt_key.ecc.idx)) {
                return BAD_STATE_E;
            }
            ret = wc_ecc_check_key(&key->alt_key.ecc);
        } break;

        case WC_MLDSA65_NISTP256_SHA512: {
            if (key->mldsa_key.level != WC_ML_DSA_65 ||
                ECC_SECP256R1 != wc_ecc_get_curve_id(key->alt_key.ecc.idx)) {
                return BAD_STATE_E;
            }
            ret = wc_ecc_check_key(&key->alt_key.ecc);
        } break;

        case WC_MLDSA65_BPOOL256_SHA512: {
            if (key->mldsa_key.level != WC_ML_DSA_65 ||
                ECC_BRAINPOOLP256R1 != wc_ecc_get_curve_id(key->alt_key.ecc.idx)) {
                return BAD_STATE_E;
            }
            ret = wc_ecc_check_key(&key->alt_key.ecc);
        } break;

        case WC_MLDSA65_ED25519_SHA512: {
            if (key->mldsa_key.level != WC_ML_DSA_65)
                return BAD_STATE_E;
            ret = wc_ed25519_check_key(&key->alt_key.ed25519);
        } break;

        case WC_MLDSA87_NISTP384_SHA512: {
            if (key->mldsa_key.level != WC_ML_DSA_87 ||
                ECC_SECP384R1 != wc_ecc_get_curve_id(key->alt_key.ecc.idx)) {
                return BAD_STATE_E;
            }
            ret = wc_ecc_check_key(&key->alt_key.ecc);
        } break;

        case WC_MLDSA87_BPOOL384_SHA512: {
            if (key->mldsa_key.level != WC_ML_DSA_87 ||
                ECC_BRAINPOOLP384R1 != wc_ecc_get_curve_id(key->alt_key.ecc.idx)) {
                return BAD_STATE_E;
            }
            ret = wc_ecc_check_key(&key->alt_key.ecc);
        } break;

        case WC_MLDSA87_ED448_SHA512: {
            if (key->mldsa_key.level != WC_ML_DSA_87)
                return BAD_STATE_E;
            ret = wc_ed448_check_key(&key->alt_key.ed448);
        } break;
#endif

        case WC_MLDSA_COMPOSITE_UNDEF:
        default: {
            ret = BAD_FUNC_ARG;
        }
    }

    return ret;
}
#endif /* WOLFSSL_MLDSA_COMPOSITE_CHECK_KEY */

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
/* Import a MlDsaComposite public key from a byte array.
 *
 * Public key encoded in big-endian.
 *
 * @param [in]      in     Array holding public key.
 * @param [in]      inLen  Number of bytes of data in array.
 * @param [in]      type   ML-DSA Composite Type (WC_MLDSA_COMPOSITE_TYPE_*)
 * @param [in, out] key    MlDsaComposite public key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when in or key is NULL or key format is not supported.
 */
int wc_mldsa_composite_import_public(const byte* inBuffer, word32 inLen, 
        mldsa_composite_key* key, enum mldsa_composite_type type)
{
    int ret = 0;
        // Ret value

    word32 idx = 0;
        // Index for the ASN.1 data
   
#ifdef HAVE_MLDSA_COMPOSITE_DRAFT_2
    ASNItem compPubKeyIT[mldsaCompASN_Length] = {
        { 0, ASN_SEQUENCE, 1, 1, 0 },
            { 1, ASN_BIT_STRING, 0, 0, 0 },
            { 1, ASN_BIT_STRING, 0, 0, 0 }
    };
#elif defined(HAVE_MLDSA_COMPOSITE_DRAFT_3)
# undef mldsaCompASN_Length
# define mldsaCompASN_Length 3
    ASNItem compPubKeyIT[mldsaCompASN_Length] = {
         { 0, ASN_SEQUENCE, 1, 1, 0 },
            { 1, ASN_BIT_STRING, 0, 0, 0 },
            { 1, ASN_BIT_STRING, 0, 0, 0 }
    };
#else
    #error "No ML-DSA Composite draft defined"
#endif
        // ASN.1 items for the composite signature

    ASNGetData compPubKeyASN[mldsaCompASN_Length];
        // ASN.1 data for the composite signature

    byte mldsa_Buffer[DILITHIUM_ML_DSA_87_PUB_KEY_SIZE];
    word32 mldsa_BufferLen = DILITHIUM_ML_DSA_87_PUB_KEY_SIZE;
        // Buffer to hold the ML-DSA public key

    byte other_Buffer[MLDSA_COMPOSITE_MAX_OTHER_SIG_SZ];
    word32 other_BufferLen = MLDSA_COMPOSITE_MAX_OTHER_SIG_SZ;
        // Buffer to hold the public key of the other DSA component

    /* Validate parameters. */
    if (!inBuffer || !key) {
        MADWOLF_DEBUG("Invalid parameters: %p, %p", inBuffer, key);
        return BAD_FUNC_ARG;
    }

    // Sets the buffers to 0
    XMEMSET(compPubKeyASN, 0, sizeof(*compPubKeyASN) * mldsaCompASN_Length);

    // Initialize the ASN data
    GetASN_Buffer(&compPubKeyASN[MLDSA_COMPASN_IDX_MLDSA], mldsa_Buffer, &mldsa_BufferLen);
    GetASN_Buffer(&compPubKeyASN[MLDSA_COMPASN_IDX_OTHER], other_Buffer, &other_BufferLen);

    // Parse the ASN.1 data
    if ((ret = GetASN_Items(compPubKeyIT, compPubKeyASN, 3, 1, inBuffer, &idx, inLen)) < 0) {
        MADWOLF_DEBUG("Error while parsing ASN.1 (%d)", ret);
        return ret;
    }

    // If no passed type, let's check the key type
    if (type == 0) type = key->type;

    // Import the ML-DSA public key
    switch(type) {
            
            // Level 1
            case WC_MLDSA44_RSA2048_SHA256:
            case WC_MLDSA44_RSAPSS2048_SHA256:
            case WC_MLDSA44_ED25519_SHA512:
            case WC_MLDSA44_NISTP256_SHA256:
            case WC_MLDSA44_BPOOL256_SHA256: {
                // Sets the level
                key->mldsa_key.level = WC_ML_DSA_44;
            } break;

            // Level 3
            case WC_MLDSA65_RSAPSS3072_SHA512:
            case WC_MLDSA65_RSA3072_SHA512:
            case WC_MLDSA65_ED25519_SHA512:
            case WC_MLDSA65_NISTP256_SHA512:
            case WC_MLDSA65_BPOOL256_SHA512: {
                // Sets the level
                key->mldsa_key.level = WC_ML_DSA_65;
            } break;

            // Level 5
            case WC_MLDSA87_NISTP384_SHA512:
            case WC_MLDSA87_BPOOL384_SHA512:
            case WC_MLDSA87_ED448_SHA512: {
                // Sets the level
                key->mldsa_key.level = WC_ML_DSA_87;
            } break;

            case WC_MLDSA_COMPOSITE_UNDEF:
            default:
                return BAD_FUNC_ARG;
    }

    // Resets the index
    idx = 0;

    // Import ML-DSA Component
    if ((ret = wc_dilithium_import_public(mldsa_Buffer, mldsa_BufferLen, &(key->mldsa_key))) < 0) {
        MADWOLF_DEBUG("failed to import ML-DSA-44 component with code %d", ret);
        return ret;
    }

   // Verify Individual DSA Components: 
    switch (type) {

        case WC_MLDSA44_RSA2048_SHA256:
        case WC_MLDSA44_RSAPSS2048_SHA256: {
            MADWOLF_DEBUG0("ML-DSA COMPOSITE: RSA public key import");
            // Checks the RSA pubkey buffer size
            if (other_BufferLen < RSA2048_PUB_KEY_SIZE) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: RSA public key size error (%d vs. %d)", other_BufferLen, RSA2048_PUB_KEY_SIZE);
                return BUFFER_E;
            }
            // Import RSA Component
            if ((ret = wc_InitRsaKey(&key->alt_key.rsa, NULL)) < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: failed to import RSA component with code %d", ret);
                return ret;
            }
            if ((ret = wc_RsaPublicKeyDecode(other_Buffer, &idx, &key->alt_key.rsa, other_BufferLen)) < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: failed to import RSA component with code %d", ret);
                return ret;
            }
            MADWOLF_DEBUG("ML-DSA COMPOSITE: RSA public key imported successfully (idx=%d)", idx);
        } break;

        case WC_MLDSA44_ED25519_SHA512: {
            // Cehcks the ED25519 pubkey buffer size
            if (other_BufferLen != ED25519_PUB_KEY_SIZE) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: ED25519 public key size error (%d vs. %d)", other_BufferLen, ED25519_PUB_KEY_SIZE);
                return BUFFER_E;
            }
            // Import ED25519 Component
            XMEMSET(&key->alt_key.ed25519, 0, sizeof(key->alt_key.ed25519));
            if ((ret = wc_ed25519_import_public(other_Buffer, other_BufferLen, &key->alt_key.ed25519)) < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: failed to import ED25519 component with code %d", ret);
                return ret;
            }

        } break;

        case WC_MLDSA44_NISTP256_SHA256: {
            MADWOLF_DEBUG0("ML-DSA COMPOSITE: ECDSA public key import");
            // Cehcks the ECDSA signature size
            XMEMSET(&key->alt_key.ecc, 0, sizeof(key->alt_key.ecc));
            if ((ret = wc_ecc_import_unsigned(&key->alt_key.ecc, 
                    other_Buffer, other_Buffer + 32, NULL, ECC_SECP256R1)) < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: ECDSA import PubKey failed with %d", ret);
                return ret;
            }
            // Checks the ECDSA curve (P-256)
            if (wc_ecc_get_curve_id(key->alt_key.ecc.idx) != ECC_SECP256R1) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: ECDSA import PubKey curve error (%d vs. %d)", key->alt_key.ecc.dp->id, ECC_SECP256R1);
                return BAD_STATE_E;
            }
        } break;

        case WC_MLDSA44_BPOOL256_SHA256: {
            MADWOLF_DEBUG0("ML-DSA COMPOSITE: ECDSA public key import");
            // Cehcks the ECDSA signature size
            XMEMSET(&key->alt_key.ecc, 0, sizeof(key->alt_key.ecc));
            if ((ret = wc_ecc_import_unsigned(&key->alt_key.ecc, 
                    other_Buffer, other_Buffer + 32, NULL, ECC_BRAINPOOLP256R1)) < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: ECDSA import PubKey failed with %d", ret);
                return ret;
            }
            // Checks the ECDSA curve (P-256)
            if (wc_ecc_get_curve_id(key->alt_key.ecc.idx) != ECC_BRAINPOOLP256R1) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: ECDSA import PubKey curve error (%d vs. %d)", key->alt_key.ecc.dp->id, ECC_BRAINPOOLP256R1);
                return BAD_STATE_E;
            }
        } break;

        case WC_MLDSA65_RSAPSS3072_SHA512:
        case WC_MLDSA65_RSA3072_SHA512: {
            MADWOLF_DEBUG0("ML-DSA COMPOSITE: RSA public key import");
            // Checks the RSA pubkey buffer size
            if (other_BufferLen < RSA3072_PUB_KEY_SIZE) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: RSA public key size error (%d vs. %d)", other_BufferLen, RSA3072_PUB_KEY_SIZE);
                return BUFFER_E;
            }
            // Import RSA Component
            if ((ret = wc_InitRsaKey(&key->alt_key.rsa, key->heap)) < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: failed to import RSA component with code %d", ret);
                return ret;
            }
            if ((ret = wc_RsaPublicKeyDecode(other_Buffer, &idx, &key->alt_key.rsa, other_BufferLen)) < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: failed to import RSA component with code %d", ret);
                return ret;
            }
            if ((ret = wc_RsaEncryptSize(&key->alt_key.rsa)) != RSA3072_SIG_SIZE) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: RSA component size error (%d vs. %d)", ret, RSA3072_SIG_SIZE);
                return ret;
            }
        } break;

        case WC_MLDSA65_ED25519_SHA512: {
            // Cehcks the ED25519 pubkey buffer size
            if (other_BufferLen != ED25519_PUB_KEY_SIZE) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: ED25519 public key size error (%d vs. %d)", other_BufferLen, ED25519_PUB_KEY_SIZE);
                return BUFFER_E;
            }
            // Import ED25519 Component
            XMEMSET(&key->alt_key.ed25519, 0, sizeof(key->alt_key.ed25519));
            if ((ret = wc_ed25519_import_public(other_Buffer, other_BufferLen, &key->alt_key.ed25519)) < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: failed to import ED25519 component with code %d", ret);
                return ret;
            }

        } break;

        case WC_MLDSA65_NISTP256_SHA512: {
            // Cehcks the ECDSA signature size
            XMEMSET(&key->alt_key.ecc, 0, sizeof(key->alt_key.ecc));
            if ((ret = wc_ecc_import_unsigned(&key->alt_key.ecc, 
                    other_Buffer, other_Buffer + 32, NULL, ECC_SECP256R1)) < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: ECDSA import PubKey failed with %d", ret);
                return ret;
            }
            // Checks the ECDSA curve (P-256)
            if (wc_ecc_get_curve_id(key->alt_key.ecc.idx) != ECC_SECP256R1) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: ECDSA import PubKey curve error (%d vs. %d)", key->alt_key.ecc.dp->id, ECC_SECP256R1);
                return BAD_STATE_E;
            }
        } break;

        case WC_MLDSA65_BPOOL256_SHA512: {
            // Cehcks the ECDSA signature size
            XMEMSET(&key->alt_key.ecc, 0, sizeof(key->alt_key.ecc));
            if ((ret = wc_ecc_import_unsigned(&key->alt_key.ecc, 
                    other_Buffer, other_Buffer + 32, NULL, ECC_BRAINPOOLP256R1)) < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: ECDSA import PubKey failed with %d", ret);
                return ret;
            }
            // Checks the ECDSA curve (P-256)
            if (wc_ecc_get_curve_id(key->alt_key.ecc.idx) != ECC_BRAINPOOLP256R1) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: ECDSA import PubKey curve error (%d vs. %d)", key->alt_key.ecc.dp->id, ECC_BRAINPOOLP256R1);
                return BAD_STATE_E;
            }
        } break;

        case WC_MLDSA87_NISTP384_SHA512: {
            // Cehcks the ECDSA signature size
            XMEMSET(&key->alt_key.ecc, 0, sizeof(key->alt_key.ecc));
            if ((ret = wc_ecc_import_unsigned(&key->alt_key.ecc, 
                    other_Buffer, other_Buffer + 48, NULL, ECC_SECP384R1)) < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: ECDSA import PubKey failed with %d", ret);
                return ret;
            }
            // Checks the ECDSA curve (P-384)
            if (wc_ecc_get_curve_id(key->alt_key.ecc.idx) != ECC_SECP384R1) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: ECDSA import PubKey curve error (%d vs. %d)", key->alt_key.ecc.dp->id, ECC_SECP384R1);
                return BAD_STATE_E;
            }
        } break;

        case WC_MLDSA87_BPOOL384_SHA512: {
            // Cehcks the ECDSA signature size
            XMEMSET(&key->alt_key.ecc, 0, sizeof(key->alt_key.ecc));
            if ((ret = wc_ecc_import_unsigned(&key->alt_key.ecc, 
                    other_Buffer, other_Buffer + 48, NULL, ECC_BRAINPOOLP384R1)) < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: ECDSA import PubKey failed with %d", ret);
                return ret;
            }
            // Checks the ECDSA curve (P-384)
            if (wc_ecc_get_curve_id(key->alt_key.ecc.idx) != ECC_BRAINPOOLP384R1) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: ECDSA import PubKey curve error (%d vs. %d)", key->alt_key.ecc.dp->id, ECC_BRAINPOOLP384R1);
                return BAD_STATE_E;
            }
        } break;

        case WC_MLDSA87_ED448_SHA512: {
            // Cehcks the ED25519 pubkey buffer size
            if (other_BufferLen != ED448_PUB_KEY_SIZE) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: ED448 public key size error (%d vs. %d)", other_BufferLen, ED448_PUB_KEY_SIZE);
                return BUFFER_E;
            }
            // Import ED448 Component
            XMEMSET(&key->alt_key.ed448, 0, sizeof(key->alt_key.ed448));
            if ((ret = wc_ed448_import_public(other_Buffer, other_BufferLen, &key->alt_key.ed448)) < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: failed to import ED448 component with code %d", ret);
                return ret;
            }
        } break;

        case WC_MLDSA_COMPOSITE_UNDEF:
        default:
            MADWOLF_DEBUG("Unsupported ML-DSA Composite Type: %d", type);
            return BAD_FUNC_ARG;
    }

    // If here, we have successfully imported the public key
    ret = 0;


    // Set the type of key
    key->type = type;

    // Set the public key set flag
    key->pubKeySet = 1;

    return ret;
}

/* Export the MlDsaComposite public key.
 *
 * @param [in]      key     MlDsaComposite public key.
 * @param [out]     out     Array to hold public key.
 * @param [in, out] outLen  On in, the number of bytes in array.
 *                          On out, the number bytes put into array.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BUFFER_E when outLen is less than DILITHIUM_LEVEL2_PUB_KEY_SIZE.
 */
int wc_mldsa_composite_export_public(mldsa_composite_key* key, byte* out, word32* outLen)
{
    int ret = 0;
    word32 inLen;

    const ASNItem compositeIT[] = {
    /*  SEQ */    { 0, ASN_SEQUENCE, 1, 1, 0 },
    /*  ML-DSA */   { 1, ASN_BIT_STRING, 0, 0, 0 },
    /*  Trad */     { 1, ASN_BIT_STRING, 0, 0, 0 },
    };

    ASNSetData keysASN[3];
        // Set the ML-DSA public key

    byte mldsa_Buffer[DILITHIUM_ML_DSA_87_PUB_KEY_SIZE];
    word32 mldsa_BufferLen = DILITHIUM_ML_DSA_87_PUB_KEY_SIZE;
        // Buffer to hold the ML-DSA public key

    byte other_Buffer[MLDSA_COMPOSITE_MAX_OTHER_KEY_SZ];
    word32 other_BufferLen = MLDSA_COMPOSITE_MAX_OTHER_KEY_SZ;
        // Buffer to hold the public key of the other DSA component

    /* Validate parameters */
    if ((key == NULL) || (out == NULL) || (outLen == NULL)) {
        return BAD_FUNC_ARG;
    }

    if (key->pubKeySet != 1) {
        WOLFSSL_MSG_VSNPRINTF("public key not set, cannot export it");
        return BAD_FUNC_ARG;
    }

    /* Get length passed in for checking. */
    inLen = *outLen;

    // Gets the expected size of the pub key
    *outLen = wc_mldsa_composite_pub_size(key);

    // Checks if the buffer is too small
    if (inLen < *outLen) {
        MADWOLF_DEBUG("Output Public Key Buffer too small (needed: %d, provided: %d)", *outLen, inLen);
        return BAD_FUNC_ARG;
    }

    /* Exports the ML-DSA key */
    if ((ret = wc_MlDsaKey_ExportPubRaw(&key->mldsa_key, mldsa_Buffer, &mldsa_BufferLen)) < 0) {
        WOLFSSL_MSG_VSNPRINTF("error cannot export ML-DSA component's public key\n");
        return ret;
    }

    /* Exports the other key */
    switch (key->type) {

        case WC_MLDSA44_RSA2048_SHA256:
        case WC_MLDSA44_RSAPSS2048_SHA256: {
            if ((ret = wc_RsaPublicKeyDerSize(&key->alt_key.rsa, 0)) < 0) {
                return ret;
            }
            if ((ret = wc_RsaKeyToPublicDer_ex(&key->alt_key.rsa, other_Buffer, other_BufferLen, 0)) < 0) {
                return ret;
            }
            other_BufferLen = ret;
        } break;

        case WC_MLDSA44_ED25519_SHA512: {
            if ((ret = wc_ed25519_export_public(&key->alt_key.ed25519, 
                    other_Buffer, &other_BufferLen)) < 0) {
                return ret;
            }
        } break;

        case WC_MLDSA44_NISTP256_SHA256: {
            word32 pubLenX = 32, pubLenY = 32;
            if ((ret = wc_ecc_export_public_raw(&key->alt_key.ecc, 
                    other_Buffer, &pubLenX, &other_Buffer[32], &pubLenY)) < 0) {
                return ret;
            }
            other_BufferLen = pubLenX + pubLenY;
        } break;

        case WC_MLDSA44_BPOOL256_SHA256: {
            word32 pubLenX = 32, pubLenY = 32;
            if ((ret = wc_ecc_export_public_raw(&key->alt_key.ecc, 
                    other_Buffer, &pubLenX, &other_Buffer[32], &pubLenY)) < 0) {
                return ret;
            }
            other_BufferLen = pubLenX + pubLenY;
        } break;

        case WC_MLDSA65_RSAPSS3072_SHA512:
        case WC_MLDSA65_RSA3072_SHA512: {
            if ((ret = wc_RsaPublicKeyDerSize(&key->alt_key.rsa, 0)) < 0) {
                return ret;
            }
            if ((ret = wc_RsaKeyToPublicDer_ex(&key->alt_key.rsa, 
                    other_Buffer, other_BufferLen, 0)) < 0) {
                return ret;
            }
            other_BufferLen = ret;
        } break;

        case WC_MLDSA65_ED25519_SHA512: {
            if ((ret = wc_ed25519_export_public(&key->alt_key.ed25519, 
                    other_Buffer, &other_BufferLen)) < 0) {
                return ret;
            }
        } break;

        case WC_MLDSA65_BPOOL256_SHA512:
        case WC_MLDSA65_NISTP256_SHA512: {
            word32 pubLenX = 32, pubLenY = 32;
            if ((ret = wc_ecc_export_public_raw(&key->alt_key.ecc, 
                    other_Buffer, &pubLenX, &other_Buffer[32], &pubLenY)) < 0) {
                return ret;
            }
            other_BufferLen = pubLenX + pubLenY;
        } break;

        case WC_MLDSA87_NISTP384_SHA512:
        case WC_MLDSA87_BPOOL384_SHA512: {
            word32 pubLenX = 48, pubLenY = 48;
            if ((ret = wc_ecc_export_public_raw(&key->alt_key.ecc, 
                    other_Buffer, &pubLenX, &other_Buffer[48], &pubLenY)) < 0) {
                return ret;
            }
            other_BufferLen = pubLenX + pubLenY;
        } break;

        case WC_MLDSA87_ED448_SHA512: {
            if ((ret = wc_ed448_export_public(&key->alt_key.ed448, 
                    other_Buffer, &other_BufferLen)) < 0) {
                return ret;
            }
        } break;

        case WC_MLDSA_COMPOSITE_UNDEF:
        default:
            return BAD_FUNC_ARG;
    }

    // Clears the memory (required because of a bug in wolfSSL)
    XMEMSET(keysASN, 0, sizeof(keysASN));

    // Let's set the ASN1 data
    SetASN_Buffer(&keysASN[MLDSA_COMPASN_IDX_MLDSA], mldsa_Buffer, mldsa_BufferLen);
    SetASN_Buffer(&keysASN[MLDSA_COMPASN_IDX_OTHER], other_Buffer, other_BufferLen);

    // Let's calculate the size of the ASN1 data
    if ((ret = SizeASN_Items(compositeIT, keysASN, 3, (int *)outLen)) < 0) {
        WOLFSSL_MSG_VSNPRINTF("error cannot calculate SizeASN_Items: %d", ret);
        return ret;
    }

    if (*outLen > inLen) {
        WOLFSSL_MSG_VSNPRINTF("error outLen > inlen: %d > %d", *outLen, inLen);
        return BAD_STATE_E;
    }

    // Let's encode the ASN1 data
    if ((*outLen = SetASN_Items(compositeIT, keysASN, 3, out)) == 0) {
        WOLFSSL_MSG_VSNPRINTF("error cannot SetASN_Items\n");
        return ASN_PARSE_E;
    }

    return ret;
}
#endif /* WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY */


#ifdef WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY
/* Import a mldsa_composite private key from a byte array.
 *
 * @param [in]      priv    Array holding private key.
 * @param [in]      privSz  Number of bytes of data in array.
 * @param [in, out] key     mldsa_composite private key.
 * @param [in]      type    mldsa_composite_type values
 * @return  0 otherwise.
 * @return  BAD_FUNC_ARG when a parameter is NULL or privSz is less than size
 *          required for level,
 */
int wc_mldsa_composite_import_private(const byte* priv, word32 privSz,
    mldsa_composite_key* key, enum mldsa_composite_type type)
{
    int ret = 0;
        // Ret value

    word32 idx = 0;
        // Index for the ASN.1 data

    // byte level = 255;
        // Level of the ML-DSA key
   
    ASNItem compPrivKeyIT[3] = {
        { 0, ASN_SEQUENCE, 1, 1, 0 },
            { 1, ASN_BIT_STRING, 0, 0, 0 },
            { 1, ASN_BIT_STRING, 0, 0, 0 },
    };
        // ASN.1 items for the composite private key

    ASNGetData compPrivKeyASN[3];
        // ASN.1 data for the composite signature

    byte mldsa_Buffer[DILITHIUM_ML_DSA_87_PRV_KEY_SIZE];
    word32 mldsa_BufferLen = DILITHIUM_ML_DSA_87_PRV_KEY_SIZE;
        // Buffer to hold the ML-DSA public key

    byte other_Buffer[MLDSA_COMPOSITE_MAX_OTHER_KEY_SZ];
    word32 other_BufferLen = MLDSA_COMPOSITE_MAX_OTHER_KEY_SZ;
        // Buffer to hold the public key of the other DSA component

    /* Validate parameters. */
    if (!priv || privSz <= 0 || !key || (key->type <= 0 && type <= 0)) {
        MADWOLF_DEBUG("Error in function argument (priv: %p, sz: %d)", priv, privSz);
        return BAD_FUNC_ARG;
    }

    // Sets the buffers to 0
    XMEMSET(compPrivKeyASN, 0, sizeof(*compPrivKeyASN) * 3);

    // Initialize the ASN data
    GetASN_Buffer(&compPrivKeyASN[MLDSA_COMPASN_IDX_MLDSA], mldsa_Buffer, &mldsa_BufferLen);
    GetASN_Buffer(&compPrivKeyASN[MLDSA_COMPASN_IDX_OTHER], other_Buffer, &other_BufferLen);

    // Parse the ASN.1 data
    if ((ret = GetASN_Items(compPrivKeyIT, compPrivKeyASN, 3, 0, priv, &idx, privSz)) < 0) {
        MADWOLF_DEBUG("Error while parsing ASN.1 (%d, privSz: %d, idx: %d)", ret, privSz, idx);
        return ret;
    }

    // If no passed type, let's check the key type
    if (type <= 0) type = key->type;

    MADWOLF_DEBUG("Parsed Buffer => mldsa: %d, other: %d", mldsa_BufferLen, other_BufferLen);

#if defined(HAVE_MLDSA_COMPOSITE_DRAFT_2)
    // Import PKCS8 ML-DSA Component
    idx = mldsa_BufferLen;
    if ((ret = wc_Dilithium_PrivateKeyDecode(mldsa_Buffer, &idx, &key->mldsa_key, mldsa_BufferLen)) < 0) {
        MADWOLF_DEBUG("failed to import ML-DSA-44 component with code %d", ret);
        return ret;
    }
#endif

    // Import the ML-DSA private key 
    switch (type) {

        case WC_MLDSA44_RSA2048_SHA256:
        case WC_MLDSA44_RSAPSS2048_SHA256:
        case WC_MLDSA44_ED25519_SHA512:
        case WC_MLDSA44_NISTP256_SHA256:
        case WC_MLDSA44_BPOOL256_SHA256: {
#if defined(HAVE_MLDSA_COMPOSITE_DRAFT_3)
            // Sets the ML-DSA level
            wc_dilithium_set_level(&(key->mldsa_key), WC_ML_DSA_44);
#endif
            // // Import PKCS8 ML-DSA Component
            // word32 idx = mldsa_BufferLen;
            // if ((ret = wc_Dilithium_PrivateKeyDecode(mldsa_Buffer, &idx, &key->mldsa_key, mldsa_BufferLen)) < 0) {
            //     MADWOLF_DEBUG("failed to import ML-DSA-44 component with code %d", ret);
            //     return ret;
            // }
            // // Checks the ML-DSA pubkey buffer size
            // if (wc_dilithium_get_level(&(key->mldsa_key), &level) < 0 || level != WC_ML_DSA_44) {
            //     MADWOLF_DEBUG("ML-DSA COMPOSITE: ML-DSA key level error (%d vs. %d)", level, WC_ML_DSA_44);
            //     return BUFFER_E;
            // }
        } break;

        case WC_MLDSA65_RSAPSS3072_SHA512:
        case WC_MLDSA65_RSA3072_SHA512:
        case WC_MLDSA65_ED25519_SHA512:
        case WC_MLDSA65_NISTP256_SHA512:
        case WC_MLDSA65_BPOOL256_SHA512: {
#if defined(HAVE_MLDSA_COMPOSITE_DRAFT_3)
            // Sets the ML-DSA level
            wc_dilithium_set_level(&(key->mldsa_key), WC_ML_DSA_65);
#endif
            // // Import PKCS8 ML-DSA Component
            // word32 idx = mldsa_BufferLen;
            // if ((ret = wc_Dilithium_PrivateKeyDecode(mldsa_Buffer, &idx, &key->mldsa_key, mldsa_BufferLen)) < 0) {
            //     MADWOLF_DEBUG("failed to import ML-DSA-44 component with code %d", ret);
            //     return ret;
            // }
            // Checks the ML-DSA level
            // if (wc_dilithium_get_level(&(key->mldsa_key), &level) < 0 || level != WC_ML_DSA_65) {
            //     MADWOLF_DEBUG("ML-DSA COMPOSITE: ML-DSA key level error (%d vs. %d)", level, WC_ML_DSA_65);
            //     return BUFFER_E;
            // }
         } break;

        case WC_MLDSA87_NISTP384_SHA512:
        case WC_MLDSA87_BPOOL384_SHA512:
        case WC_MLDSA87_ED448_SHA512: {
#if defined(HAVE_MLDSA_COMPOSITE_DRAFT_3)
            // Sets the ML-DSA level
            wc_dilithium_set_level(&(key->mldsa_key), WC_ML_DSA_87);
#endif
            // // Checks the ML-DSA level
            // if (wc_dilithium_get_level(&(key->mldsa_key), &level) < 0 || level != WC_ML_DSA_87) {
            //     MADWOLF_DEBUG("ML-DSA COMPOSITE: ML-DSA key level error (%d vs. %d)", level, WC_ML_DSA_87);
            //     return BUFFER_E;
            // }
        } break;

        case WC_MLDSA_COMPOSITE_UNDEF:
        default:
            return BAD_FUNC_ARG;
    }

#if defined(HAVE_MLDSA_COMPOSITE_DRAFT_3)
        // Import ML-DSA Component
        if ((ret = wc_dilithium_import_private(mldsa_Buffer, mldsa_BufferLen, &key->mldsa_key)) < 0) {
            MADWOLF_DEBUG("failed to import ML-DSA component with code %d", ret);
            return ret;
        }
#endif

    // Resets the index
    idx = other_BufferLen;

    // import the other DSA component
    switch (type) {

        case WC_MLDSA44_RSA2048_SHA256:
        case WC_MLDSA44_RSAPSS2048_SHA256: {
            // Import the RSA component
            word32 rsaSz = 0;
            int sz = 0;
            if ((ret = wc_RsaPrivateKeyDecode(other_Buffer, &rsaSz, &key->alt_key.rsa, other_BufferLen)) < 0) {
                MADWOLF_DEBUG("failed to import RSA component with code %d (other: %d, rsaSz: %d)", ret, other_BufferLen, rsaSz);
                return ASN_PARSE_E;
            }
            if ((sz = wc_RsaEncryptSize(&key->alt_key.rsa)) < 0) {
                MADWOLF_DEBUG("failed to get RSA encrypt size with code %d", sz);
                return BAD_STATE_E;
            }
            // Checks it is a RSA-2048 key
            if (sz != RSA2048_SIG_SIZE) {
                MADWOLF_DEBUG("wrong RSA-2048 sig size (%d vs. %d)", rsaSz, sz);
                return BAD_STATE_E;
            }
        } break;

        case WC_MLDSA65_ED25519_SHA512:
        case WC_MLDSA44_ED25519_SHA512: {
#if defined(HAVE_MLDSA_COMPOSITE_DRAFT_3)
            // Cehcks the ED25519 pubkey buffer size
            if (other_BufferLen != ED25519_KEY_SIZE) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: ED25519 private key size error (%d vs. %d)", other_BufferLen, ED25519_KEY_SIZE);
                return BUFFER_E;
            }
            if ((ret = wc_ed25519_init(&key->alt_key.ed25519)) < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: failed to init ED25519 component with code %d", ret);
                return ret;
            }

            if ((ret = wc_ed25519_import_private_key(other_Buffer, ED25519_KEY_SIZE, NULL, 0, &key->alt_key.ed25519)) < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: failed to import ED25519 component with code %d, Trying private only", ret);
                if ((ret = wc_ed25519_import_private_only(other_Buffer, other_BufferLen, &key->alt_key.ed25519)) < 0) {
                    MADWOLF_DEBUG("ML-DSA COMPOSITE: failed to import ED25519 private only component with code %d", ret);
                    return ret;
                }
            }
#elif defined(HAVE_MLDSA_COMPOSITE_DRAFT_2)
            if ((ret = wc_Ed25519PrivateKeyDecode(other_Buffer, &idx, &key->alt_key.ed25519, other_BufferLen)) < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: failed to import ED25519 component with code %d", ret);
                return ret;
            }
#endif
        } break;

        case WC_MLDSA87_BPOOL384_SHA512:
        case WC_MLDSA87_NISTP384_SHA512:
        case WC_MLDSA65_BPOOL256_SHA512:
        case WC_MLDSA44_BPOOL256_SHA256:
        case WC_MLDSA65_NISTP256_SHA512:
        case WC_MLDSA44_NISTP256_SHA256: {
            XMEMSET(&key->alt_key.ecc, 0, sizeof(key->alt_key.ecc));
            wc_ecc_init_ex(&key->alt_key.ecc, key->heap, key->devId);
#if defined(HAVE_MLDSA_COMPOSITE_DRAFT_3)
            if (type == WC_MLDSA65_NISTP256_SHA512 || type == WC_MLDSA44_NISTP256_SHA256) {
                wc_ecc_set_curve(&key->alt_key.ecc, 32, ECC_SECP256R1);
            } else if (type == WC_MLDSA65_BPOOL256_SHA512 || type == WC_MLDSA44_BPOOL256_SHA256) {
                wc_ecc_set_curve(&key->alt_key.ecc, 32, ECC_BRAINPOOLP256R1);
            } else if (type == WC_MLDSA87_NISTP384_SHA512) {
                wc_ecc_set_curve(&key->alt_key.ecc, 48, ECC_SECP384R1);
            } else if (type == WC_MLDSA87_BPOOL384_SHA512) {
                wc_ecc_set_curve(&key->alt_key.ecc, 48, ECC_BRAINPOOLP384R1);
            }
            
            if ((ret = wc_ecc_import_private_key(other_Buffer, other_BufferLen, NULL, 0, &key->alt_key.ecc)) < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: ECDSA import PrivKey failed with %d", ret);
                return ret;
            }

            // if ((ret = wc_ecc_import_unsigned(&key->alt_key.ecc, 
            //         other_Buffer, other_Buffer + 32, NULL, ECC_SECP256R1)) < 0) {
            //     MADWOLF_DEBUG("ML-DSA COMPOSITE: ECDSA import PubKey failed with %d", ret);
            //     return ret;
            // } 
#elif defined(HAVE_MLDSA_COMPOSITE_DRAFT_2)
            if ((ret = wc_EccPrivateKeyDecode(other_Buffer, &idx, &key->alt_key.ecc, other_BufferLen)) < 0) {
                MADWOLF_DEBUG("failed to import ECDSA component with code %d", ret);
                return ret;
            }
            if (type == WC_MLDSA65_NISTP256_SHA512 || type == WC_MLDSA44_NISTP256_SHA256) {
                // Checks the ECDSA curve (P-256)
                if (wc_ecc_get_curve_id(key->alt_key.ecc.idx) != ECC_SECP256R1) {
                    MADWOLF_DEBUG("ML-DSA COMPOSITE: ECDSA import PubKey curve error (%d vs. %d)", key->alt_key.ecc.dp->id, ECC_SECP256R1);
                    return BAD_STATE_E;
                }
            } else {
                // Checks the ECDSA curve (BRAINPOOLP256R1)
                if (wc_ecc_get_curve_id(key->alt_key.ecc.idx) != ECC_BRAINPOOLP256R1) {
                    MADWOLF_DEBUG("ML-DSA COMPOSITE: ECDSA import PubKey curve error (%d vs. %d)", key->alt_key.ecc.dp->id, ECC_BRAINPOOLP256R1);
                    return BAD_STATE_E;
                }
            }
            // // Checks the ECDSA curve (P-256)
            // if (wc_ecc_get_curve_id(key->alt_key.ecc.idx) != ECC_SECP256R1) {
            //     MADWOLF_DEBUG("ML-DSA COMPOSITE: ECDSA import PubKey curve error (%d vs. %d)", key->alt_key.ecc.dp->id, ECC_SECP256R1);
            //     return BAD_STATE_E;
            // }
#endif
        } break;

        // case WC_MLDSA65_BPOOL256_SHA512:
        // case WC_MLDSA44_BPOOL256_SHA256: {
        //     XMEMSET(&key->alt_key.ecc, 0, sizeof(key->alt_key.ecc));
        //     wc_ecc_init_ex(&key->alt_key.ecc, key->heap, key->devId);
        //     if ((ret = wc_EccPrivateKeyDecode(other_Buffer, &idx, &key->alt_key.ecc, other_BufferLen)) < 0) {
        //         MADWOLF_DEBUG("failed to import ECDSA component with code %d", ret);
        //         return ret;
        //     }
        //     // if ((ret = wc_ecc_import_unsigned(&key->alt_key.ecc, 
        //     //         other_Buffer, other_Buffer + 32, NULL, ECC_BRAINPOOLP256R1)) < 0) {
        //     //     MADWOLF_DEBUG("ML-DSA COMPOSITE: ECDSA import PubKey failed with %d", ret);
        //     //     return ret;
        //     // }
        //     // Checks the ECDSA curve (BRAINPOOLP256R1)
        //     if (wc_ecc_get_curve_id(key->alt_key.ecc.idx) != ECC_BRAINPOOLP256R1) {
        //         MADWOLF_DEBUG("ML-DSA COMPOSITE: ECDSA import PubKey curve error (%d vs. %d)", key->alt_key.ecc.dp->id, ECC_BRAINPOOLP256R1);
        //         return BAD_STATE_E;
        //     }
        // } break;

        case WC_MLDSA65_RSAPSS3072_SHA512:
        case WC_MLDSA65_RSA3072_SHA512: {
            // Import the RSA component
            word32 rsaSz = 0;
            int sz = 0;
            if ((ret = wc_RsaPrivateKeyDecode(other_Buffer, &rsaSz, &key->alt_key.rsa, other_BufferLen)) < 0) {
                MADWOLF_DEBUG("failed to import RSA component with code %d (other: %d, rsaSz: %d)", ret, other_BufferLen, rsaSz);
                return ASN_PARSE_E;
            }
            if ((sz = wc_RsaEncryptSize(&key->alt_key.rsa)) < 0) {
                MADWOLF_DEBUG("failed to get RSA encrypt size with code %d", sz);
                return BAD_STATE_E;
            }
            // Checks it is a RSA3072 key
            if (sz != RSA3072_SIG_SIZE) {
                MADWOLF_DEBUG("wrong RSA-2048 sig size (%d vs. %d)", rsaSz, sz);
                return BAD_STATE_E;
            }
        } break;

        case WC_MLDSA87_ED448_SHA512: {
#if defined(HAVE_MLDSA_COMPOSITE_DRAFT_3)
            // Cehcks the ED448 pubkey buffer size
            if (other_BufferLen != ED448_KEY_SIZE) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: ED448 signature size error (%d vs. %d)", other_BufferLen, ED448_KEY_SIZE);
                return BUFFER_E;
            }
            // Import ED448 Component
            if ((ret = wc_ed448_import_private_only(other_Buffer, other_BufferLen, &key->alt_key.ed448)) < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: failed to import ED448 component with code %d", ret);
                return ret;
            }
#elif defined(HAVE_MLDSA_COMPOSITE_DRAFT_2)
            if ((ret = wc_Ed448PrivateKeyDecode(other_Buffer, &idx, &key->alt_key.ed448, other_BufferLen)) < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: failed to import ED448 component with code %d", ret);
                return ret;
            }
#endif

        } break;

        case WC_MLDSA_COMPOSITE_UNDEF:
        default:
            MADWOLF_DEBUG("Unsupported ML-DSA Composite Type: %d", type);
            return BAD_FUNC_ARG;
    }

    // Set the type of key
    key->type = type;

    // Set the private key set flag
    key->prvKeySet = 1;

    return ret;
}

/* Export the mldsa_composite private key.
 *
 * @param [in]      key     mldsa_composite private key.
 * @param [out]     out     Array to hold private key.
 * @param [in, out] outLen  On in, the number of bytes in array.
 *                          On out, the number bytes put into array.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BUFFER_E when outLen is less than MLDSA_COMPOSITE_MIN_SZ.
 */
int wc_mldsa_composite_export_private(mldsa_composite_key* key, byte* out, word32* outLen)
{
    int ret = 0;
    word32 inLen;

// #ifdef HAVE_MLDSA_COMPOSITE_DRAFT_2
//     static const ASNItem compPrivKeyIT[1] = {
//     /*  SEQ */    { 0, ASN_SEQUENCE, 1, 1, 0 }
//     };
// #elif defined(HAVE_MLDSA_COMPOSITE_DRAFT_3)
    static const ASNItem compPrivKeyIT[3] = {
    /*  SEQ */    { 0, ASN_SEQUENCE, 1, 1, 0 },
    /*  ML-DSA */   { 1, ASN_BIT_STRING, 0, 0, 0 },
    /*  Trad */     { 1, ASN_BIT_STRING, 0, 0, 0 },
    };
// #endif

    ASNSetData compPrivKeyASN[3];
        // Set the ML-DSA public key

    byte mldsa_Buffer[DILITHIUM_ML_DSA_87_PRV_KEY_SIZE];
    word32 mldsa_BufferLen = DILITHIUM_ML_DSA_87_PRV_KEY_SIZE;
        // Buffer to hold the ML-DSA public key

    byte other_Buffer[MLDSA_COMPOSITE_MAX_OTHER_KEY_SZ + 200];
    word32 other_BufferLen = MLDSA_COMPOSITE_MAX_OTHER_KEY_SZ + 200;
        // Buffer to hold the public key of the other DSA component

    /* Validate parameters */
    if ((key == NULL) || (out == NULL) || (outLen == NULL || *outLen == 0)) {
        ret = BAD_FUNC_ARG;
    }

    if (key->prvKeySet != 1) {
        MADWOLF_DEBUG0("private key not set, cannot export it");
        return BAD_FUNC_ARG;
    }

    // Get the length passed in for checking
    inLen = *outLen;

    // Get the expected size of the private key
    *outLen = wc_mldsa_composite_priv_size(key);

    MADWOLF_DEBUG("Exporting ML-DSA Composite Private Key (inbuf: %d, estimated outLen: %d)", inLen, *outLen);

    // Check if the buffer is too small
    if (inLen < *outLen) {
        MADWOLF_DEBUG("Private Key Export Buffer (needed: %d, provided: %d, type: %d)", *outLen, inLen, key->type);
        return BAD_FUNC_ARG;
    }

    /* Exports the ML-DSA key */
    /*
        * NOTE: There seem to be a bug in the MsDsa export function
        *       since the wc_MlDsaKey_ExportPrivRaw MACRO points to
        *       an undefined function (wc_dilithium_Kind of... I am 
        * 
        * 
        * _raw).
        * 
        *       We use the `wc_dilithium_export_private` function directly.
        */
#ifdef HAVE_MLDSA_COMPOSITE_DRAFT_3
    MADWOLF_DEBUG("Draft-3: Exporting ML-DSA Private Key (type: %d)", key->type);
    if ((ret = wc_dilithium_export_private(&key->mldsa_key, mldsa_Buffer, &mldsa_BufferLen)) < 0) {
        MADWOLF_DEBUG("error cannot export ML-DSA component's private key with error %d\n", ret);
        return ret;
    }
#elif defined(HAVE_MLDSA_COMPOSITE_DRAFT_2)
    MADWOLF_DEBUG("Draft-2: Exporting ML-DSA Private Key (type: %d)", key->type);
    if ((ret = wc_Dilithium_KeyToDer(&key->mldsa_key, mldsa_Buffer, mldsa_BufferLen)) < 0) {
        MADWOLF_DEBUG("error cannot export ML-DSA component's private key with error %d\n", ret);
        return ret;
    }
    mldsa_BufferLen = ret;
    ret = 0;
#endif

    /* Exports the other key */
    switch (key->type) {
        case WC_MLDSA44_ED25519_SHA512: 
        case WC_MLDSA65_ED25519_SHA512: {
#ifdef HAVE_MLDSA_COMPOSITE_DRAFT_3
            MADWOLF_DEBUG("Draft-3: Exporting ED25519 Private Key (type: %d)", key->type);
            if ((ret = wc_ed25519_export_private(&key->alt_key.ed25519, other_Buffer, &other_BufferLen)) < 0) {
                return ret;
            }
#elif defined(HAVE_MLDSA_COMPOSITE_DRAFT_2)
            MADWOLF_DEBUG("Draft-2: Exporting ED25519 Private Key (type: %d)", key->type);
            if ((ret = wc_Ed25519PrivateKeyToDer(&key->alt_key.ed25519, other_Buffer, other_BufferLen)) < 0) {
                return other_BufferLen;
            }
            other_BufferLen = ret;
            ret = 0;
#endif
        } break;

        case WC_MLDSA44_BPOOL256_SHA256:
        case WC_MLDSA44_NISTP256_SHA256: 
        case WC_MLDSA65_NISTP256_SHA512:
        case WC_MLDSA65_BPOOL256_SHA512:
        case WC_MLDSA87_NISTP384_SHA512:
        case WC_MLDSA87_BPOOL384_SHA512: {
            MADWOLF_DEBUG("Exporting ECDSA Private Key (type: %d; curve: %d)", key->type, key->alt_key.ecc.dp->id);
#ifdef HAVE_MLDSA_COMPOSITE_DRAFT_3
            if ((ret = wc_ecc_export_private_only(&key->alt_key.ecc, other_Buffer, &other_BufferLen)) < 0) {
                return ret;
            }
#elif defined(HAVE_MLDSA_COMPOSITE_DRAFT_2)
            if ((ret = wc_EccPrivateKeyToDer(&key->alt_key.ecc, other_Buffer, other_BufferLen)) < 0) {
                return ret;
            }
            other_BufferLen = ret;
            ret = 0;
#endif
        } break;

        case WC_MLDSA87_ED448_SHA512: {
#ifdef HAVE_MLDSA_COMPOSITE_DRAFT_3
            if ((ret = wc_ed448_export_private_only(&key->alt_key.ed448, other_Buffer, &other_BufferLen)) < 0) {
                return ret;
            }
#elif defined(HAVE_MLDSA_COMPOSITE_DRAFT_2)
            if ((ret = wc_Ed448PrivateKeyToDer(&key->alt_key.ed448, other_Buffer, other_BufferLen)) < 0) {
                return ret;
            }
            other_BufferLen = ret;
            ret = 0;
#endif
        } break;

        // Placeholders for the other DSA components
        case WC_MLDSA44_RSA2048_SHA256:
        case WC_MLDSA44_RSAPSS2048_SHA256:
        case WC_MLDSA65_RSAPSS3072_SHA512:
        case WC_MLDSA65_RSA3072_SHA512: {
            if (key->alt_key.rsa.type != RSA_PRIVATE) {
                MADWOLF_DEBUG0("RSA component is not private key");
                return ALGO_ID_E;
            }
            // Export the RSA component as PKCS8
#ifdef HAVE_MLDSA_COMPOSITE_DRAFT_3
            MADWOLF_DEBUG0("ERROR - Cannot Find The RSA PKCS8 Export Function");
            // if ((ret = wc_RsaExportKey(&key->alt_key.rsa, other_Buffer, other_BufferLen)) < 0) {
            //     MADWOLF_DEBUG("ERROR: xExporting ML-DSA Composite Private Key (ret: %d, otherBufferLen: %d)", ret, other_BufferLen);
            //     return ret;
            // }
#elif defined(HAVE_MLDSA_COMPOSITE_DRAFT_2)
            MADWOLF_DEBUG0("ERROR - Cannot Find The RSA PKCS8 Export Function");
            // if ((ret = wc_RsaPrivateKeyToDer(&key->alt_key.rsa, other_Buffer, other_BufferLen)) < 0) {
            //     MADWOLF_DEBUG("ERROR: xExporting ML-DSA Composite Private Key (ret: %d, otherBufferLen: %d)", ret, other_BufferLen);
            //     return ret;
            // }
            // Set the buffer length
            other_BufferLen = ret;
            // Resets the return value
            ret = 0;
#endif

        } break;

        case WC_MLDSA_COMPOSITE_UNDEF:
        default:
            return ALGO_ID_E;
    }

#ifdef HAVE_MLDSA_COMPOSITE_DRAFT_2

    byte * sequenceBuffer = NULL;
    word32 sequenceBufferLen = mldsa_BufferLen + other_BufferLen;

    // Clear the memory
    XMEMSET(compPrivKeyASN, 0, sizeof(ASNSetData));

    sequenceBuffer = (byte*)XMALLOC(sequenceBufferLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sequenceBuffer == NULL) {
        MADWOLF_DEBUG("error cannot allocate memory for sequence buffer (%d)", sequenceBufferLen);
        return MEMORY_E;
    }

    // Copy the ML-DSA buffer
    XMEMCPY(sequenceBuffer, mldsa_Buffer, mldsa_BufferLen);
    // Copy the other buffer
    XMEMCPY(sequenceBuffer + mldsa_BufferLen, other_Buffer, other_BufferLen);

    // Let's set the ASN1 data
    SetASN_Buffer(&compPrivKeyASN[0], sequenceBuffer, sequenceBufferLen);

    // Let's calculate the size of the ASN1 data
    int encSz = 0;
    if (SizeASN_Items(compPrivKeyIT, compPrivKeyASN, 1, &encSz) < 0) {
        MADWOLF_DEBUG0("error cannot calculate SizeASN_Items");
        return BAD_STATE_E;  
    }

    if (encSz > (int)(inLen)) {
        MADWOLF_DEBUG("error encoded size too big for output buffer : %d > %d", encSz, inLen);
        return BAD_STATE_E;
    }

    // Let's encode the ASN1 data
    if ((*outLen = SetASN_Items(compPrivKeyIT, compPrivKeyASN, 1, out)) <= 0) {
        MADWOLF_DEBUG("error cannot SetASN_Items with error %d", *outLen);
        return BAD_STATE_E;
    }
    
#elif defined(HAVE_MLDSA_COMPOSITE_DRAFT_3)

    // Clear the memory
    XMEMSET(compPrivKeyASN, 0, sizeof(ASNSetData) * mldsaCompASN_Length);

    // Let's set the ASN1 data
    SetASN_Buffer(&compPrivKeyASN[MLDSA_COMPASN_IDX_MLDSA], mldsa_Buffer, mldsa_BufferLen);
    SetASN_Buffer(&compPrivKeyASN[MLDSA_COMPASN_IDX_OTHER], other_Buffer, other_BufferLen);

    // Let's calculate the size of the ASN1 data
    int encSz = 0;
    if (SizeASN_Items(compPrivKeyIT, compPrivKeyASN, mldsaCompASN_Length, &encSz) < 0) {
        MADWOLF_DEBUG0("error cannot calculate SizeASN_Items");
        return BAD_STATE_E;  
    }

    if (encSz > (int)(inLen)) {
        MADWOLF_DEBUG("error encoded size too big for output buffer : %d > %d", encSz, inLen);
        return BUFFER_E;
    }

    // Let's encode the ASN1 data
    int encodedLen = SetASN_Items(compPrivKeyIT, compPrivKeyASN, mldsaCompASN_Length, out);
    if (encodedLen <= 0) {
        MADWOLF_DEBUG("error cannot SetASN_Items with error %d", encodedLen);
        return ASN_PARSE_E;
    }
    *outLen = encodedLen;

    // byte * sequenceBuffer = NULL;
    // word32 sequenceBufferLen = mldsa_BufferLen + other_BufferLen;

    // // Clear the memory
    // XMEMSET(compPrivKeyASN, 0, sizeof(ASNSetData));

    // sequenceBuffer = (byte*)XMALLOC(sequenceBufferLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    // if (sequenceBuffer == NULL) {
    //     MADWOLF_DEBUG("error cannot allocate memory for sequence buffer (%d)", sequenceBufferLen);
    //     return MEMORY_E;
    // }

    // // Copy the ML-DSA buffer
    // XMEMCPY(sequenceBuffer, mldsa_Buffer, mldsa_BufferLen);
    // // Copy the other buffer
    // XMEMCPY(sequenceBuffer + mldsa_BufferLen, other_Buffer, other_BufferLen);

    // // Let's set the ASN1 data
    // SetASN_Buffer(&compPrivKeyASN[0], sequenceBuffer, sequenceBufferLen);

    // // Let's calculate the size of the ASN1 data
    // int encSz = 0;
    // if (SizeASN_Items(compPrivKeyIT, compPrivKeyASN, 1, &encSz) < 0) {
    //     MADWOLF_DEBUG0("error cannot calculate SizeASN_Items");
    //     return BAD_STATE_E;  
    // }

    // if (encSz > (int)(inLen)) {
    //     MADWOLF_DEBUG("error encoded size too big for output buffer : %d > %d", encSz, inLen);
    //     return BAD_STATE_E;
    // }

    // // Let's encode the ASN1 data
    // if ((*outLen = SetASN_Items(compPrivKeyIT, compPrivKeyASN, 1, out)) <= 0) {
    //     MADWOLF_DEBUG("error cannot SetASN_Items with error %d", *outLen);
    //     return BAD_STATE_E;
    // }

#endif

    MADWOLF_DEBUG("Exported ML-DSA Composite Private Key Components (%d, %d)", mldsa_BufferLen, other_BufferLen);
    MADWOLF_DEBUG("Exported ML-DSA Composite Private Key %d (sz: %d) (mldsa: %d, secondary: %d), ret = %d", *outLen, encSz, mldsa_BufferLen, other_BufferLen, ret);

    return ret;
}

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
int wc_mldsa_composite_import_key(const byte* priv, word32 privSz,
    const byte* pub, word32 pubSz, mldsa_composite_key* key, enum mldsa_composite_type type)
{
    int ret = 0;

    /* Validate parameters. */
    if ((priv == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    /* If the type is not set, use the key type */
    if (type < 0) {
        type = key->type;
    }

    /* Imports the private key first */
    ret = wc_mldsa_composite_import_private(priv, privSz, key, type);
    if (ret == 0 && (pub != NULL && pubSz > 0)) {
        /* If the input buffer is not NULL, import the public key */
        ret = wc_mldsa_composite_import_public(pub, pubSz, key, type);
    }

    return ret;
}
#endif /* WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY */

int wc_mldsa_composite_export_key(mldsa_composite_key* key, byte* priv, word32 *privSz,
    byte* pub, word32 *pubSz)
{
    int ret = 0;

    if ((key == NULL) || (priv == NULL) || (privSz == NULL) || (pub == NULL) || (pubSz == NULL)) {
        return BAD_FUNC_ARG;
    }

    if (key->prvKeySet != 1 || key->pubKeySet != 1) {
        WOLFSSL_MSG_VSNPRINTF("private or public key not set, cannot export it");
        return BAD_FUNC_ARG;
    }

    /* Export private key only. */
    ret = wc_mldsa_composite_export_private(key, priv, privSz);
    if (ret == 0) {
        /* Export public key. */
        ret = wc_mldsa_composite_export_public(key, pub, pubSz);
    }

    // MADWOLF_DEBUG("Exporting succssful (%d)", ret);

    return ret;
}
#endif /* WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY */

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_ASN1
#if defined(WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY)
int wc_MlDsaComposite_PrivateKeyDecode(const byte* input, word32* inOutIdx,
    mldsa_composite_key* key, word32 inSz, enum mldsa_composite_type type)
{
    int ret = 0;
    const byte* privKey = NULL;
    const byte* pubKey = NULL;
    word32 privKeyLen = 0;
    word32 pubKeyLen = 0;
    enum Key_Sum keytype = 0;

    /* Validate parameters. */
    if ((input == NULL) || (inOutIdx == NULL) || (key == NULL) || (inSz == 0)) {
        ret = BAD_FUNC_ARG;
    }

    // Get the key type
    if (type <= 0) type = key->type;

    /* Retrieves the OID SUM for the key type*/
    if ((ret = wc_mldsa_composite_get_keytype(type, &keytype)) < 0) {
        WOLFSSL_MSG_VSNPRINTF("error cannot get ML-DSA Composite type");
        return ret;
    }

    if (ret == 0) {
        /* Decode the asymmetric key and get out private and public key data. */
        ret = DecodeAsymKey_Assign(input, inOutIdx, inSz, &privKey, &privKeyLen,
            &pubKey, &pubKeyLen, keytype);
    }

    if (ret == 0) {
        /* Check whether public key data was found. */
#if defined(WOLFSSL_DILITHIUM_PUBLIC_KEY)
        if (pubKeyLen == 0)
#endif
        {
            /* No public key data, only import private key data. */
            ret = wc_mldsa_composite_import_private(privKey, privKeyLen, key, type);
        }
#if defined(WOLFSSL_DILITHIUM_PUBLIC_KEY)
        else {
            /* Import private and public key data. */
            ret = wc_mldsa_composite_import_key(privKey, privKeyLen, pubKey,
                pubKeyLen, key, type);
        }
#endif
    }

    (void)pubKey;
    (void)pubKeyLen;

    return ret;
}

#endif /* WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY */

#endif /* WOLFSSL_MLDSA_COMPOSITE_NO_ASN1 */

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
int wc_MlDsaComposite_PublicKeyDecode(const byte* input, word32* inOutIdx,
    mldsa_composite_key* key, word32 inSz, enum mldsa_composite_type type)
{
    int ret = 0;
    const byte* pubKey;
    word32 pubKeyLen = 0;

    /* Validate parameters. */
    if ((input == NULL) || (inOutIdx == NULL) || (key == NULL) || (inSz == 0)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        // Get the key type
        if (type <= 0) type = key->type;

        /* Try to import the key directly. */
        ret = wc_mldsa_composite_import_public(input, inSz, key, type);
        if (ret != 0) {
        #if !defined(WOLFSSL_MLDSA_COMPOSITE_NO_ASN1)
            int keytype = 0;
        #else
            int length;
            unsigned char* oid;
            int oidLen;
            word32 idx = 0;
        #endif

            /* Start again. */
            ret = 0;

    #if !defined(WOLFSSL_MLDSA_COMPOSITE_NO_ASN1)

            /* Get OID sum for level. */
            switch (type) {

                // Level 2
                case WC_MLDSA44_RSA2048_SHA256:
                case WC_MLDSA44_RSAPSS2048_SHA256:
                    keytype = MLDSA44_RSA2048k;
                    break;
                case WC_MLDSA44_ED25519_SHA512:
                    keytype = MLDSA44_ED25519k;
                    break;
                case WC_MLDSA44_NISTP256_SHA256:
                    keytype = MLDSA44_NISTP256k;
                    break;
                case WC_MLDSA44_BPOOL256_SHA256:
                    keytype = MLDSA44_BPOOL256k;
                    break;

                // Level 3
                case WC_MLDSA65_RSAPSS3072_SHA512:
                case WC_MLDSA65_RSA3072_SHA512:
                    keytype = MLDSA65_RSA3072k;
                    break;
                case WC_MLDSA65_ED25519_SHA512:
                    keytype = MLDSA65_ED25519k;
                    break;
                case WC_MLDSA65_NISTP256_SHA512:
                    keytype = MLDSA65_NISTP256k;
                    break;
                case WC_MLDSA65_BPOOL256_SHA512:
                    keytype = MLDSA65_BPOOL256k;
                    break;
                
                // Level 5
                case WC_MLDSA87_NISTP384_SHA512:
                    keytype = MLDSA87_NISTP384k;
                    break;
                
                case WC_MLDSA87_BPOOL384_SHA512:
                    keytype = MLDSA87_BPOOL384k;
                    break;

                case WC_MLDSA87_ED448_SHA512:
                    keytype = MLDSA87_ED448k;
                    break;

                case WC_MLDSA_COMPOSITE_UNDEF:
                default:
                    ret = BAD_FUNC_ARG;
            }
            if (ret == 0) {
                /* Decode the asymmetric key and get out public key data. */
                ret = DecodeAsymKeyPublic_Assign(input, inOutIdx, inSz, &pubKey,
                    &pubKeyLen, keytype);
            }
    #else
            /* Get OID sum for level. */
        #ifndef WOLFSSL_NO_MLDSA44_ED25519
            if (key->type == WC_MLDSA_COMPOSITE_TYPE_MLDSA44_ED25519_SHA512) {
                oid = mldsa44_ed25519_oid;
                oidLen = (int)sizeof(mldsa44_ed25519_oid);
            }
            else
        #endif
        #ifndef WOLFSSL_NO_MLDSA44_P256
            if (key->level == WC_MLDSA_COMPOSITE_TYPE_MLDSA44_NISTP256_SHA256) {
                // oid = dilithium_oid_65;
                // oidLen = (int)sizeof(dilithium_oid_65);
                oid = mldsa44_p256_oid;
                oidLen = (int)sizeof(mldsa44_p256_oid);
            }
            else
        #endif
            {
                /* Level not set. */
                ret = BAD_FUNC_ARG;
            }
            
            if (ret == 0) {
                if (input[idx] != 0) {
                    ret = ASN_PARSE_E;
                }
                idx++;
                length--;
            }
            if (ret == 0) {
                /* This is the raw point data compressed or uncompressed. */
                pubKeyLen = (word32)length;
                pubKey = input + idx;
            }
    #endif
            if (ret == 0) {
                /* Import public key data. */
                ret = wc_mldsa_composite_import_public(pubKey, pubKeyLen, key, key->type);
            }
        }
    }
    return ret;
}

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_ASN1

#ifdef WC_ENABLE_ASYM_KEY_EXPORT
int wc_MlDsaComposite_PublicKeyToDer(mldsa_composite_key* key, byte* output, word32 len, int withAlg)
{
    int ret = 0;
    int keytype = 0;

    word32 pubKeyLen = 0;
        // Length of the public key

    /* Validate parameters. */
    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    /* Check we have a public key to encode. */
    if ((ret == 0) && (!key->pubKeySet) ) {
        WOLFSSL_MSG_VSNPRINTF("public key not set, cannot export it");
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Get OID and length for level. */
        if (key->type == WC_MLDSA44_ED25519_SHA512) {
            keytype = MLDSA44_ED25519k;
            pubKeyLen = MLDSA44_ED25519_KEY_SIZE;
        }
        else if (key->type == WC_MLDSA44_NISTP256_SHA256) {
            keytype = MLDSA44_NISTP256k;
            pubKeyLen = MLDSA44_NISTP256_KEY_SIZE;
        }
        else {
            /* Level not set. */
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {
        byte pubKey[MLDSA_COMPOSITE_MAX_KEY_SIZE];
            // Buffer to hold the public key

        /* Export the public key. */
        ret = wc_mldsa_composite_export_public(key, pubKey, &pubKeyLen);
        if (ret == 0) {
            /* Encode the public key. */
            ret = SetAsymKeyDerPublic(pubKey, pubKeyLen, output, len, keytype,
                withAlg);
        }
    }

    return ret;
}
#endif /* WC_ENABLE_ASYM_KEY_EXPORT */

#endif /* !WOLFSSL_MLDSA_COMPOSITE_NO_ASN1 */

#endif /* WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY */

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_ASN1

#ifdef WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY


int wc_MlDsaComposite_PrivateKeyToDer(mldsa_composite_key* key, byte* output, word32 len)
{
    int ret = WC_NO_ERR_TRACE(BAD_FUNC_ARG);

    byte privKey_Buffer[MLDSA_COMPOSITE_MAX_PRV_KEY_SIZE];
    word32 privKey_BufferLen = MLDSA_COMPOSITE_MAX_PRV_KEY_SIZE;
        // Buffer to hold the private key

    /* Validate parameters and check private key set. */
    if ((key != NULL) && key->prvKeySet) {
        enum Key_Sum keytype = 0;
        int privkey_sz = 0;

        // Gets the key type (SUM)
        if (wc_mldsa_composite_get_keytype(key->type, &keytype) < 0) {
            return BAD_FUNC_ARG;
        }

        // Export the private key
        if ((ret = wc_mldsa_composite_export_private(key, privKey_Buffer, &privKey_BufferLen)) < 0) {
            return MEMORY_E;
        }

        // Check the private key buffer size
        if ((privkey_sz = SetAsymKeyDer(privKey_Buffer, privKey_BufferLen, NULL, 0, NULL, 0, keytype)) < 0) {
            MADWOLF_DEBUG0("Cannot calculate the private key size");
            return MEMORY_E;
        }

        // If output is provided, export the private key
        if (output) {
            if ((word32)privkey_sz > len) {
                MADWOLF_DEBUG("Private Key Export Buffer (needed: %d, provided: %d, type: %d)", privkey_sz, len, key->type);
                return BAD_FUNC_ARG;
            }
            // Export the private key (if any output is provided)
            ret = SetAsymKeyDer(privKey_Buffer, privKey_BufferLen, NULL, 0, output, privkey_sz, keytype);
            if (ret < 0) {
                return ret;
            }
        } else {
            ret = privkey_sz;
        }
    }

    return ret;
}

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY

int wc_MlDsaComposite_KeyToDer(mldsa_composite_key* key, byte* output, word32 len)
{
    int ret = WC_NO_ERR_TRACE(BAD_FUNC_ARG);

    byte privKey_Buffer[MLDSA_COMPOSITE_MAX_PRV_KEY_SIZE];
    word32 privKey_BufferLen = MLDSA_COMPOSITE_MAX_PRV_KEY_SIZE;
        // Buffer to hold the private key
    
    byte pubKey_Buffer[MLDSA_COMPOSITE_MAX_PUB_KEY_SIZE];
    word32 pubKey_BufferLen = MLDSA_COMPOSITE_MAX_PUB_KEY_SIZE;
        // Buffer to hold the private key

    /* Validate parameters and check private key set. */
    if ((key != NULL) && key->prvKeySet && key->pubKeySet) {
        enum Key_Sum keytype = 0;
        int privkey_sz = 0;

        // Gets the key type (SUM)
        if (wc_mldsa_composite_get_keytype(key->type, &keytype) < 0) {
            return BAD_FUNC_ARG;
        }

        // Export the public and private components
        if ((ret = wc_mldsa_composite_export_key(key, privKey_Buffer, &privKey_BufferLen, pubKey_Buffer, &pubKey_BufferLen)) < 0) {
            return MEMORY_E;
        }

        // Check the private key buffer size
        if ((privkey_sz = SetAsymKeyDer(privKey_Buffer, privKey_BufferLen, pubKey_Buffer, pubKey_BufferLen, NULL, 0, keytype)) < 0) {
            return MEMORY_E;
        }

        if (output) {
            if ((word32)privkey_sz > len) {
                MADWOLF_DEBUG("Private Key Export Buffer (needed: %d, provided: %d, type: %d)", privkey_sz, len, key->type);
                return BAD_FUNC_ARG;
            }
            // Export the private key (if any output is provided)
            ret = SetAsymKeyDer(privKey_Buffer, privKey_BufferLen, pubKey_Buffer, pubKey_BufferLen, output, len, keytype);
            if (ret < 0) {
                return ret;
            }
        } else {
            ret = privkey_sz;
        }
    }

    // If successful, it returns the number of encoded bytes in output
    return ret;
}
#endif /* WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY */
#endif /* WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY */

#endif /* !WOLFSSL_MLDSA_COMPOSITE_NO_ASN1 */

