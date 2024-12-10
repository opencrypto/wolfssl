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
        printf("[%s:%d] %s(): " a "\n", __FILE__, __LINE__, __func__);      \
        fflush(stdout);                               \
    } while (0)


#define MADWOLF_DEBUG(a, ...)                         \
    do {                                              \
        printf("[%s:%d] %s(): " a "\n", __FILE__, __LINE__, __func__, __VA_ARGS__);      \
        fflush(stdout);                               \
    } while (0)

enum {
    MLDSA_COMPASN_IDX_SEQ   = 0,
    MLDSA_COMPASN_IDX_MLDSA = 1,
    MLDSA_COMPASN_IDX_OTHER = 2,
};

#ifdef HAVE_MLDSA_COMPOSITE_DRAFT_2
# define mldsaCompASN_Length 1
#elif defined(HAVE_MLDSA_COMPOSITE_DRAFT_3)
# define mldsaCompASN_Length 3
#else
# error "Unknown ML-DSA Composite Draft"
#endif


const byte mldsa_composite_oid_data[][13] = {
    // Unset
    { 0x0 },
    // -------------------------- Draft 2 --------------------------
    // Level 1
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x01 }, /* MLDSA44_RSAPSS2048_SHA256*/
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x02 }, /* MLDSA44_RSA2048_SHA256 */
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x03 }, /* MLDSA44_ED25519_SHA512 */
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x04 }, /* MLDSA44_NISTP256_SHA256 */
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x05 }, /* MLDSA44_BRAINP256_SHA256 */
    // Level 3
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x06 }, /* MLDSA65_RSAPSS3072_SHA512 */
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x07 }, /* MLDSA65_RSA3072_SHA512 */
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x08 }, /* MLDSA65_NISTP256_SHA512*/
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x09 }, /* MLDSA65_BRAINP256_SHA512 */
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x10 }, /* MLDSA65_ED25519_SHA512 */
    // Level 5
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x11 }, /* MLDSA87_NISTP384_SHA512 */
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x12 }, /* MLDSA87_BRAINP384_SHA512 */
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x13 }, /* MLDSA87_ED448_SHA512*/

    // -------------------------- Draft 3 --------------------------
    // Level 1
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x15 }, /* MLDSA44_RSAPSS2048_SHA256 <compSig>.21 */
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x16 }, /* MLDSA44_RSA2048_SHA256 <compSig>.22 */
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x17 }, /* MLDSA44_ED25519 <compSig>.23 */
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x18 }, /* MLDSA44_NISTP256_SHA256 <compSig>.24 */
    // Level 3
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x1A }, /* MLDSA65_RSAPSS3072_SHA256 <compSig>.26 */
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x1B }, /* MLDSA65_RSA3072_SHA256 <compSig>.27 */
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x22 }, /* MLDSA65_RSAPSS4096_SHA384 <compSig>.34 */
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x23 }, /* MLDSA65_RSA4096_SHA384 <compSig>.35 */
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x1C }, /* MLDSA65_NISTP384_SHA384 <compSig>.28 */ 
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x1D }, /* MLDSA65_BRAINP256_SHA256 <compSig>.29 */
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x1E }, /* MLDSA65_ED25519_SHA384 <compSig>.30 */
    // Level 5
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x1F }, /* MLDSA87_NISTP384_SHA384 <compSig>.31 */
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x20 }, /* MLDSA87_BRAINP384_SHA384 <compSig>.32 */
    { 0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFA, 0x6B, 0x50, 0x08, 0x01, 0x21 }, /* MLDSA87_ED448_SHA384* <compSig>.33 */
};

/******************************************************************************
 * Encode/Decode operations
 ******************************************************************************/

// Generate the composite message to be signed/verified
static int wc_mldsa_compositeTBS_msg(byte* tbsMsg, word32 *tbsLen, const byte* msg,
    word32 msgLen, mldsa_composite_key* key, const byte* context, byte contextLen) {

    int ret = 0;
        // Ret value

    int compType = 0;
        // Composite Type

    if (!tbsMsg || !tbsLen || !msg || !key) {
        return BAD_FUNC_ARG;
    }

    if ((contextLen > 0 && !context) || (msgLen <= 0) ||
            (*tbsLen < MLDSA_COMPOSITE_TBS_DATA_MIN_SZ)) {
        return BAD_FUNC_ARG;
    }

    // Set the domain
    compType = wc_mldsa_composite_level(key);
    XMEMCPY(tbsMsg, mldsa_composite_oid_data[compType], 13);
    *tbsLen = 13;

    // Adds the context, if any
    if (context) {
        XMEMCPY(tbsMsg + 13, context, contextLen);
        *tbsLen += contextLen;
    }

    /* Select the hash function to calculate the composite message */
    switch (compType) {

        case WC_MLDSA_COMPOSITE_UNDEF: {
            MADWOLF_DEBUG("Invalid Composite Type (%d)", compType);
            return ALGO_ID_E;
        } break;

        case D2_WC_MLDSA65_RSAPSS3072_SHA512:
        case D2_WC_MLDSA65_RSA3072_SHA512:
        case D2_WC_MLDSA65_NISTP256_SHA512:
        case D2_WC_MLDSA65_BPOOL256_SHA512:
        case D2_WC_MLDSA65_ED25519_SHA512:
        case D2_WC_MLDSA87_NISTP384_SHA512:
        case D2_WC_MLDSA87_BPOOL384_SHA512:
        case D2_WC_MLDSA87_ED448_SHA512: {

            if ((ret = wc_Sha512Hash(msg, msgLen, tbsMsg + *tbsLen)) < 0) {
                MADWOLF_DEBUG("wc_Sha512Hash() failed with error %d", ret);
                return ret;
            }
            *tbsLen += WC_SHA512_DIGEST_SIZE;

            // // Calculates the Message Digest
            // wc_Sha512 sha512_hash;
            // if (!((ret = wc_InitSha512(&sha512_hash)) < 0) &&
            //      !((ret = wc_Sha512Update(&sha512_hash, msg, msgLen)) < 0) &&
            //      !((ret = wc_Sha512Final(&sha512_hash, tbsMsg + *tbsLen)) < 0)) {

            //     // Adds the length of the hash to the total length
            //     *tbsLen += WC_SHA512_DIGEST_SIZE;
            // } else {
            //     return ret;
            // }

        } break;

        case D2_WC_MLDSA44_RSAPSS2048_SHA256:
        case D2_WC_MLDSA44_RSA2048_SHA256:
        // case D2_WC_MLDSA44_BPOOL256_SHA256:
        case D2_WC_MLDSA44_ED25519_SHA256:
        case D2_WC_MLDSA44_NISTP256_SHA256:
        case WC_MLDSA44_RSAPSS2048_SHA256:
        case WC_MLDSA44_RSA2048_SHA256:
        case WC_MLDSA44_ED25519_SHA256:
        case WC_MLDSA44_NISTP256_SHA256: {

            if ((ret = wc_Sha256Hash(msg, msgLen, tbsMsg + *tbsLen)) < 0) {
                MADWOLF_DEBUG("wc_Sha256Hash() failed with error %d", ret);
                return ret;
            }

            *tbsLen += WC_SHA256_DIGEST_SIZE;

            // // Calculates the Message Digest
            // wc_Sha256 sha256_hash;
            // if (!((ret = wc_InitSha256(&sha256_hash)) < 0) &&
            //      !((ret = wc_Sha256Update(&sha256_hash, msg, msgLen)) < 0 ) &&
            //      !((ret = wc_Sha256Final(&sha256_hash, tbsMsg + *tbsLen)) < 0)) {

            //     // Adds the length of the hash to the total length
            //     *tbsLen += WC_SHA256_DIGEST_SIZE;
            // } else {
            //     return ret;
            // }

        } break;

#if defined(WOLFSSL_SHA384)
        case WC_MLDSA65_RSAPSS3072_SHA384:
        case WC_MLDSA65_RSA3072_SHA384:
        case WC_MLDSA65_RSAPSS4096_SHA384:
        case WC_MLDSA65_RSA4096_SHA384:
        case WC_MLDSA65_ED25519_SHA384:
        case WC_MLDSA65_NISTP256_SHA384:
        case WC_MLDSA65_BPOOL256_SHA384:
        case WC_MLDSA87_NISTP384_SHA384:
        case WC_MLDSA87_BPOOL384_SHA384:
        case WC_MLDSA87_ED448_SHA384: {

            ret = wc_Sha384Hash(msg, msgLen, tbsMsg + *tbsLen);
            if (ret < 0) {
                MADWOLF_DEBUG("wc_Sha384Hash() failed with error %d", ret);
                return ret;
            }
            *tbsLen += WC_SHA384_DIGEST_SIZE;

            // // Calculates the Message Digest
            // wc_Sha384 sha384_hash;
            // if (!((ret = wc_InitSha384(&sha384_hash)) <0) &&
            //      !((ret = wc_Sha384Update(&sha384_hash, msg, msgLen)) <0) &&
            //      !((ret = wc_Sha384Final(&sha384_hash, tbsMsg + *tbsLen)) < 0)) {

            //     // Adds the length of the hash to the total length
            //     *tbsLen += WC_SHA384_DIGEST_SIZE;
            // } else {
            //     return ret;
            // }

        } break;
#endif
    
        default:
            MADWOLF_DEBUG("Invalid Composite Type (%d)", compType);
            return ALGO_ID_E;
    }

    return ret;
}

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_MAKE_KEY
int wc_mldsa_composite_make_key(mldsa_composite_key* key, enum mldsa_composite_level composite_level, WC_RNG* rng)
{
    int ret = 0;
    int mldsa_level = WC_ML_DSA_44;
    int type = 0;

    if (!key || !rng) {
        return BAD_FUNC_ARG;
    }

    // Init the Rng
    if (wc_InitRng_ex(rng, key->heap, key->devId) < 0) {
        return BAD_STATE_E;
    }

    // Use default type if not set
    if (composite_level <= 0) {
        composite_level = WC_MLDSA44_NISTP256_SHA256;
    }

    // Retrieves the key/cert type
    type = wc_mldsa_composite_level_type(composite_level);
    if (type < 0) {
        return type;
    }

    switch (composite_level) {

        case WC_MLDSA_COMPOSITE_UNDEF:
            return BAD_FUNC_ARG;
            break;

        // Level 1
        case D2_WC_MLDSA44_RSAPSS2048_SHA256:
        case D2_WC_MLDSA44_RSA2048_SHA256:
        case D2_WC_MLDSA44_NISTP256_SHA256:
        case D2_WC_MLDSA44_ED25519_SHA256:
        case WC_MLDSA44_RSAPSS2048_SHA256:
        case WC_MLDSA44_RSA2048_SHA256:
        case WC_MLDSA44_ED25519_SHA256:
        case WC_MLDSA44_NISTP256_SHA256:
            mldsa_level = WC_ML_DSA_44;
            break;
        
        // Level 3
        case D2_WC_MLDSA65_RSAPSS3072_SHA512:
        case D2_WC_MLDSA65_RSA3072_SHA512:
        case D2_WC_MLDSA65_NISTP256_SHA512:
        case D2_WC_MLDSA65_BPOOL256_SHA512:
        case D2_WC_MLDSA65_ED25519_SHA512:
        case WC_MLDSA65_RSAPSS3072_SHA384:
        case WC_MLDSA65_RSA3072_SHA384:
        case WC_MLDSA65_RSAPSS4096_SHA384:
        case WC_MLDSA65_RSA4096_SHA384:
        case WC_MLDSA65_NISTP256_SHA384:
        case WC_MLDSA65_BPOOL256_SHA384:
        case WC_MLDSA65_ED25519_SHA384:
            mldsa_level = WC_ML_DSA_65;
            break;

        // Level 5
        case D2_WC_MLDSA87_NISTP384_SHA512:
        case D2_WC_MLDSA87_BPOOL384_SHA512:
        case D2_WC_MLDSA87_ED448_SHA512:
        case WC_MLDSA87_NISTP384_SHA384:
        case WC_MLDSA87_BPOOL384_SHA384:
        case WC_MLDSA87_ED448_SHA384:
            mldsa_level = WC_ML_DSA_87;
            break;

        default:
            return BAD_STATE_E;
    }

    // Allocates and Zeroes the memory
    key->mldsa_key = (dilithium_key*)XMALLOC(sizeof(dilithium_key), key->heap, DYNAMIC_TYPE_DILITHIUM);
    if (!key->mldsa_key) {
        return MEMORY_E;
    }
    XMEMSET(key->mldsa_key, 0, sizeof(dilithium_key));

    // Initialize and Generate the ML-DSA key
    if ((wc_dilithium_init_ex(key->mldsa_key, key->heap, key->devId) < 0) ||
        (wc_dilithium_set_level(key->mldsa_key, mldsa_level) < 0)) {
        ret = BAD_STATE_E;
        goto err;
    }

    if (wc_dilithium_make_key(key->mldsa_key, rng) < 0) {
        ret = CRYPTGEN_E;
        goto err;
    }

    // Initialize and Generate the Traditional DSA key
    switch (composite_level) {

        case WC_MLDSA_COMPOSITE_UNDEF: {
            ret = BAD_FUNC_ARG;
            goto err;
        } break;

        // Ed25519 Component
        case D2_WC_MLDSA65_ED25519_SHA512:
        case D2_WC_MLDSA44_ED25519_SHA256:
        case WC_MLDSA65_ED25519_SHA384:
        case WC_MLDSA44_ED25519_SHA256: {

            if ((key->prvKeySet || key->pubKeySet) && key->alt_key.ed25519) {
                wc_ed25519_free(key->alt_key.ed25519);
                key->alt_key.ed25519 = NULL;
            }

            key->alt_key.ed25519 = (ed25519_key*)XMALLOC(sizeof(ed25519_key), key->heap, DYNAMIC_TYPE_PRIVATE_KEY);
            if (!key->alt_key.ed25519) {
                ret = MEMORY_E;
                goto err;
            }
            if (wc_ed25519_init_ex(key->alt_key.ed25519, key->heap, key->devId) < 0) {
                ret = BAD_STATE_E;
                goto err;
            }
            if (wc_ed25519_make_key(rng, ED25519_KEY_SIZE, key->alt_key.ed25519) < 0) {
                ret = CRYPTGEN_E;
                goto err;
            }
        } break;

        // NISTP256 Component
        case D2_WC_MLDSA44_NISTP256_SHA256:
        case D2_WC_MLDSA65_NISTP256_SHA512:
        case D2_WC_MLDSA65_BPOOL256_SHA512:
        case D2_WC_MLDSA87_NISTP384_SHA512:
        case D2_WC_MLDSA87_BPOOL384_SHA512:
        case WC_MLDSA44_NISTP256_SHA256:
        case WC_MLDSA65_BPOOL256_SHA384:
        case WC_MLDSA65_NISTP256_SHA384:
        case WC_MLDSA87_BPOOL384_SHA384:
        case WC_MLDSA87_NISTP384_SHA384: {
            int curveSz = 32;
            int curveId = ECC_SECP256R1;

            // Gets the curve size and id
            if (composite_level == D2_WC_MLDSA44_NISTP256_SHA256
                || composite_level == D2_WC_MLDSA65_NISTP256_SHA512
                // || type == D2_WC_MLDSA44_BPOOL256_SHA256
                || composite_level == D2_WC_MLDSA65_NISTP256_SHA512) {
                curveId = ECC_SECP256R1;
            } else if (composite_level == WC_MLDSA65_BPOOL256_SHA384
                       || composite_level == D2_WC_MLDSA65_BPOOL256_SHA512) {
                curveId = ECC_BRAINPOOLP256R1;
            }  else if (composite_level == WC_MLDSA87_NISTP384_SHA384 ||
                        composite_level == D2_WC_MLDSA87_NISTP384_SHA512) {
                curveId = ECC_SECP384R1;
            } else if (composite_level == WC_MLDSA87_BPOOL384_SHA384 ||
                       composite_level == D2_WC_MLDSA87_BPOOL384_SHA512) {
                curveId = ECC_BRAINPOOLP384R1;
            }

            // Gets the curve size
            if ((curveSz = wc_ecc_get_curve_size_from_id(curveId)) <= 0) {
                ret = BAD_STATE_E;
                goto err;
            }

            // Frees the memory if a key is already set
            if ((key->prvKeySet || key->pubKeySet) && key->alt_key.ecc) {
                wc_ecc_key_free(key->alt_key.ecc);
                key->alt_key.ecc = NULL;
            }

            // Allocates the ECC key
            key->alt_key.ecc = (ecc_key*)XMALLOC(sizeof(ecc_key), key->heap, DYNAMIC_TYPE_PRIVATE_KEY);
            if (!key->alt_key.ecc) {
                ret = MEMORY_E;
                goto err;
            }
            // Initializes the ECC key
            if (wc_ecc_init_ex(key->alt_key.ecc, key->heap, key->devId) < 0) {
                ret = BAD_STATE_E;
                goto err;
            }
            if (wc_ecc_make_key_ex(rng, curveSz, key->alt_key.ecc, curveId) < 0) {
                ret = CRYPTGEN_E;
                goto err;
            }
        } break;

        // RSA Component
        case D2_WC_MLDSA44_RSAPSS2048_SHA256:
        case D2_WC_MLDSA44_RSA2048_SHA256:
        case D2_WC_MLDSA65_RSAPSS3072_SHA512:
        case D2_WC_MLDSA65_RSA3072_SHA512:
        case WC_MLDSA44_RSAPSS2048_SHA256:
        case WC_MLDSA44_RSA2048_SHA256:
        case WC_MLDSA65_RSAPSS4096_SHA384:
        case WC_MLDSA65_RSA4096_SHA384:
        case WC_MLDSA65_RSAPSS3072_SHA384:
        case WC_MLDSA65_RSA3072_SHA384: {
            
            if ((key->prvKeySet || key->pubKeySet) && key->alt_key.rsa) {
                wc_FreeRsaKey(key->alt_key.rsa);
                key->alt_key.rsa = NULL;
            }
            
            key->alt_key.rsa = (RsaKey*)XMALLOC(sizeof(RsaKey), key->heap, DYNAMIC_TYPE_PRIVATE_KEY);
            if (!key->alt_key.rsa) {
                return MEMORY_E;
            }
            // Initializes the RSA key
            if (wc_InitRsaKey_ex(key->alt_key.rsa, key->heap, key->devId) < 0) {
                return BAD_STATE_E;
            }
            // Generates the RSA key
            if (composite_level == WC_MLDSA44_RSA2048_SHA256 || composite_level == WC_MLDSA44_RSAPSS2048_SHA256) {
                ret = wc_MakeRsaKey(key->alt_key.rsa, 2048, WC_RSA_EXPONENT, rng);
            } else if (composite_level == WC_MLDSA65_RSAPSS3072_SHA384 || composite_level == WC_MLDSA65_RSA3072_SHA384) {
                ret = wc_MakeRsaKey(key->alt_key.rsa, 3072, WC_RSA_EXPONENT, rng);
            } else if (composite_level == WC_MLDSA65_RSAPSS4096_SHA384 || composite_level == WC_MLDSA65_RSA4096_SHA384) {
                ret = wc_MakeRsaKey(key->alt_key.rsa, 4096, WC_RSA_EXPONENT, rng);
            } else {
                ret = ALGO_ID_E;
            }

            // Checks for errors
            if (ret != 0) goto err;
        } break;

        // ED448 Component
        case D2_WC_MLDSA87_ED448_SHA512:
        case WC_MLDSA87_ED448_SHA384: {
            
            if ((key->prvKeySet || key->pubKeySet) && key->alt_key.ed448) {
                wc_ed448_free(key->alt_key.ed448);
                key->alt_key.ed448 = NULL;
            }

            key->alt_key.ed448 = (ed448_key*)XMALLOC(sizeof(ed448_key), key->heap, DYNAMIC_TYPE_PRIVATE_KEY);
            if (!key->alt_key.ed448) {
                ret = MEMORY_E;
                goto err;
            }
            if (wc_ed448_init_ex(key->alt_key.ed448, key->heap, key->devId) < 0) {
                ret = BAD_STATE_E;
                goto err;
            }
            if (wc_ed448_make_key(rng, ED448_KEY_SIZE, key->alt_key.ed448) < 0) {
                ret = CRYPTGEN_E;
                goto err;
            }
        } break;

        default:
            ret = ALGO_ID_E;
            goto err;
    }

    // Sets the key parts
    key->prvKeySet = 1;
    key->pubKeySet = 1;

    // Sets the key type
    key->type = wc_mldsa_composite_level_type(composite_level);

    return ret;

err:

    // ML-DSA
    if (key->mldsa_key) {
        XFREE(key->mldsa_key, key->heap, DYNAMIC_TYPE_DILITHIUM);
        key->mldsa_key = NULL;
    }
    // RSA
    else if ((composite_level == WC_MLDSA44_RSAPSS2048_SHA256
         || composite_level == WC_MLDSA44_RSA2048_SHA256
         || composite_level == WC_MLDSA65_RSAPSS3072_SHA384
         || composite_level == WC_MLDSA65_RSA3072_SHA384
         || composite_level == WC_MLDSA65_RSAPSS4096_SHA384
         || composite_level == WC_MLDSA65_RSA4096_SHA384) && key->alt_key.rsa) {
        wc_FreeRsaKey(key->alt_key.rsa);
        key->alt_key.rsa = NULL;
    }
    // Ed 25519
    else if ((composite_level == WC_MLDSA44_ED25519_SHA256
         || composite_level == WC_MLDSA65_ED25519_SHA384
         || composite_level == D2_WC_MLDSA44_ED25519_SHA256
         || composite_level == D2_WC_MLDSA65_ED25519_SHA512) && key->alt_key.ed25519) {
        wc_ed25519_free(key->alt_key.ed25519);
        key->alt_key.ed25519 = NULL;
    }
    // NIST P256, NIST P384, Brainpool P256, Brainpool P384
    else if ((composite_level == WC_MLDSA44_NISTP256_SHA256
        //  || composite_level == WC_MLDSA44_BPOOL256_SHA256
         || composite_level == WC_MLDSA65_NISTP256_SHA384
         || composite_level == WC_MLDSA65_BPOOL256_SHA384
         || composite_level == WC_MLDSA87_NISTP384_SHA384
         || composite_level == WC_MLDSA87_BPOOL384_SHA384
         // -------------- Draft 2 ---------------- //
         || composite_level == D2_WC_MLDSA44_NISTP256_SHA256
         || composite_level == D2_WC_MLDSA65_BPOOL256_SHA512
         || composite_level == D2_WC_MLDSA65_NISTP256_SHA512
         || composite_level == D2_WC_MLDSA87_BPOOL384_SHA512
         || composite_level == D2_WC_MLDSA87_NISTP384_SHA512) && key->alt_key.ecc) {
        wc_ecc_key_free(key->alt_key.ecc);
        key->alt_key.ecc = NULL;
    }
    else if ((composite_level == WC_MLDSA87_ED448_SHA384
         || composite_level == D2_WC_MLDSA87_ED448_SHA512) && key->alt_key.ed448) {
        wc_ed448_free(key->alt_key.ed448);
        key->alt_key.ed448 = NULL;
    }
    else {
        MADWOLF_DEBUG("Invalid key type in composite key (compType: %d)", composite_level);
        ret = BAD_STATE_E;
    }

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

    int composite_level = 0;
        // Composite Level
   
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
        return ret;
    }

    // Gets the CompositeTBS Message
    if ((ret = wc_mldsa_compositeTBS_msg(tbsMsg, &tbsMsgLen, msg, msgLen, key, context, contextLen)) < 0) {
        return ret;
    }

    // Gets the Composite Level
    composite_level = wc_mldsa_composite_level(key);
    if (composite_level <= 0) {
        return BAD_STATE_E;
    }

    // Verify Individual DSA Components: 
    switch (composite_level) {

        case WC_MLDSA_COMPOSITE_UNDEF: {
            return BAD_STATE_E;
        } break;

        // Level 1
        case D2_WC_MLDSA44_RSAPSS2048_SHA256:
        case D2_WC_MLDSA44_RSA2048_SHA256:
        case WC_MLDSA44_RSAPSS2048_SHA256:
        case WC_MLDSA44_RSA2048_SHA256: {
            
            word32 sigSz = RSA2048_SIG_SIZE;
            byte sigBuffer[RSA2048_SIG_SIZE];

            // Checks the ML-DSA key level
            if (key->mldsa_key->level != WC_ML_DSA_44) {
                return BAD_STATE_E;
            }
            // Cehcks the RSA signature size
            if (other_BufferLen != RSA2048_SIG_SIZE) {
                return BUFFER_E;
            }
            // Sets the type of padding
            if (composite_level == WC_MLDSA44_RSAPSS2048_SHA256
                || composite_level == D2_WC_MLDSA44_RSAPSS2048_SHA256) {
                // Sets the RSA PSS Padding
                key->alt_key.rsa->type = WC_RSA_PSS_PAD;
                // Verify RSA Component
                if ((ret = wc_RsaPSS_Verify_ex(other_Buffer, other_BufferLen,
                                               sigBuffer, sigSz, 
                                               WC_HASH_TYPE_SHA256, WC_MGF1SHA256,
                                               RSA_PSS_SALT_LEN_DEFAULT, key->alt_key.rsa)) < 0) {
                    return ret;
                }
            } else {
                key->alt_key.rsa->type = WC_RSA_PKCSV15_PAD;
                // Verify RSA Component
                if ((ret = wc_RsaSSL_Verify_ex2(other_Buffer, other_BufferLen,
                                                sigBuffer, sigSz, key->alt_key.rsa,
                                                WC_RSA_PKCSV15_PAD, WC_HASH_TYPE_SHA256)) < 0) {
                    return ret;
                }
            }
        } break;

        case D2_WC_MLDSA44_ED25519_SHA256:
        case WC_MLDSA44_ED25519_SHA256: {
            // Checks the ML-DSA key level
            if (key->mldsa_key->level != WC_ML_DSA_44) {
                return BAD_STATE_E;
            }
            // Cehcks the ED25519 signature size
            if (other_BufferLen != ED25519_SIG_SIZE) {
                return BUFFER_E;
            }
            // Verify ED25519 Component
            if ((ret = wc_ed25519_verify_msg_ex(other_Buffer, other_BufferLen, 
                                                tbsMsg, tbsMsgLen, res, 
                                                key->alt_key.ed25519, (byte)Ed25519,
                                                context, contextLen)) < 0) {
                return ret;
            }
        } break;

        case D2_WC_MLDSA44_NISTP256_SHA256:
        case WC_MLDSA44_NISTP256_SHA256: {
            // Checks the ML-DSA key level
            if (key->mldsa_key->level != WC_ML_DSA_44) {
                return BAD_STATE_E;
            }
            if (key->alt_key.ecc->dp->id != ECC_SECP256R1) {
                return BAD_STATE_E;
            }
            // Cehcks the ECDSA signature size
            if ((int)other_BufferLen > wc_ecc_sig_size(key->alt_key.ecc)) {
                return BUFFER_E;
            }
            // Verify ECDSA Component
            if ((ret = wc_ecc_verify_hash(other_Buffer, other_BufferLen,
                                          tbsMsg, tbsMsgLen, 
                                          res, key->alt_key.ecc)) < 0) {
                return ret;
            }
        } break;

        // Level 3
        case D2_WC_MLDSA65_RSAPSS3072_SHA512:
        case D2_WC_MLDSA65_RSA3072_SHA512:
        case WC_MLDSA65_RSAPSS4096_SHA384:
        case WC_MLDSA65_RSA4096_SHA384:
        case WC_MLDSA65_RSAPSS3072_SHA384:
        case WC_MLDSA65_RSA3072_SHA384: {
            word32 sigSz = RSA4096_SIG_SIZE;
            byte sigBuffer[RSA4096_SIG_SIZE];

            // Checks the ML-DSA key level
            if (key->mldsa_key->level != WC_ML_DSA_65) {
                return BAD_STATE_E;
            }

            // Cehcks the RSA signature size
            if (composite_level == WC_MLDSA65_RSAPSS3072_SHA384 
                || composite_level == WC_MLDSA65_RSA3072_SHA384) {
                // Checks the RSA signature size
                if (other_BufferLen != RSA3072_SIG_SIZE) {
                    return ASN_PARSE_E;
                }
            } else if (composite_level == WC_MLDSA65_RSAPSS3072_SHA384
                       || composite_level == WC_MLDSA65_RSA3072_SHA384) {
                // Checks the RSA signature size
                if (other_BufferLen != RSA4096_SIG_SIZE) {
                    return ASN_PARSE_E;
                }
            }

            // Sets the PSS parameters
            if (composite_level == WC_MLDSA65_RSAPSS3072_SHA384
                || composite_level == WC_MLDSA65_RSAPSS4096_SHA384
                || composite_level == D2_WC_MLDSA65_RSAPSS3072_SHA512) {
                
                int mgf = 0;
                int saltLen = 0;
                    // MGF and Salt Length

                if (composite_level == D2_WC_MLDSA65_RSAPSS3072_SHA512) {
                    mgf = WC_MGF1SHA512;
                    saltLen = 64;
                } else if (composite_level == WC_MLDSA65_RSAPSS4096_SHA384
                    || composite_level == WC_MLDSA65_RSAPSS3072_SHA384) {
                    mgf = WC_MGF1SHA384;
                    saltLen = 48;
                } else {
                    mgf = WC_MGF1SHA256;
                    saltLen = 32;
                }

                // Sets the Padding and Verify
                key->alt_key.rsa->type = WC_RSA_PSS_PAD;
                if ((ret = wc_RsaPSS_Verify_ex(other_Buffer, other_BufferLen,
                                               sigBuffer, sigSz, 
                                               WC_HASH_TYPE_SHA384, mgf,
                                               saltLen, key->alt_key.rsa)) < 0) {
                    return SIG_VERIFY_E;
                }
            } else {
                // Sets the Padding and Verify
                key->alt_key.rsa->type = WC_RSA_PKCSV15_PAD;
                if ((ret = wc_RsaSSL_Verify_ex2(other_Buffer, other_BufferLen,
                                                sigBuffer, sigSz, key->alt_key.rsa,
                                                WC_RSA_PKCSV15_PAD, WC_HASH_TYPE_SHA512)) < 0) {
                    return SIG_VERIFY_E;
                }
            }
        } break;

        case D2_WC_MLDSA65_NISTP256_SHA512:
        case WC_MLDSA65_NISTP256_SHA384: {
            // Checks the ML-DSA key level
            if (key->mldsa_key->level != WC_ML_DSA_65) {
                return BAD_STATE_E;
            }
            // Checks the ECDSA curve (P-256)
            if (key->alt_key.ecc->dp->id != ECC_SECP256R1) {
                return BAD_STATE_E;
            }
            // Cehcks the ECDSA signature size
            if ((int)other_BufferLen > wc_ecc_sig_size(key->alt_key.ecc)) {
                return ASN_PARSE_E;
            }
            // Verify ECDSA Component
            if ((ret = wc_ecc_verify_hash(other_Buffer, other_BufferLen,
                                            tbsMsg, tbsMsgLen, res, key->alt_key.ecc)) < 0) {
                return SIG_VERIFY_E;
            }
        } break;

        case D2_WC_MLDSA65_BPOOL256_SHA512:
        case WC_MLDSA65_BPOOL256_SHA384: {
            // Checks the ML-DSA key level
            if (key->mldsa_key->level != WC_ML_DSA_65) {
                return BAD_STATE_E;
            }
            // Checks the ECDSA curve (P-256)
            if (key->alt_key.ecc->dp->id != ECC_BRAINPOOLP256R1) {
                return BAD_STATE_E;
            }
            // Cehcks the ECDSA signature size
            if ((int)other_BufferLen > wc_ecc_sig_size(key->alt_key.ecc)) {
                return ASN_PARSE_E;
            }
            // Verify ECDSA Component
            if ((ret = wc_ecc_verify_hash(other_Buffer, other_BufferLen,
                                            tbsMsg, tbsMsgLen, res, key->alt_key.ecc)) < 0) {
                return SIG_VERIFY_E;
            }
        } break;

        case D2_WC_MLDSA65_ED25519_SHA512:
        case WC_MLDSA65_ED25519_SHA384: {
            // Checks the ML-DSA key level
            if (key->mldsa_key->level != WC_ML_DSA_65) {
                return BAD_STATE_E;
            }
            // Cehcks the ED25519 signature size
            if (other_BufferLen != ED25519_SIG_SIZE) {
                return BAD_STATE_E;
            }
            // Verify ED25519 Component
            if ((ret = wc_ed25519_verify_msg_ex(other_Buffer, other_BufferLen, 
                                                tbsMsg, tbsMsgLen, res, key->alt_key.ed25519,
                                                (byte)Ed25519, context, contextLen)) < 0) {
                return SIG_VERIFY_E;
            }
        } break;

        // Level 5
        case D2_WC_MLDSA87_NISTP384_SHA512:
        case WC_MLDSA87_NISTP384_SHA384: {
            // Checks the ML-DSA key level
            if (key->mldsa_key->level != WC_ML_DSA_87) {
                return BAD_STATE_E;
            }
            // Checks the ECDSA curve (P-384)
            if (key->alt_key.ecc->dp->id != ECC_SECP384R1) {
                return BAD_STATE_E;
            }
            // Cehcks the ECDSA signature size
            if ((int)other_BufferLen > wc_ecc_sig_size(key->alt_key.ecc)) {
                return ASN_PARSE_E;
            }
            // Verify ECDSA Component
            if ((ret = wc_ecc_verify_hash(other_Buffer, other_BufferLen,
                                          tbsMsg, tbsMsgLen, res,
                                          key->alt_key.ecc)) < 0) {
                return SIG_VERIFY_E;
            }
        } break;

        case D2_WC_MLDSA87_BPOOL384_SHA512:
        case WC_MLDSA87_BPOOL384_SHA384: {
            // Checks the ML-DSA key level
            if (key->mldsa_key->level != WC_ML_DSA_87) {
                return BAD_STATE_E;
            }
            // Checks the ECDSA curve (P-384)
            if (key->alt_key.ecc->dp->id != ECC_BRAINPOOLP384R1) {
                return BAD_STATE_E;
            }
            // Cehcks the ECDSA signature size
            if ((int)other_BufferLen > wc_ecc_sig_size(key->alt_key.ecc)) {
                return ASN_PARSE_E;
            }
            // Verify ECDSA Component
            if ((ret = wc_ecc_verify_hash(other_Buffer, other_BufferLen,
                                          tbsMsg, tbsMsgLen, res,
                                          key->alt_key.ecc)) < 0) {
                return SIG_VERIFY_E;
            }
        } break;

        case D2_WC_MLDSA87_ED448_SHA512:
        case WC_MLDSA87_ED448_SHA384: {
            // Checks the ML-DSA key level
            if (key->mldsa_key->level != WC_ML_DSA_87) {
                return BAD_STATE_E;
            }
            // Cehcks the ED448 signature size
            if (other_BufferLen != ED448_SIG_SIZE) {
                return ASN_PARSE_E;
            }
            // Verify ED448 Component
            if ((ret = wc_ed448_verify_msg_ex(other_Buffer, other_BufferLen, 
                                              tbsMsg, tbsMsgLen, res, key->alt_key.ed448,
                                              (byte)Ed448, context, contextLen)) < 0) {
                return SIG_VERIFY_E;
            }
        } break;

        default:
            return ALGO_ID_E;
    }

    // Checks the size of the ML-DSA signature
    if (key->mldsa_key->level == WC_ML_DSA_44 && mldsa_BufferLen != DILITHIUM_ML_DSA_44_SIG_SIZE) {
        return ASN_PARSE_E;
    } else if (key->mldsa_key->level == WC_ML_DSA_65 && mldsa_BufferLen != DILITHIUM_ML_DSA_65_SIG_SIZE) {
        return ASN_PARSE_E;
    } else if (key->mldsa_key->level == WC_ML_DSA_87 && mldsa_BufferLen != DILITHIUM_ML_DSA_87_SIG_SIZE) {
        return ASN_PARSE_E;
    }

    MADWOLF_DEBUG("ML-DSA Signature Size: %d - calling wc_dilithium_verify_ctx_msg()", mldsa_BufferLen);

    // Verify the ML-DSA Component
    if ((ret = wc_dilithium_verify_ctx_msg(mldsa_Buffer, 
                                           mldsa_BufferLen,
                                           context,
                                           contextLen,
                                           tbsMsg,
                                           tbsMsgLen,
                                           res,
                                           key->mldsa_key)) < 0) {
        MADWOLF_DEBUG("wc_dilithium_verify_ctx_msg() failed with error %d", ret);
        return SIG_VERIFY_E;
    }

    // If all components are verified, then the signature is valid
    *res = 1;

    MADWOLF_DEBUG("ML-DSA Signature Verified: %d", *res);

    // Return the result
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
        // Ret value

    int composite_level = 0;
        // Composite Level

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
        MADWOLF_DEBUG0("Invalid input parameters");
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
        MADWOLF_DEBUG("wc_mldsa_compositeTBS_msg() failed with error %d", ret);
        return ret;
    }

    /* Sign the message with the ML-DSA key. */
    if ((ret = wc_dilithium_sign_ctx_msg(NULL,
                                         0,
                                         tbsMsg,
                                         tbsMsgLen,
                                         mldsaSig_buffer, 
                                         &mldsaSig_bufferLen,
                                         key->mldsa_key,
                                         rng)) < 0) {
        MADWOLF_DEBUG("wc_dilithium_sign_ctx_msg() failed with error %d", ret);
        return ret;
    }

    /* Gets the Composite Level */
    composite_level = wc_mldsa_composite_level(key);

    // Sign The Traditional component
    switch (composite_level) {

        case WC_MLDSA_COMPOSITE_UNDEF: {
            return BAD_STATE_E;
        } break;

        case D2_WC_MLDSA44_RSAPSS2048_SHA256:
        case D2_WC_MLDSA44_RSA2048_SHA256:
        case WC_MLDSA44_RSAPSS2048_SHA256:
        case WC_MLDSA44_RSA2048_SHA256: {
            // Sign RSA Component
            word32 sigSz = RSA2048_SIG_SIZE;
            byte sigBuffer[RSA2048_SIG_SIZE];

            // Hash buffer
            byte hash[WC_SHA256_DIGEST_SIZE];

            // Checks the ML-DSA key level
            if (key->mldsa_key->level != WC_ML_DSA_44) {
                return BAD_STATE_E;
            }
            // Sets the type of padding
            if (composite_level == WC_MLDSA44_RSAPSS2048_SHA256 ||
                composite_level == D2_WC_MLDSA44_RSAPSS2048_SHA256) {
                key->alt_key.rsa->type = WC_RSA_PSS_PAD;
            } else {
                key->alt_key.rsa->type = WC_RSA_PKCSV15_PAD;
            }

            // Gets the RSA signature size
            sigSz = (word32)wc_RsaEncryptSize(key->alt_key.rsa);

            // Hash the message using SHA-256
            if (wc_Sha256Hash(tbsMsg, tbsMsgLen, hash) != 0) {
                return BAD_STATE_E;
            }

            // Sign the message digest (PSS vs PKCS#1 v1.5)
            if (composite_level == WC_MLDSA44_RSAPSS2048_SHA256) {
                // Sign the message digest
                if ((ret = wc_RsaPSS_Sign(hash, WC_SHA256_DIGEST_SIZE, 
                                          sigBuffer, sigSz, WC_HASH_TYPE_SHA256, 
                                          WC_MGF1SHA256, key->alt_key.rsa, rng)) < 0) {
                    // handle error
                    return ret;
                }
            } else {
                // Sign the message digest
                if ((ret = wc_RsaSSL_Sign(hash, WC_SHA256_DIGEST_SIZE, 
                                          sigBuffer, sigSz, key->alt_key.rsa, rng)) < 0) {
                    return ret;
                }
            }

            // Check the size of the signature
            if ((int)sigSz != ret) {
                return BAD_STATE_E;
            }

            // Copy the signature to the output buffer
            XMEMCPY(otherSig_buffer, sigBuffer, sigSz);
            otherSig_bufferLen = sigSz;

        } break;

        case D2_WC_MLDSA44_ED25519_SHA256:
        case WC_MLDSA44_ED25519_SHA256: {
            // Sign ED25519 Component
            if ((ret = wc_ed25519_sign_msg_ex(tbsMsg, tbsMsgLen, otherSig_buffer, 
                                              &otherSig_bufferLen, key->alt_key.ed25519,
                                              (byte)Ed25519, context, contextLen)) < 0) {
                MADWOLF_DEBUG("wc_ed25519_sign_msg_ex() failed with error %d", ret);
                return ret;
            }
            if (otherSig_bufferLen != ED25519_SIG_SIZE) {
                return BAD_STATE_E;
            }
        } break;

        case D2_WC_MLDSA44_NISTP256_SHA256:
        case WC_MLDSA44_NISTP256_SHA256: {
            // Sign ECC Component
            byte msg_digest[WC_SHA256_DIGEST_SIZE];

            if (wc_Sha256Hash(tbsMsg, tbsMsgLen, msg_digest) < 0) {
                return BAD_STATE_E;
            }

            if ((ret = wc_ecc_sign_hash(msg_digest, sizeof(msg_digest), 
                                        otherSig_buffer, &otherSig_bufferLen, 
                                        rng, key->alt_key.ecc)) < 0) {
                MADWOLF_DEBUG("wc_ecc_sign_hash() failed with error %d", ret);
                return ret;
            }
        } break;

        // Level 3
        case D2_WC_MLDSA65_RSAPSS3072_SHA512:
        case D2_WC_MLDSA65_RSA3072_SHA512:
        case WC_MLDSA65_RSAPSS3072_SHA384:
        case WC_MLDSA65_RSA3072_SHA384:
        case WC_MLDSA65_RSAPSS4096_SHA384:
        case WC_MLDSA65_RSA4096_SHA384: {
            // Sign RSA Component
            word32 sigSz = RSA4096_SIG_SIZE;
            byte sigBuffer[RSA4096_SIG_SIZE];

            // Hash buffer
            byte hash[WC_SHA512_DIGEST_SIZE];

            // Checks the ML-DSA key level
            if (key->mldsa_key->level != WC_ML_DSA_65) {
                return BAD_STATE_E;
            }

            // Gets the RSA signature size
            sigSz = (word32)wc_RsaEncryptSize(key->alt_key.rsa);

            // Sets the type of padding
            if (composite_level == WC_MLDSA65_RSAPSS3072_SHA384 || 
                        composite_level == WC_MLDSA65_RSAPSS4096_SHA384 ||
                        composite_level == D2_WC_MLDSA65_RSAPSS3072_SHA512) {
                key->alt_key.rsa->type = WC_RSA_PSS_PAD;
            } else {
                key->alt_key.rsa->type = WC_RSA_PKCSV15_PAD;
            }

            if (composite_level == D2_WC_MLDSA65_RSAPSS3072_SHA512 ||
                composite_level == WC_MLDSA65_RSAPSS3072_SHA384) {
                // Hash the message using SHA-512
                if (wc_Sha512Hash(tbsMsg, tbsMsgLen, hash) < 0) {
                    // handle error
                    return BAD_STATE_E;
                }
            } else {
                // Hash the message using SHA-384
                if (wc_Sha384Hash(tbsMsg, tbsMsgLen, hash) < 0) {
                    // handle error
                    return BAD_STATE_E;
                }
            }

            if (composite_level == WC_MLDSA65_RSAPSS3072_SHA384 || 
                    composite_level == WC_MLDSA65_RSAPSS4096_SHA384 ||
                    composite_level == D2_WC_MLDSA65_RSAPSS3072_SHA512) {

                int mgf = 0;
                int saltLen = 0;

                if (composite_level == WC_MLDSA65_RSAPSS4096_SHA384 ||
                        composite_level == WC_MLDSA65_RSAPSS3072_SHA384) {
                    mgf = WC_MGF1SHA384;
                    saltLen = 48;
                } else if (composite_level == WC_MLDSA65_RSAPSS3072_SHA384) {
                    mgf = WC_MGF1SHA512;
                    saltLen = 64;
                } else {
                    mgf = WC_MGF1SHA256;
                    saltLen = 32;
                }
                
                // Sets the Padding
                key->alt_key.rsa->type = WC_RSA_PSS_PAD;

                // Sign the message digest
                if ((ret = wc_RsaPSS_Sign_ex(hash, WC_SHA384_DIGEST_SIZE, 
                                             sigBuffer, sigSz, WC_HASH_TYPE_SHA384,
                                             mgf, saltLen, key->alt_key.rsa, rng)) < 0) {
                    // handle error
                    return BAD_STATE_E;
                }
                // Checks the RSA signature size
                if (composite_level == WC_MLDSA65_RSAPSS3072_SHA384 && 
                                sigSz != RSA3072_SIG_SIZE) {
                    return BAD_STATE_E;
                } else if (composite_level == WC_MLDSA65_RSAPSS4096_SHA384 && 
                                sigSz != RSA4096_SIG_SIZE) {
                    return BAD_STATE_E;
                } else if (composite_level == D2_WC_MLDSA65_RSAPSS3072_SHA512 && 
                                sigSz != RSA3072_SIG_SIZE) {
                    return BAD_STATE_E;
                }

            } else {
                // Sets the Padding
                key->alt_key.rsa->type = WC_RSA_PKCSV15_PAD;

                // Sign the message digest
                if ((ret = wc_RsaSSL_Sign(hash, WC_SHA384_DIGEST_SIZE,
                                          sigBuffer, sigSz, key->alt_key.rsa, rng)) < 0) {
                    // handle error
                    return BAD_STATE_E;
                }

                // Checks the RSA signature size
                if (composite_level == WC_MLDSA65_RSA3072_SHA384 && sigSz != RSA3072_SIG_SIZE) {
                    return BAD_STATE_E;
                } else if (composite_level == WC_MLDSA65_RSA4096_SHA384 && sigSz != RSA4096_SIG_SIZE) {
                    return BAD_STATE_E;
                } else if (composite_level == D2_WC_MLDSA65_RSA3072_SHA512 && sigSz != RSA3072_SIG_SIZE) {
                    return BAD_STATE_E;
                }
            }

            // Check the size of the signature
            if ((int)sigSz != ret) {
                return ASN_PARSE_E;
            }

            // Copy the signature to the output buffer
            XMEMCPY(otherSig_buffer, sigBuffer, sigSz);
            otherSig_bufferLen = sigSz;

        } break;
        
        case D2_WC_MLDSA65_NISTP256_SHA512:
        case WC_MLDSA65_NISTP256_SHA384: {
            // Sign ECC Component
            byte msg_digest[WC_SHA512_DIGEST_SIZE];

            if (composite_level == D2_WC_MLDSA65_NISTP256_SHA512) {
                if (wc_Sha512Hash(tbsMsg, tbsMsgLen, msg_digest) < 0) {
                    return BAD_STATE_E;
                }
            } else {
                if (wc_Sha384Hash(tbsMsg, tbsMsgLen, msg_digest) < 0) {
                    return BAD_STATE_E;
                }
            }

            if ((ret = wc_ecc_sign_hash(msg_digest, sizeof(msg_digest), 
                                        otherSig_buffer, &otherSig_bufferLen, 
                                        rng, key->alt_key.ecc)) < 0) {
                return ret;
            }
        } break;

        case D2_WC_MLDSA65_ED25519_SHA512:
        case WC_MLDSA65_ED25519_SHA384: {
            // Sign ED25519 Component
            if ((ret = wc_ed25519_sign_msg_ex(tbsMsg, tbsMsgLen, 
                                              otherSig_buffer, &otherSig_bufferLen,
                                              key->alt_key.ed25519, (byte)Ed25519,
                                              context, contextLen)) < 0) {
                return ret;
            }
            if (otherSig_bufferLen != ED25519_SIG_SIZE) {
                return BAD_STATE_E;
            }
        } break;

        case D2_WC_MLDSA65_BPOOL256_SHA512:
        case WC_MLDSA65_BPOOL256_SHA384: {
            // Sign ECC Component
            byte msg_digest[WC_SHA512_DIGEST_SIZE];

            if (composite_level == D2_WC_MLDSA65_BPOOL256_SHA512) {
                if (wc_Sha512Hash(tbsMsg, tbsMsgLen, msg_digest) < 0) {
                    return BAD_STATE_E;
                }
            } else {
                if (wc_Sha256Hash(tbsMsg, tbsMsgLen, msg_digest) < 0) {
                    return BAD_STATE_E;
                }
            }

            // Sign the message digest
            if ((ret = wc_ecc_sign_hash(msg_digest, sizeof(msg_digest),
                                        otherSig_buffer, &otherSig_bufferLen, 
                                        rng, key->alt_key.ecc)) < 0) {
                return ret;
            }
        } break;

        case D2_WC_MLDSA87_NISTP384_SHA512:
        case WC_MLDSA87_NISTP384_SHA384: {
            // Sign ECC Component
            byte msg_digest[WC_SHA512_DIGEST_SIZE];

            if (composite_level == D2_WC_MLDSA87_NISTP384_SHA512) {
                if (wc_Sha512Hash(tbsMsg, tbsMsgLen, msg_digest) < 0) {
                    return BAD_STATE_E;
                }
            } else {
                if (wc_Sha384Hash(tbsMsg, tbsMsgLen, msg_digest) < 0) {
                    return BAD_STATE_E;
                }
            }

            if ((ret = wc_ecc_sign_hash(msg_digest, sizeof(msg_digest),
                                        otherSig_buffer, &otherSig_bufferLen, 
                                        rng, key->alt_key.ecc)) < 0) {
                return ret;
            }
        } break;

        case D2_WC_MLDSA87_BPOOL384_SHA512:
        case WC_MLDSA87_BPOOL384_SHA384: {
            // Sign ECC Component
            byte msg_digest[WC_SHA512_DIGEST_SIZE];

            if (composite_level == D2_WC_MLDSA87_BPOOL384_SHA512) {
                if (wc_Sha512Hash(tbsMsg, tbsMsgLen, msg_digest) < 0) {
                    return BAD_STATE_E;
                }
            } else {
                if (wc_Sha384Hash(tbsMsg, tbsMsgLen, msg_digest) < 0) {
                    return BAD_STATE_E;
                }
            }

            if ((ret = wc_ecc_sign_hash(msg_digest, sizeof(msg_digest),
                                        otherSig_buffer, &otherSig_bufferLen, 
                                        rng, key->alt_key.ecc)) < 0) {

                return ret;
            }
        } break;

        case D2_WC_MLDSA87_ED448_SHA512:
        case WC_MLDSA87_ED448_SHA384: {
            // Sign ED448 Component
            if ((ret = wc_ed448_sign_msg_ex(tbsMsg, tbsMsgLen,
                                            otherSig_buffer, 
                                            &otherSig_bufferLen, key->alt_key.ed448, 
                                            (byte)Ed448, context, contextLen)) < 0) {
                return ret;
            }
            if (otherSig_bufferLen != ED448_SIG_SIZE) {
                return BAD_STATE_E;
            }
        } break;

        default:
            MADWOLF_DEBUG("Invalid Composite Type: %d", composite_level);
            return ALGO_ID_E;
    }

    // Clears the memory (required because of a bug in wolfSSL)
    XMEMSET(sigsASN, 0, sizeof(sigsASN));

    // Set the ASN1 data for the ML-DSA and traditional DSA components
    SetASN_Buffer(&sigsASN[MLDSA_COMPASN_IDX_MLDSA], mldsaSig_buffer, mldsaSig_bufferLen);
    SetASN_Buffer(&sigsASN[MLDSA_COMPASN_IDX_OTHER], otherSig_buffer, otherSig_bufferLen);

    // Let's calculate the size of the ASN1 data
    if ((ret = SizeASN_Items(compositeIT, sigsASN, 3, (int *)sigLen)) < 0) {
        return ASN_PARSE_E;
    }

    // Check if the output buffer is large enough
    if (*sigLen > inSigLen) {
        return BUFFER_E;
    }

    // Let's encode the ASN1 data
    if ((*sigLen = SetASN_Items(compositeIT, sigsASN, 3, sig)) <= 0) { 
        return ASN_PARSE_E;
    }

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

        XMEMSET(key, 0, sizeof(mldsa_composite_key));

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
        // No Default Type
        key->type = 0;

        // Tracks the pub/priv key set
        key->prvKeySet = 0;
        key->pubKeySet = 0;
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
        wc_dilithium_free(key->mldsa_key);

        // Clear the alternative key
        switch (key->type) {
            case D2_MLDSA44_RSAPSS2048_SHA256_TYPE:
            case D2_MLDSA44_RSA2048_SHA256_TYPE:
            case D2_MLDSA65_RSAPSS3072_SHA512_TYPE:
            case D2_MLDSA65_RSA3072_SHA512_TYPE:
            case MLDSA65_RSAPSS3072_TYPE:
            case MLDSA65_RSA3072_TYPE:
            case MLDSA65_RSAPSS4096_TYPE:
            case MLDSA65_RSA4096_TYPE:
                if (key->alt_key.rsa != NULL) {
                    ret = wc_FreeRsaKey(key->alt_key.rsa);
                    key->alt_key.rsa = NULL;
                }
                break;

            case D2_MLDSA44_ED25519_SHA256_TYPE:
            case D2_MLDSA65_ED25519_SHA512_TYPE:
            case MLDSA44_ED25519_TYPE:
            case MLDSA65_ED25519_TYPE:
                if (key->alt_key.ed25519 != NULL) {
                    wc_ed25519_free(key->alt_key.ed25519);
                    key->alt_key.ed25519 = NULL;
                }
                ret = 0;
                break;

            case D2_MLDSA44_NISTP256_SHA256_TYPE:
            case D2_MLDSA65_NISTP256_SHA512_TYPE:
            case D2_MLDSA65_BPOOL256_SHA512_TYPE:
            case D2_MLDSA87_NISTP384_SHA512_TYPE:
            case D2_MLDSA87_BPOOL384_SHA512_TYPE:
            case WC_MLDSA44_NISTP256_SHA256:
            case MLDSA65_BPOOL256_TYPE:
            case MLDSA65_NISTP256_TYPE:
            case MLDSA87_NISTP384_TYPE:
            case MLDSA87_BPOOL384_TYPE:
                if (key->alt_key.ecc != NULL) {
                    ret = wc_ecc_free(key->alt_key.ecc);
                    key->alt_key.ecc = NULL;
                }
                break;

            case D2_MLDSA87_ED448_SHA512_TYPE:
            case MLDSA87_ED448_TYPE:
                if (key->alt_key.ed448 != NULL) {
                    wc_ed448_free(key->alt_key.ed448);
                    key->alt_key.ed448 = NULL;
                }
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
        ret = wc_dilithium_init_ex(key->mldsa_key, heap, devId);
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

// /* Set the level of the MlDsaComposite private/public key.
//  *
//  * key   [out]  MlDsaComposite key.
//  * level [in]   One of WC_MLDSA_COMPOSITE_TYPE_* values.
//  * returns BAD_FUNC_ARG when key is NULL or level is a bad values.
//  */
// int wc_mldsa_composite_set_level(mldsa_composite_key* key, int type)
// {
//     int ret = 0;

//     /* Validate parameters. */
//     if (key == NULL || wc_mldsa_composite_type <= 0 || key->pubKeySet || key->prvKeySet) {
//         /* Cannot set a type for an existing key */
//         ret = BAD_FUNC_ARG;
//     }
//     if (ret == 0) {
//         /* Sets the combination type */
//         switch (wc_mldsa_composite_type) {
//             case WC_MLDSA44_RSAPSS2048_SHA256:
//             case WC_MLDSA44_RSA2048_SHA256:
//             case WC_MLDSA44_ED25519_SHA256:
//             case WC_MLDSA44_NISTP256_SHA256:
//             case WC_MLDSA65_RSAPSS3072_SHA384:
//             case WC_MLDSA65_RSA3072_SHA384:
//             case WC_MLDSA65_RSAPSS4096_SHA384:
//             case WC_MLDSA65_RSA4096_SHA384:
//             case WC_MLDSA65_ED25519_SHA384:
//             case WC_MLDSA65_NISTP256_SHA384:
//             case WC_MLDSA65_BPOOL256_SHA384:
//             case WC_MLDSA87_NISTP384_SHA384:
//             case WC_MLDSA87_BPOOL384_SHA384:
//             case WC_MLDSA87_ED448_SHA384: {
//                 key->compType = wc_mldsa_composite_type;
//             } break;

//             default:
//                 MADWOLF_DEBUG("Invalid ML-DSA composite type: %d", wc_mldsa_composite_type);
//                 ret = BAD_FUNC_ARG;
//         }
//     }

//     return ret;
// }

/* Get the Key/Cert type of the composite key.
 *
 * key   [in]  MlDsaComposite key.
 * returns a value from enum CertType for the key.
 * returns BAD_FUNC_ARG when key is NULL or level has not been set.
 */
int wc_mldsa_composite_type(const mldsa_composite_key* key) {

    int ret = BAD_FUNC_ARG;

    if (!key || key->type <= 0) {
        return ret;
    }

    switch(key->type) {

        case MLDSA44_RSAPSS2048_TYPE:
        case MLDSA44_RSA2048_TYPE:
        case MLDSA44_ED25519_TYPE:
        case MLDSA44_NISTP256_TYPE:
        // case MLDSA44_BPOOL256_TYPE:
        case MLDSA65_RSAPSS3072_TYPE:
        case MLDSA65_RSA3072_TYPE:
        case MLDSA65_RSAPSS4096_TYPE:
        case MLDSA65_RSA4096_TYPE:
        case MLDSA65_ED25519_TYPE:
        case MLDSA65_NISTP256_TYPE:
        case MLDSA65_BPOOL256_TYPE:
        case MLDSA87_NISTP384_TYPE:
        case MLDSA87_BPOOL384_TYPE:
        case MLDSA87_ED448_TYPE:
            break;
        
        case D2_MLDSA44_RSAPSS2048_SHA256_TYPE:
        case D2_MLDSA44_RSA2048_SHA256_TYPE:
        case D2_MLDSA44_ED25519_SHA256_TYPE:
        case D2_MLDSA44_NISTP256_SHA256_TYPE:
        // case D2_MLDSA44_BPOOL256_SHA256_TYPE:
        case D2_MLDSA65_RSAPSS3072_SHA512_TYPE:
        case D2_MLDSA65_RSA3072_SHA512_TYPE:
        case D2_MLDSA65_ED25519_SHA512_TYPE:
        case D2_MLDSA65_NISTP256_SHA512_TYPE:
        case D2_MLDSA65_BPOOL256_SHA512_TYPE:
        case D2_MLDSA87_NISTP384_SHA512_TYPE:
        case D2_MLDSA87_BPOOL384_SHA512_TYPE:
        case D2_MLDSA87_ED448_SHA512_TYPE:
            break;

        case WC_MLDSA_COMPOSITE_UNDEF:
        default:
            return BAD_FUNC_ARG;
    }

    return key->type;
}


/* Get the mldsa_composite_level corresponding to the key/cert type.
 *
 * key   [in]  The value of the type of the key.
 * returns the value of the mldsa_composite_level corresponding to the key type.
 * returns BAD_FUNC_ARG when key is NULL or not initialized.
 */
int wc_mldsa_composite_type_level(int type) {
    
    int ret = BAD_FUNC_ARG;

    if (type <= 0) {
        return ret;
    }

    switch (type) {

        // Level 1
        case MLDSA44_RSA2048_TYPE:
            ret = WC_MLDSA44_RSA2048_SHA256;
            break;
        case MLDSA44_RSAPSS2048_TYPE:
            ret = WC_MLDSA44_RSAPSS2048_SHA256;
            break;
        case MLDSA44_ED25519_TYPE:
            ret = WC_MLDSA44_ED25519_SHA256;
            break;
        case MLDSA44_NISTP256_TYPE:
            ret = WC_MLDSA44_NISTP256_SHA256;
            break;

        // case MLDSA44_BPOOL256_TYPE:
        //     ret = WC_MLDSA44_BPOOL256_SHA256;
        //     break;

        // Level 3
        case MLDSA65_RSAPSS3072_TYPE:
            ret = WC_MLDSA65_RSAPSS3072_SHA384;
            break;
        case MLDSA65_RSA3072_TYPE:
            ret = WC_MLDSA65_RSA3072_SHA384;
            break;
        case MLDSA65_RSAPSS4096_TYPE:
            ret = WC_MLDSA65_RSAPSS4096_SHA384;
            break;
        case MLDSA65_RSA4096_TYPE:
            ret = WC_MLDSA65_RSA4096_SHA384;
            break;
        case MLDSA65_ED25519_TYPE:
            ret = WC_MLDSA65_ED25519_SHA384;
            break;
        case MLDSA65_NISTP256_TYPE:
            ret = WC_MLDSA65_NISTP256_SHA384;
            break;
        case MLDSA65_BPOOL256_TYPE:
            ret = WC_MLDSA65_BPOOL256_SHA384;
            break;
        
        // Level 5
        case MLDSA87_NISTP384_TYPE:
            ret = WC_MLDSA87_NISTP384_SHA384;
            break;
        case MLDSA87_BPOOL384_TYPE:
            ret = WC_MLDSA87_BPOOL384_SHA384;
            break;
        case MLDSA87_ED448_TYPE:
            ret = WC_MLDSA87_ED448_SHA384;
            break;

        // ------- Draft 2 ------------ //

        case D2_MLDSA44_RSAPSS2048_SHA256_TYPE:
            ret = D2_WC_MLDSA44_RSAPSS2048_SHA256;
            break;
        case D2_MLDSA44_RSA2048_SHA256_TYPE:
            ret = D2_WC_MLDSA44_RSA2048_SHA256;
            break;
        case D2_MLDSA44_ED25519_SHA256_TYPE:
            ret = D2_WC_MLDSA44_ED25519_SHA256;
            break;
        case D2_MLDSA44_NISTP256_SHA256_TYPE:
            ret = D2_WC_MLDSA44_NISTP256_SHA256;
            break;
        // case D2_MLDSA44_BPOOL256_SHA256_TYPE:
        //     ret = D2_WC_MLDSA44_BPOOL256_SHA256;
        //     break;

        case D2_MLDSA65_RSAPSS3072_SHA512_TYPE:
            ret = D2_WC_MLDSA65_RSAPSS3072_SHA512;
            break;
        case D2_MLDSA65_RSA3072_SHA512_TYPE:
            ret = D2_WC_MLDSA65_RSA3072_SHA512;
            break;
        case D2_MLDSA65_ED25519_SHA512_TYPE:
            ret = D2_WC_MLDSA65_ED25519_SHA512;
            break;
        case D2_MLDSA65_NISTP256_SHA512_TYPE:
            ret = D2_WC_MLDSA65_NISTP256_SHA512;
            break;
        case D2_MLDSA65_BPOOL256_SHA512_TYPE:
            ret = D2_WC_MLDSA65_BPOOL256_SHA512;
            break;
        case D2_MLDSA87_NISTP384_SHA512_TYPE:
            ret = D2_WC_MLDSA87_NISTP384_SHA512;
            break;
        case D2_MLDSA87_BPOOL384_SHA512_TYPE:
            ret = D2_WC_MLDSA87_BPOOL384_SHA512;
            break;
        case D2_MLDSA87_ED448_SHA512_TYPE:
            ret = D2_WC_MLDSA87_ED448_SHA512;
            break;

        case WC_MLDSA_COMPOSITE_UNDEF:
        default:
            MADWOLF_DEBUG("Invalid ML-DSA composite type: %d", type);
            ret = BAD_FUNC_ARG;
    }

    return ret;
}

/* Get the level of the MlDsaComposite private/public key.
 *
 * key   [in]  MlDsaComposite key.
 * level [out] The level.
 * returns a value from enum mldsa_composite_type.
 * returns BAD_FUNC_ARG when key is NULL or level has not been set.
 */
int wc_mldsa_composite_level(const mldsa_composite_key* key)
{
    int ret = 0;
    int type = 0;
        // The level of the composite key

    /* Validate parameters. */
    if (!key) {
        return BAD_FUNC_ARG;
    }

    /* Get the type of the composite key */
    type = wc_mldsa_composite_type(key);

    MADWOLF_DEBUG("Type: %d (key->type: %d)", type, key->type);

    /* Only recognized combinations are returned */
    switch (type) {

        case MLDSA44_RSAPSS2048_TYPE:
            ret = WC_MLDSA44_RSAPSS2048_SHA256;
            break;

        case MLDSA44_RSA2048_TYPE:
            ret = WC_MLDSA44_RSA2048_SHA256;
            break;

        case MLDSA44_ED25519_TYPE:
            ret = WC_MLDSA44_ED25519_SHA256;
            break;

        case MLDSA44_NISTP256_TYPE:
            ret = WC_MLDSA44_NISTP256_SHA256;
            break;

        // case MLDSA44_BPOOL256_TYPE:
        //     ret = WC_MLDSA44_BPOOL256_SHA256;
        //     break;

        case MLDSA65_RSAPSS3072_TYPE:
            ret = WC_MLDSA65_RSAPSS3072_SHA384;
            break;

        case MLDSA65_RSA3072_TYPE:
            ret = WC_MLDSA65_RSA3072_SHA384;
            break;

        case MLDSA65_RSAPSS4096_TYPE:
            ret = WC_MLDSA65_RSAPSS4096_SHA384;
            break;

        case MLDSA65_RSA4096_TYPE:
            ret = WC_MLDSA65_RSA4096_SHA384;
            break;

        case MLDSA65_ED25519_TYPE:
            ret = WC_MLDSA65_ED25519_SHA384;
            break;

        case MLDSA65_NISTP256_TYPE:
            ret = WC_MLDSA65_NISTP256_SHA384;
            break;

        case MLDSA65_BPOOL256_TYPE:
            ret = WC_MLDSA65_BPOOL256_SHA384;
            break;

        case MLDSA87_NISTP384_TYPE:
            ret = WC_MLDSA87_NISTP384_SHA384;
            break;

        case MLDSA87_BPOOL384_TYPE:
            ret = WC_MLDSA87_BPOOL384_SHA384;
            break;

        case MLDSA87_ED448_TYPE:
            ret = WC_MLDSA87_ED448_SHA384;
            break;

        // ---------------- Draft 2 ---------------- //

        case D2_MLDSA44_RSAPSS2048_SHA256_TYPE:
            ret = D2_WC_MLDSA44_RSAPSS2048_SHA256;
            break;
            
        case D2_MLDSA44_RSA2048_SHA256_TYPE:
            ret = D2_WC_MLDSA44_RSA2048_SHA256;
            break;

        case D2_MLDSA44_ED25519_SHA256_TYPE:
            ret = D2_WC_MLDSA44_ED25519_SHA256;
            break;

        case D2_MLDSA44_NISTP256_SHA256_TYPE:
            ret = D2_WC_MLDSA44_NISTP256_SHA256;
            break;

        // case D2_MLDSA44_BPOOL256_SHA256_TYPE:
        //     ret = D2_MLDSA44_BPOOL256k;
        //     break;

        case D2_WC_MLDSA65_RSAPSS3072_SHA512:
            ret = D2_WC_MLDSA65_RSAPSS3072_SHA512;
            break;
            
        case D2_WC_MLDSA65_RSA3072_SHA512:
            ret = D2_WC_MLDSA65_RSA3072_SHA512;
            break;

        case D2_WC_MLDSA65_ED25519_SHA512:
            ret = D2_WC_MLDSA65_ED25519_SHA512;
            break;

        case D2_WC_MLDSA65_NISTP256_SHA512:
            ret = D2_WC_MLDSA65_NISTP256_SHA512;
            break;

        case D2_WC_MLDSA65_BPOOL256_SHA512:
            ret = D2_WC_MLDSA65_BPOOL256_SHA512;
            break;

        case D2_WC_MLDSA87_NISTP384_SHA512:
            ret = D2_WC_MLDSA87_NISTP384_SHA512;
            break;

        case D2_WC_MLDSA87_BPOOL384_SHA512:
            ret = D2_WC_MLDSA87_BPOOL384_SHA512;
            break;

        case D2_WC_MLDSA87_ED448_SHA512:
            ret = D2_WC_MLDSA87_ED448_SHA512;
            break;

        case WC_MLDSA_COMPOSITE_UNDEF:
        default:
            return BAD_FUNC_ARG;
    }

    return ret;
}

/* Get the level of the MlDsaComposite private/public key.
 *
 * key   [in]  MlDsaComposite key.
 * level [out] The level.
 * returns a value from enum CertType.
 * returns BAD_FUNC_ARG when key is NULL or level has not been set.
 */
int wc_mldsa_composite_level_type(int mldsa_level)
{
    int ret = 0;

    /* Validate parameters. */
    if (mldsa_level <= 0) {
        return BAD_FUNC_ARG;
    }

    /* Only recognized combinations are returned */
    switch (mldsa_level) {

        case WC_MLDSA44_RSAPSS2048_SHA256:
            ret = MLDSA44_RSAPSS2048_TYPE;
            break;

        case WC_MLDSA44_RSA2048_SHA256:
            ret = MLDSA44_RSA2048_TYPE;
            break;

        case WC_MLDSA44_ED25519_SHA256:
            ret = MLDSA44_ED25519_TYPE;
            break;

        case WC_MLDSA44_NISTP256_SHA256:
            ret = MLDSA44_NISTP256_TYPE;
            break;

        // case WC_MLDSA44_BPOOL256_SHA256:
        //     ret = MLDSA44_BPOOL256_TYPE;
        //     break;

        case WC_MLDSA65_RSAPSS3072_SHA384:
            ret = MLDSA65_RSAPSS3072_TYPE;
            break;

        case WC_MLDSA65_RSA3072_SHA384:
            ret = MLDSA65_RSA3072_TYPE;
            break;

        case WC_MLDSA65_RSAPSS4096_SHA384:
            ret = MLDSA65_RSAPSS4096_TYPE;
            break;

        case WC_MLDSA65_RSA4096_SHA384:
            ret = MLDSA65_RSA4096_TYPE;
            break;

        case WC_MLDSA65_ED25519_SHA384:
            ret = MLDSA65_ED25519_TYPE;
            break;

        case WC_MLDSA65_NISTP256_SHA384:
            ret = MLDSA65_NISTP256_TYPE;
            break;

        case WC_MLDSA65_BPOOL256_SHA384:
            ret = MLDSA65_BPOOL256_TYPE;
            break;

        case WC_MLDSA87_NISTP384_SHA384:
            ret = MLDSA87_NISTP384_TYPE;
            break;

        case WC_MLDSA87_BPOOL384_SHA384:
            ret = MLDSA87_BPOOL384_TYPE;
            break;

        case WC_MLDSA87_ED448_SHA384:
            ret = MLDSA87_ED448_TYPE;
            break;

        // ---------------- Draft 2 ---------------- //

        case D2_WC_MLDSA44_RSAPSS2048_SHA256:
            ret = D2_MLDSA44_RSAPSS2048_SHA256_TYPE;
            break;
            
        case D2_WC_MLDSA44_RSA2048_SHA256:
            ret = D2_MLDSA44_RSA2048_SHA256_TYPE;
            break;

        case D2_WC_MLDSA44_ED25519_SHA256:
            ret = D2_MLDSA44_ED25519_SHA256_TYPE;
            break;

        case D2_WC_MLDSA44_NISTP256_SHA256:
            ret = D2_MLDSA44_NISTP256_SHA256_TYPE;
            break;

        // case D2_WC_MLDSA44_BPOOL256_SHA256:
        //     ret = D2_MLDSA44_BPOOL256_SHA256_TYPE;
        //     break;

        case D2_WC_MLDSA65_RSAPSS3072_SHA512:
            ret = D2_MLDSA65_RSAPSS3072_SHA512_TYPE;
            break;
            
        case D2_WC_MLDSA65_RSA3072_SHA512:
            ret = D2_MLDSA65_RSA3072_SHA512_TYPE;
            break;

        case D2_WC_MLDSA65_ED25519_SHA512:
            ret = D2_MLDSA65_ED25519_SHA512_TYPE;
            break;

        case D2_WC_MLDSA65_NISTP256_SHA512:
            ret = D2_MLDSA65_NISTP256_SHA512_TYPE;
            break;

        case D2_WC_MLDSA65_BPOOL256_SHA512:
            ret = D2_MLDSA65_BPOOL256_SHA512_TYPE;
            break;

        case D2_WC_MLDSA87_NISTP384_SHA512:
            ret = D2_MLDSA87_NISTP384_SHA512_TYPE;
            break;

        case D2_WC_MLDSA87_BPOOL384_SHA512:
            ret = D2_MLDSA87_BPOOL384_SHA512_TYPE;
            break;

        case D2_WC_MLDSA87_ED448_SHA512:
            ret = D2_MLDSA87_ED448_SHA512_TYPE;
            break;

        case WC_MLDSA_COMPOSITE_UNDEF:
        default:
            return BAD_FUNC_ARG;
    }

    return ret;
}

/* Get the KeySum of the MlDsaComposite private/public key.
 *
 * key   [in]  MlDsaComposite key.
 * returns enum Key_Sum value of the key.
 * returns BAD_FUNC_ARG when key is NULL or not initialized.
 */
int wc_mldsa_composite_key_sum(const mldsa_composite_key * key) {
    
    int ret = BAD_FUNC_ARG;

    if (key == NULL) {
        return ret;
    }

    /* Only recognized combinations are returned */
    if (ret == 0) {

        switch (key->type) {

            // Level 1
            case MLDSA44_RSA2048_TYPE:
                ret = MLDSA44_RSA2048k;
                break;
            case MLDSA44_RSAPSS2048_TYPE:
                ret = MLDSA44_RSAPSS2048k;
                break;
            case MLDSA44_ED25519_TYPE:
                ret = MLDSA44_ED25519k;
                break;
            case MLDSA44_NISTP256_TYPE:
                ret = MLDSA44_NISTP256k;
                break;
            // case WC_MLDSA44_BPOOL256_TYPE:
            //     ret = MLDSA44_BPOOL256k;
            //     break;

            // Level 3
            case MLDSA65_RSAPSS3072_TYPE:
                ret = MLDSA65_RSAPSS3072k;
                break;
            case MLDSA65_RSA3072_TYPE:
                ret = MLDSA65_RSA3072k;
                break;
            case MLDSA65_RSAPSS4096_TYPE:
                ret = MLDSA65_RSAPSS4096k;
                break;
            case MLDSA65_RSA4096_TYPE:
                ret = MLDSA65_RSA4096k;
                break;
            case MLDSA65_ED25519_TYPE:
                ret = MLDSA65_ED25519k;
                break;
            case MLDSA65_NISTP256_TYPE:
                ret = MLDSA65_NISTP256k;
                break;
            case MLDSA65_BPOOL256_TYPE:
                ret = MLDSA65_BPOOL256k;
                break;
            
            // Level 5
            case MLDSA87_NISTP384_TYPE:
                ret = MLDSA87_NISTP384k;
                break;
            case MLDSA87_BPOOL384_TYPE:
                ret = MLDSA87_BPOOL384k;
                break;
            case MLDSA87_ED448_TYPE:
                ret = MLDSA87_ED448k;
                break;

            // ------- Draft 2 ------------ //

            case D2_MLDSA44_RSAPSS2048_SHA256_TYPE:
                ret = D2_MLDSA44_RSAPSS2048k;
                break;
            case D2_MLDSA44_RSA2048_SHA256_TYPE:
                ret = D2_MLDSA44_RSA2048k;
                break;
            case D2_MLDSA44_ED25519_SHA256_TYPE:
                ret = D2_MLDSA44_ED25519k;
                break;
            case D2_MLDSA44_NISTP256_SHA256_TYPE:
                ret = D2_MLDSA44_NISTP256k;
                break;
            // case D2_MLDSA44_BPOOL256_SHA256_TYPE:
            //     ret = D2_MLDSA44
            //     break;

            case D2_MLDSA65_RSAPSS3072_SHA512_TYPE:
                ret = D2_MLDSA65_RSAPSS3072k;
                break;
            case D2_MLDSA65_RSA3072_SHA512_TYPE:
                ret = D2_MLDSA65_RSA3072k;
                break;
            case D2_MLDSA65_ED25519_SHA512_TYPE:
                ret = D2_MLDSA65_ED25519k;
                break;
            case D2_MLDSA65_NISTP256_SHA512_TYPE:
                ret = D2_MLDSA65_NISTP256k;
                break;
            case D2_MLDSA65_BPOOL256_SHA512_TYPE:
                ret = D2_MLDSA65_BPOOL256k;
                break;
            case D2_MLDSA87_NISTP384_SHA512_TYPE:
                ret = D2_MLDSA87_NISTP384k;
                break;
            case D2_MLDSA87_BPOOL384_SHA512_TYPE:
                ret = D2_MLDSA87_BPOOL384k;
                break;
            case D2_MLDSA87_ED448_SHA512_TYPE:
                ret = D2_MLDSA87_ED448k;
                break;

            case WC_MLDSA_COMPOSITE_UNDEF:
            default:
                MADWOLF_DEBUG("Invalid ML-DSA composite type: %d", key->type);
                ret = BAD_FUNC_ARG;
        }
    }

    return ret;
}

/*
* Convert the KeySum to the MlDsaComposite level.
*
* keytype_sum  [in]  enum Key_Sum value.
* returns enum mldsa_composite_level value.
* returns BAD_FUNC_ARG when keytype_sum is not a valid value.
*/
int wc_mldsa_composite_key_sum_level(const enum Key_Sum keytype_sum) {

    enum mldsa_composite_level ret = 0;

    /* Validate parameters. */
    if (keytype_sum <= 0) {
        return BAD_FUNC_ARG;
    }

    /* Only recognized combinations are returned */
    if (ret == 0) {
        // Level 1
        if (keytype_sum == MLDSA44_RSA2048k) {
            ret = WC_MLDSA44_RSA2048_SHA256;
        } else if (keytype_sum == MLDSA44_RSAPSS2048k) {
            ret = WC_MLDSA44_RSAPSS2048_SHA256;
        } else if (keytype_sum == MLDSA44_ED25519k) {
            ret = WC_MLDSA44_ED25519_SHA256;
        } else if (keytype_sum == MLDSA44_NISTP256k) {
            ret = WC_MLDSA44_NISTP256_SHA256;
        // } else if (keytype_sum == MLDSA44_BPOOL256k) {
        //     ret = WC_MLDSA44_BPOOL256_SHA256;
        // Level 3
        } else if (keytype_sum == MLDSA65_RSAPSS3072k) {
            ret = WC_MLDSA65_RSAPSS3072_SHA384;
        } else if (keytype_sum == MLDSA65_RSA3072k) {
            ret = WC_MLDSA65_RSA3072_SHA384;
        } else if (keytype_sum == MLDSA65_RSAPSS4096k) {
            ret = WC_MLDSA65_RSAPSS4096_SHA384;
        } else if (keytype_sum == MLDSA65_RSA4096k) {
            ret = WC_MLDSA65_RSA4096_SHA384;
        } else if (keytype_sum == MLDSA65_ED25519k) {
            ret = WC_MLDSA65_ED25519_SHA384;
        } else if (keytype_sum == MLDSA65_NISTP256k) {
            ret = WC_MLDSA65_NISTP256_SHA384;
        } else if (keytype_sum == MLDSA65_BPOOL256k) {
            ret = WC_MLDSA65_BPOOL256_SHA384;
        // Level 5
        } else if (keytype_sum == MLDSA87_NISTP384k) {
            ret = WC_MLDSA87_NISTP384_SHA384;
        } else if (keytype_sum == MLDSA87_BPOOL384k) {
            ret = WC_MLDSA87_BPOOL384_SHA384;
        } else if (keytype_sum == MLDSA87_ED448k) {
            ret = WC_MLDSA87_ED448_SHA384;
        // ------------- Draft 2 ---------------- //
        } else if (keytype_sum == D2_MLDSA44_RSAPSS2048k) {
            ret = D2_WC_MLDSA44_RSAPSS2048_SHA256;
        } else if (keytype_sum == D2_MLDSA44_RSA2048k) {
            ret = D2_WC_MLDSA44_RSA2048_SHA256;
        } else if (keytype_sum == D2_MLDSA44_ED25519k) {
            ret = D2_WC_MLDSA44_ED25519_SHA256;
        } else if (keytype_sum == D2_MLDSA44_NISTP256k) {
            ret = D2_WC_MLDSA44_NISTP256_SHA256;
        // } else if (keytype_sum == D2_MLDSA44_BPOOL256k) {
        //     ret = D2_WC_MLDSA44_BPOOL256_SHA256;
        // Level 3
        } else if (keytype_sum == D2_MLDSA65_RSAPSS3072k) {
            ret = D2_WC_MLDSA65_RSAPSS3072_SHA512;
        } else if (keytype_sum == D2_MLDSA65_RSA3072k) {
            ret = D2_WC_MLDSA65_RSA3072_SHA512;
        } else if (keytype_sum == D2_MLDSA65_ED25519k) {
            ret = D2_WC_MLDSA65_ED25519_SHA512;
        } else if (keytype_sum == D2_MLDSA65_NISTP256k) {
            ret = D2_WC_MLDSA65_NISTP256_SHA512;
        } else if (keytype_sum == D2_MLDSA65_BPOOL256k) {
            ret = D2_WC_MLDSA65_BPOOL256_SHA512;
        } else if (keytype_sum == D2_MLDSA87_NISTP384k) {
            ret = D2_WC_MLDSA87_NISTP384_SHA512;
        } else if (keytype_sum == D2_MLDSA87_BPOOL384k) {
            ret = D2_WC_MLDSA87_BPOOL384_SHA512;
        } else if (keytype_sum == D2_MLDSA87_ED448k) {
            ret = D2_WC_MLDSA87_ED448_SHA512;
        // Error
        } else {
            return BAD_FUNC_ARG;
        }
    }

    return ret;
}

/*
* Convert the KeySum to the MlDsaComposite type.
*
* keytype_sum  [in]  enum Key_Sum value.
* returns enum mldsa_composite_type value.
* returns BAD_FUNC_ARG when keytype_sum is not a valid value.
*/
int wc_composite_level_key_sum(const enum mldsa_composite_level type) {

    enum Key_Sum ret = 0;

    /* Validate parameters. */
    if (type <= 0) {
        return BAD_FUNC_ARG;
    }

    /* Only recognized combinations are returned */
    if (ret == 0) {
        // Level 1
        if (type == WC_MLDSA44_RSA2048_SHA256) {
            ret = MLDSA44_RSA2048k;
        } else if (type == WC_MLDSA44_RSAPSS2048_SHA256) {
            ret = MLDSA44_RSAPSS2048k;
        } else if (type == WC_MLDSA44_ED25519_SHA256) {
            ret = MLDSA44_ED25519k;
        } else if (type == WC_MLDSA44_NISTP256_SHA256) {
            ret = MLDSA44_NISTP256k;
        // } else if (type == MLDSA44_BPOOL256k) {
        //     ret = WC_MLDSA44_BPOOL256_SHA256;
        // Level 3
        } else if (type == WC_MLDSA65_RSAPSS3072_SHA384) {
            ret = MLDSA65_RSAPSS3072k;
        } else if (type == WC_MLDSA65_RSA3072_SHA384) {
            ret = MLDSA65_RSA3072k;
        } else if (type == WC_MLDSA65_RSAPSS4096_SHA384) {
            ret = MLDSA65_RSAPSS4096k;
        } else if (type == WC_MLDSA65_RSA4096_SHA384) {
            ret = MLDSA65_RSA4096k;
        } else if (type == WC_MLDSA65_ED25519_SHA384) {
            ret = MLDSA65_ED25519k;
        } else if (type == WC_MLDSA65_NISTP256_SHA384) {
            ret = MLDSA65_NISTP256k;
        } else if (type == WC_MLDSA65_BPOOL256_SHA384) {
            ret = MLDSA65_BPOOL256k;
        // Level 5
        } else if (type == WC_MLDSA87_NISTP384_SHA384) {
            ret = MLDSA87_NISTP384k;
        } else if (type == WC_MLDSA87_BPOOL384_SHA384) {
            ret = MLDSA87_BPOOL384k;
        } else if (type == WC_MLDSA87_ED448_SHA384) {
            ret = MLDSA87_ED448k;
        } else if (type == D2_WC_MLDSA44_RSAPSS2048_SHA256) {
            ret = D2_MLDSA44_RSAPSS2048k;
        } else if (type == D2_WC_MLDSA44_RSA2048_SHA256) {
            ret = D2_MLDSA44_RSA2048k;
        } else if (type == D2_WC_MLDSA44_ED25519_SHA256) {
            ret = D2_MLDSA44_ED25519k;
        } else if (type == D2_WC_MLDSA44_NISTP256_SHA256) {
            ret = D2_MLDSA44_NISTP256k;
        // } else if (type == D2_MLDSA44_BPOOL256k) {
        //     ret = D2_WC_MLDSA44_BPOOL256_SHA256;
        } else if (type == D2_WC_MLDSA65_RSAPSS3072_SHA512) {
            ret = D2_MLDSA65_RSAPSS3072k;
        } else if (type == D2_WC_MLDSA65_RSA3072_SHA512) {
            ret = D2_MLDSA65_RSA3072k;
        } else if (type == D2_WC_MLDSA65_ED25519_SHA512) {
            ret = D2_MLDSA65_ED25519k;
        } else if (type == D2_WC_MLDSA65_NISTP256_SHA512) {
            ret = D2_MLDSA65_NISTP256k;
        } else if (type == D2_WC_MLDSA65_BPOOL256_SHA512) {
            ret = D2_MLDSA65_BPOOL256k;
        } else if (type == D2_WC_MLDSA87_NISTP384_SHA512) {
            ret = D2_MLDSA87_NISTP384k;
        } else if (type == D2_WC_MLDSA87_BPOOL384_SHA512) {
            ret = D2_MLDSA87_BPOOL384k;
        } else if (type == D2_WC_MLDSA87_ED448_SHA512) {
            ret = D2_MLDSA87_ED448k;
        // Error
        } else {
            return BAD_FUNC_ARG;
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

    int composite_level = 0;
        // The level of the composite key
    
    /* Validate parameters. */
    if (key == NULL) {
        return;
    }

    /* Free the ML-DSA key*/
    if (key->mldsa_key) {
        wc_dilithium_free(key->mldsa_key);
        key->mldsa_key = NULL;
    }

    /* Gets the Composite Level */
    composite_level = wc_mldsa_composite_level(key);

    /* Free the classic component */
    switch (composite_level) {

        case WC_MLDSA_COMPOSITE_UNDEF: {
            /* Do nothing */
        } break;
        
        // Level 1
        case D2_WC_MLDSA44_RSAPSS2048_SHA256:
        case D2_WC_MLDSA44_RSA2048_SHA256:
        case D2_WC_MLDSA65_RSAPSS3072_SHA512:
        case D2_WC_MLDSA65_RSA3072_SHA512:
        case WC_MLDSA44_RSA2048_SHA256:
        case WC_MLDSA44_RSAPSS2048_SHA256:
        case WC_MLDSA65_RSA3072_SHA384:
        case WC_MLDSA65_RSAPSS3072_SHA384:
        case WC_MLDSA65_RSA4096_SHA384:
        case WC_MLDSA65_RSAPSS4096_SHA384: {
            if (key->alt_key.rsa) {
                wc_FreeRsaKey(key->alt_key.rsa);
                key->alt_key.rsa = NULL;
            }
        } break;

        case D2_WC_MLDSA44_ED25519_SHA256:
        case D2_WC_MLDSA65_ED25519_SHA512:
        case WC_MLDSA44_ED25519_SHA256:
        case WC_MLDSA65_ED25519_SHA384: {
            if (key->alt_key.ed25519) {
                wc_ed25519_free(key->alt_key.ed25519);
                key->alt_key.ed25519 = NULL;
            }
        } break;
        
        case D2_WC_MLDSA44_NISTP256_SHA256:
        case D2_WC_MLDSA65_NISTP256_SHA512:
        case D2_WC_MLDSA65_BPOOL256_SHA512:
        case D2_WC_MLDSA87_BPOOL384_SHA512:
        case D2_WC_MLDSA87_NISTP384_SHA512:
        // case D2_MLDSA44_BPOOL256_SHA256:
        // case WC_MLDSA44_BPOOL256_SHA256:
        case WC_MLDSA44_NISTP256_SHA256:
        case WC_MLDSA65_NISTP256_SHA384:
        case WC_MLDSA65_BPOOL256_SHA384:
        case WC_MLDSA87_NISTP384_SHA384:
        case WC_MLDSA87_BPOOL384_SHA384: {
            if (key->alt_key.ecc) {
                wc_ecc_free(key->alt_key.ecc);
                key->alt_key.ecc = NULL;
            }
        } break;

        case D2_WC_MLDSA87_ED448_SHA512:
        case WC_MLDSA87_ED448_SHA384: {
            if (key->alt_key.ed448) {
                wc_ed448_free(key->alt_key.ed448);
                key->alt_key.ed448 = NULL;
            }
        } break;

        default: {
            /* Error */
            WOLFSSL_MSG_VSNPRINTF("Invalid MLDSA Composite Level: %d and Type: %d", composite_level, key->type);
        }
    }

    XFREE(key, key->heap, sizeof(mldsa_composite_key));
}

#ifdef WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY

int wc_mldsa_composite_size(mldsa_composite_key* key)
{
    int ret = 0;

    if (!key) {
        return BAD_FUNC_ARG;
    }

    switch (key->type) {

        // Level 1
        case MLDSA44_RSA2048_TYPE:
        case MLDSA44_RSAPSS2048_TYPE:
            ret = MLDSA44_RSA2048_KEY_SIZE;
            break;

        case MLDSA44_ED25519_TYPE:
            ret = MLDSA44_ED25519_KEY_SIZE;
            break;

        case MLDSA44_NISTP256_TYPE:
            ret = MLDSA44_NISTP256_KEY_SIZE; // + wc_ecc_get_curve_size_from_id(ECC_SECP256R1);
            break;

        // case WC_MLDSA44_BPOOL256_SHA256:
        //     ret = MLDSA44_NISTP256_KEY_SIZE; // + wc_ecc_get_curve_size_from_id(ECC_BRAINPOOLP256R1);
        //     break;
        
        // Level 3
        case MLDSA65_RSAPSS4096_TYPE:
        case MLDSA65_RSA4096_TYPE:
            ret = MLDSA65_RSA4096_KEY_SIZE;
            break;
        
        case MLDSA65_RSAPSS3072_TYPE:
        case MLDSA65_RSA3072_TYPE:
            ret = MLDSA65_RSA3072_KEY_SIZE;
            break;
        
        case MLDSA65_ED25519_TYPE:
            ret = MLDSA65_ED25519_KEY_SIZE;
            break;

        case MLDSA65_NISTP256_TYPE:
        case MLDSA65_BPOOL256_TYPE:
            ret = MLDSA65_NISTP256_KEY_SIZE; // + wc_ecc_get_curve_size_from_id(ECC_SECP256R1);
            break;
        
        // Level 5
        case MLDSA87_NISTP384_TYPE:
            ret = MLDSA87_NISTP384_KEY_SIZE; // + wc_ecc_get_curve_size_from_id(ECC_SECP384R1);
            break;
        
        case MLDSA87_BPOOL384_TYPE:
            ret = MLDSA87_NISTP384_KEY_SIZE; // + wc_ecc_get_curve_size_from_id(ECC_BRAINPOOLP384R1);
            break;
        
        case MLDSA87_ED448_TYPE:
            ret = MLDSA87_ED448_KEY_SIZE;
            break;

        case D2_MLDSA44_RSAPSS2048_SHA256_TYPE:
        case D2_MLDSA44_RSA2048_SHA256_TYPE:
        case D2_MLDSA44_NISTP256_SHA256_TYPE:
        // case D2_WC_MLDSA44_BPOOL256_SHA256_TYPE:
        case D2_MLDSA44_ED25519_SHA256_TYPE:
        case D2_MLDSA65_RSAPSS3072_SHA512_TYPE:
        case D2_MLDSA65_RSA3072_SHA512_TYPE:
        case D2_MLDSA65_NISTP256_SHA512_TYPE:
        case D2_MLDSA65_BPOOL256_SHA512_TYPE:
        case D2_MLDSA65_ED25519_SHA512_TYPE:
        case D2_MLDSA87_NISTP384_SHA512_TYPE:
        case D2_MLDSA87_BPOOL384_SHA512_TYPE:
        case D2_MLDSA87_ED448_SHA512_TYPE:
            MADWOLF_DEBUG("Draft 2 composite size (GET) not supported (type: %d)", key->type);
            return BAD_FUNC_ARG;

        case WC_MLDSA_COMPOSITE_UNDEF:
        default:
            /* Error */
            return BAD_FUNC_ARG;
    }

    return ret;
}

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY

int wc_mldsa_composite_priv_size(mldsa_composite_key* key) {

    int ret = BAD_FUNC_ARG;

    if (!key) {
        return BAD_FUNC_ARG;
    }

    switch (key->type) {
        
        case MLDSA44_RSAPSS2048_TYPE:
        case MLDSA44_RSA2048_TYPE:
            ret = MLDSA44_RSA2048_PRV_KEY_SIZE;
            break;

        case MLDSA44_ED25519_TYPE:
            ret = MLDSA44_ED25519_PRV_KEY_SIZE;
            break;

        case MLDSA44_NISTP256_TYPE:
            ret = MLDSA44_NISTP256_PRV_KEY_SIZE;
            break;
        
        // case MLDSA44_BPOOL256_TYPE:
        //     ret = MLDSA44_NISTP256_PRV_KEY_SIZE;
        //     break;

        case MLDSA65_RSAPSS4096_TYPE:
        case MLDSA65_RSA4096_TYPE:
            ret = MLDSA65_RSA4096_PRV_KEY_SIZE;
            break;

        case MLDSA65_RSAPSS3072_TYPE:
        case MLDSA65_RSA3072_TYPE:
            ret = MLDSA65_RSA3072_PRV_KEY_SIZE;
            break;

        case MLDSA65_NISTP256_TYPE:
            ret = MLDSA65_NISTP256_PRV_KEY_SIZE;
            break;
        
        case MLDSA65_BPOOL256_TYPE:
            ret = MLDSA65_NISTP256_PRV_KEY_SIZE;
            break;

        case MLDSA65_ED25519_TYPE:
            ret = MLDSA65_ED25519_PRV_KEY_SIZE;
            break;

        case MLDSA87_NISTP384_TYPE:
            ret = MLDSA87_NISTP384_PRV_KEY_SIZE;
            break;
        
        case MLDSA87_BPOOL384_TYPE:
            ret = MLDSA87_NISTP384_PRV_KEY_SIZE;
            break;
        
        case MLDSA87_ED448_TYPE:
            ret = MLDSA87_ED448_PRV_KEY_SIZE;
            break;

        /* -------------- Draft 2 ---------------- */

        case D2_MLDSA44_RSAPSS2048_SHA256_TYPE:
        case D2_MLDSA44_RSA2048_SHA256_TYPE:
        case D2_MLDSA44_NISTP256_SHA256_TYPE:
        // case D2_MLDSA44_BPOOL256_SHA256_TYPE:
        case D2_MLDSA44_ED25519_SHA256_TYPE:
        case D2_MLDSA65_RSAPSS3072_SHA512_TYPE:
        case D2_MLDSA65_RSA3072_SHA512_TYPE:
        case D2_MLDSA65_NISTP256_SHA512_TYPE:
        case D2_MLDSA65_BPOOL256_SHA512_TYPE:
        case D2_MLDSA65_ED25519_SHA512_TYPE:
        case D2_MLDSA87_NISTP384_SHA512_TYPE:
        case D2_MLDSA87_BPOOL384_SHA512_TYPE:
        case D2_MLDSA87_ED448_SHA512_TYPE:
            MADWOLF_DEBUG("Draft 2 private key size (GET) not supported (type: %d)", key->type);
            return BAD_FUNC_ARG;

        case WC_MLDSA_COMPOSITE_UNDEF:
        default:
            /* Error */
            ret = BAD_FUNC_ARG;
    }

    return ret;
}

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

int wc_mldsa_composite_pub_size(mldsa_composite_key* key)
{
    int ret = BAD_FUNC_ARG;
    int composite_level = 0;

    if (!key) {
        return ret;
    }

    composite_level = wc_mldsa_composite_level(key);


    switch (composite_level) {

        // Level 1
        case WC_MLDSA44_RSAPSS2048_SHA256:
        case WC_MLDSA44_RSA2048_SHA256:
            ret = MLDSA44_RSA2048_PUB_KEY_SIZE;
            break;

        case WC_MLDSA44_ED25519_SHA256:
            ret = MLDSA44_ED25519_PUB_KEY_SIZE;
            break;

        case WC_MLDSA44_NISTP256_SHA256:
            ret = MLDSA44_NISTP256_PUB_KEY_SIZE;
            break;

        // case WC_MLDSA44_BPOOL256_SHA256:
        //     ret = MLDSA44_BPOOL256_PUB_KEY_SIZE;
        //     break;

        // Level 3
        case WC_MLDSA65_RSAPSS3072_SHA384:
        case WC_MLDSA65_RSA3072_SHA384:
            ret = MLDSA65_RSA3072_PUB_KEY_SIZE;
            break;
        
        case WC_MLDSA65_RSAPSS4096_SHA384:
        case WC_MLDSA65_RSA4096_SHA384:
            ret = MLDSA65_RSA4096_PUB_KEY_SIZE;
            break;

        case WC_MLDSA65_ED25519_SHA384:
            ret = MLDSA65_ED25519_PUB_KEY_SIZE;
            break;
        
        case WC_MLDSA65_NISTP256_SHA384:
            ret = MLDSA65_NISTP256_PUB_KEY_SIZE;
            break;
        
        case WC_MLDSA65_BPOOL256_SHA384:
            ret = MLDSA65_NISTP256_PUB_KEY_SIZE;
            break;
        
        // Level 5
        case WC_MLDSA87_NISTP384_SHA384:
            ret = MLDSA87_NISTP384_PUB_KEY_SIZE;
            break;
        
        case WC_MLDSA87_BPOOL384_SHA384:
            ret = MLDSA87_NISTP384_PUB_KEY_SIZE;
            break;
        
        case WC_MLDSA87_ED448_SHA384:
            ret = MLDSA87_ED448_PUB_KEY_SIZE;
            break;

        case D2_WC_MLDSA44_RSAPSS2048_SHA256:
        case D2_WC_MLDSA44_RSA2048_SHA256:
        case D2_WC_MLDSA44_NISTP256_SHA256:
        // case D2_WC_MLDSA44_BPOOL256_SHA256:
        case D2_WC_MLDSA44_ED25519_SHA256:
        case D2_WC_MLDSA65_RSAPSS3072_SHA512:
        case D2_WC_MLDSA65_RSA3072_SHA512:
        case D2_WC_MLDSA65_NISTP256_SHA512:
        case D2_WC_MLDSA65_BPOOL256_SHA512:
        case D2_WC_MLDSA65_ED25519_SHA512:
        case D2_WC_MLDSA87_NISTP384_SHA512:
        case D2_WC_MLDSA87_BPOOL384_SHA512:
        case D2_WC_MLDSA87_ED448_SHA512:
            MADWOLF_DEBUG("Draft 2 public key size (GET) not supported (level: %d)", composite_level);
            return BAD_FUNC_ARG;

        case WC_MLDSA_COMPOSITE_UNDEF:
        default:
            /* Error */
            return BAD_FUNC_ARG;
    }

    return ret;
}

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

int wc_mldsa_composite_sig_size(mldsa_composite_key* key)
{
    int ret = BAD_FUNC_ARG;
    int composite_level = wc_mldsa_composite_level(key);

    if (!key)
        return BAD_FUNC_ARG;
    
    switch (composite_level) {

        // Level 1
        case WC_MLDSA44_RSA2048_SHA256:
            ret = MLDSA44_RSA2048_SIG_SIZE;
            break;

        case WC_MLDSA44_RSAPSS2048_SHA256:
            ret = MLDSA44_RSA2048_SIG_SIZE;
            break;
        
        case WC_MLDSA44_ED25519_SHA256:
            ret = MLDSA44_ED25519_SIG_SIZE;
            break;

        case WC_MLDSA44_NISTP256_SHA256:
            ret = MLDSA44_NISTP256_SIG_SIZE;
            break;

        // case WC_MLDSA44_BPOOL256_SHA256:
        //     ret = MLDSA44_BPOOL256_SIG_SIZE;
        //     break;
        
        // Level 3
        case WC_MLDSA65_RSAPSS3072_SHA384:
        case WC_MLDSA65_RSA3072_SHA384:
            ret = MLDSA65_RSA3072_SIG_SIZE;
            break;

        case WC_MLDSA65_RSAPSS4096_SHA384:
        case WC_MLDSA65_RSA4096_SHA384:
            ret = MLDSA65_RSA4096_SIG_SIZE;
            break;

        case WC_MLDSA65_ED25519_SHA384:
            ret = MLDSA65_ED25519_SIG_SIZE;
            break;

        case WC_MLDSA65_NISTP256_SHA384:
            ret = MLDSA65_NISTP256_SIG_SIZE;
            break;

        case WC_MLDSA65_BPOOL256_SHA384:
            ret = MLDSA65_NISTP256_SIG_SIZE;
            break;
    
        // Level 5
        case WC_MLDSA87_NISTP384_SHA384:
            ret = MLDSA87_NISTP384_SIG_SIZE;
            break;

        case WC_MLDSA87_BPOOL384_SHA384:
            ret = MLDSA87_NISTP384_SIG_SIZE;
            break;
        
        case WC_MLDSA87_ED448_SHA384:
            ret = MLDSA87_ED448_SIG_SIZE;
            break;

        case D2_WC_MLDSA44_RSA2048_SHA256:
        case D2_WC_MLDSA44_RSAPSS2048_SHA256:
        case D2_WC_MLDSA44_NISTP256_SHA256:
        // case D2_WC_MLDSA44_BPOOL256_SHA256:
        case D2_WC_MLDSA44_ED25519_SHA256:
        case D2_WC_MLDSA65_RSAPSS3072_SHA512:
        case D2_WC_MLDSA65_RSA3072_SHA512:
        case D2_WC_MLDSA65_NISTP256_SHA512:
        case D2_WC_MLDSA65_BPOOL256_SHA512:
        case D2_WC_MLDSA65_ED25519_SHA512:
        case D2_WC_MLDSA87_NISTP384_SHA512:
        case D2_WC_MLDSA87_BPOOL384_SHA512:
        case D2_WC_MLDSA87_ED448_SHA512:
            MADWOLF_DEBUG("Draft 2 signature size (GET) not supported (level: %d)", composite_level);
            return BAD_FUNC_ARG;

        case WC_MLDSA_COMPOSITE_UNDEF:
        default:
            /* Error */
            return BAD_FUNC_ARG;
    }

    return ret;
}


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
    int composite_level = 0;
    
    // Error Handling: Check for NULL pointers and invalid input lengths.
    if (key == NULL || key->mldsa_key == NULL) {
        return BAD_FUNC_ARG;
    }

    // Check the ML-DSA key
    ret = wc_dilithium_check_key(key->mldsa_key);
    if (ret != 0)
        return ret;

    composite_level = wc_mldsa_composite_level(key);
    switch(composite_level) {

#if !defined(WC_NO_RSA)
        case D2_WC_MLDSA44_RSA2048_SHA256:
        case D2_WC_MLDSA44_RSAPSS2048_SHA256:
        case WC_MLDSA44_RSA2048_SHA256:
        case WC_MLDSA44_RSAPSS2048_SHA256: {
            if (key->mldsa_key->level != WC_ML_DSA_44)
                return BAD_STATE_E;
        } break;

        case WC_MLDSA65_RSAPSS4096_SHA384:
        case WC_MLDSA65_RSA4096_SHA384:
        case WC_MLDSA65_RSAPSS3072_SHA384:
        case WC_MLDSA65_RSA3072_SHA384:
        case D2_WC_MLDSA65_RSAPSS3072_SHA512:
        case D2_WC_MLDSA65_RSA3072_SHA512: {
            if (key->mldsa_key->level != WC_ML_DSA_65)
                return BAD_STATE_E;
        } break;
#endif

#if !defined(WC_NO_ED25519)
        case D2_WC_MLDSA44_ED25519_SHA256:
        case WC_MLDSA44_ED25519_SHA256: {
            if (key->mldsa_key->level != WC_ML_DSA_44)
                return BAD_STATE_E;
            if (key->alt_key.ed25519 == NULL)
                return BAD_FUNC_ARG;
            ret = wc_ed25519_check_key(key->alt_key.ed25519);
            MADWOLF_DEBUG("Checking ED25519 key: %d", ret);
        } break;

        case D2_WC_MLDSA65_ED25519_SHA512:
        case WC_MLDSA65_ED25519_SHA384: {
            if (key->mldsa_key->level != WC_ML_DSA_65)
                return BAD_STATE_E;
            if (key->alt_key.ed25519 == NULL)
                return BAD_FUNC_ARG;
            ret = wc_ed25519_check_key(key->alt_key.ed25519);
            MADWOLF_DEBUG("Checking ED25519 key: %d", ret);
        } break;
#endif

#if !defined(WC_NO_ECC)
        case D2_WC_MLDSA44_NISTP256_SHA256:
        case WC_MLDSA44_NISTP256_SHA256: {
            if (key->alt_key.ecc == NULL)
                return BAD_FUNC_ARG;
            if (key->mldsa_key->level != WC_ML_DSA_44 ||
                    ECC_SECP256R1 != wc_ecc_get_curve_id(key->alt_key.ecc->idx)) {
                return BAD_STATE_E;
            }
            ret = wc_ecc_check_key(key->alt_key.ecc);
            MADWOLF_DEBUG("Checking ECDSA key: %d", ret);
        } break;

        case D2_WC_MLDSA65_NISTP256_SHA512:
        case WC_MLDSA65_NISTP256_SHA384: {
            if (key->alt_key.ecc == NULL)
                return BAD_FUNC_ARG;
            if (key->mldsa_key->level != WC_ML_DSA_65 ||
                        ECC_SECP256R1 != wc_ecc_get_curve_id(key->alt_key.ecc->idx)) {
                return BAD_STATE_E;
            }
            ret = wc_ecc_check_key(key->alt_key.ecc);
        } break;

        case D2_WC_MLDSA65_BPOOL256_SHA512:
        case WC_MLDSA65_BPOOL256_SHA384: {
            if (key->alt_key.ecc == NULL)
                return BAD_FUNC_ARG;
            if (key->mldsa_key->level != WC_ML_DSA_65 ||
                    ECC_BRAINPOOLP256R1 != wc_ecc_get_curve_id(key->alt_key.ecc->idx)) {
                return BAD_STATE_E;
            }
            ret = wc_ecc_check_key(key->alt_key.ecc);
        } break;

        case D2_WC_MLDSA87_NISTP384_SHA512:
        case WC_MLDSA87_NISTP384_SHA384: {
            if (key->alt_key.ecc == NULL)
                return BAD_FUNC_ARG;
            if (key->mldsa_key->level != WC_ML_DSA_87 ||
                    ECC_SECP384R1 != wc_ecc_get_curve_id(key->alt_key.ecc->idx)) {
                return BAD_STATE_E;
            }
            ret = wc_ecc_check_key(key->alt_key.ecc);
        } break;

        case D2_WC_MLDSA87_BPOOL384_SHA512:
        case WC_MLDSA87_BPOOL384_SHA384: {
            if (key->alt_key.ecc == NULL)
                return BAD_FUNC_ARG;
            if (key->mldsa_key->level != WC_ML_DSA_87 ||
                    ECC_BRAINPOOLP384R1 != wc_ecc_get_curve_id(key->alt_key.ecc->idx)) {
                return BAD_STATE_E;
            }
            ret = wc_ecc_check_key(key->alt_key.ecc);
        } break;
#endif

#if !defined(WC_NO_ED448)
        case D2_WC_MLDSA87_ED448_SHA512:
        case WC_MLDSA87_ED448_SHA384: {
            if (key->alt_key.ed448 == NULL)
                return BAD_FUNC_ARG;
            if (key->mldsa_key->level != WC_ML_DSA_87)
                return BAD_STATE_E;
            ret = wc_ed448_check_key(key->alt_key.ed448);
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

int wc_mldsa_composite_import_public(const byte* inBuffer, word32 inLen, 
        mldsa_composite_key* key, enum mldsa_composite_level comp_level)
{
    int ret = 0;
        // Ret value

    word32 idx = 0;
        // Index for the ASN.1 data
        
    ASNItem compPubKeyIT[mldsaCompASN_Length] = {
         { 0, ASN_SEQUENCE, 1, 1, 0 },
            { 1, ASN_OCTET_STRING, 0, 0, 0 },
            { 1, ASN_OCTET_STRING, 0, 0, 0 }
    };
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
    if ((ret = GetASN_Items(compPubKeyIT, compPubKeyASN, 3, 0, inBuffer, &idx, inLen)) < 0) {
        MADWOLF_DEBUG("Error while parsing ASN.1 (%d)", ret);
        FILE *fp = fopen("mldsa_composite_import_public_error.bin", "wb");
        if (fp) {
            fwrite(inBuffer, 1, inLen, fp);
            fclose(fp);
        }
        return ret;
    }

    // If no passed type, let's check the key type
    if (comp_level == 0) comp_level = wc_mldsa_composite_level(key);

    // Free the ML-DSA key
    if (key->mldsa_key) {
        wc_dilithium_free(key->mldsa_key);
        key->mldsa_key = NULL;
    }
    // Allocates the memory
    if ((key->mldsa_key = (dilithium_key*)XMALLOC(sizeof(dilithium_key), NULL, DYNAMIC_TYPE_DILITHIUM)) == NULL) {
        MADWOLF_DEBUG0("failed to allocate ML-DSA component");
        return MEMORY_E;
    }
    // Initialize the ML-DSA key
    if ((ret = wc_dilithium_init(key->mldsa_key)) < 0) {
        MADWOLF_DEBUG("failed to initialize ML-DSA component (key: %p, code %d)", key->mldsa_key, ret);
        XFREE(key->mldsa_key, key->heap, DYNAMIC_TYPE_DILITHIUM);
        key->mldsa_key = NULL;
        return ret;
    }

    // Import the ML-DSA public key
    switch(comp_level) {
            
            // Level 1
            case D2_WC_MLDSA44_RSAPSS2048_SHA256:
            case D2_WC_MLDSA44_RSA2048_SHA256:
            case D2_WC_MLDSA44_ED25519_SHA256:
            // case WC_MLDSA44_BPOOL256_SHA256: {
            case D2_WC_MLDSA44_NISTP256_SHA256:
            case WC_MLDSA44_RSA2048_SHA256:
            case WC_MLDSA44_RSAPSS2048_SHA256:
            case WC_MLDSA44_ED25519_SHA256:
            case WC_MLDSA44_NISTP256_SHA256: {
                ret = wc_dilithium_set_level(key->mldsa_key, WC_ML_DSA_44);
                // key->mldsa_key->level = WC_ML_DSA_44;
            } break;

            // Level 3
            case D2_WC_MLDSA65_RSAPSS3072_SHA512:
            case D2_WC_MLDSA65_RSA3072_SHA512:
            case D2_WC_MLDSA65_ED25519_SHA512:
            case D2_WC_MLDSA65_NISTP256_SHA512:
            case D2_WC_MLDSA65_BPOOL256_SHA512:
            case WC_MLDSA65_RSAPSS3072_SHA384:
            case WC_MLDSA65_RSA3072_SHA384:
            case WC_MLDSA65_RSAPSS4096_SHA384:
            case WC_MLDSA65_RSA4096_SHA384:
            case WC_MLDSA65_ED25519_SHA384:
            case WC_MLDSA65_NISTP256_SHA384:
            case WC_MLDSA65_BPOOL256_SHA384: {
                ret = wc_dilithium_set_level(key->mldsa_key, WC_ML_DSA_65);
                // key->mldsa_key->level = WC_ML_DSA_65;
            } break;

            // Level 5
            case D2_WC_MLDSA87_NISTP384_SHA512:
            case D2_WC_MLDSA87_BPOOL384_SHA512:
            case D2_WC_MLDSA87_ED448_SHA512:
            case WC_MLDSA87_NISTP384_SHA384:
            case WC_MLDSA87_BPOOL384_SHA384:
            case WC_MLDSA87_ED448_SHA384: {
                ret = wc_dilithium_set_level(key->mldsa_key, WC_ML_DSA_87);
                // key->mldsa_key->level = WC_ML_DSA_87;
            } break;

            case WC_MLDSA_COMPOSITE_UNDEF:
            default:
                XFREE(key->mldsa_key, key->heap, DYNAMIC_TYPE_DILITHIUM);
                key->mldsa_key = NULL;
                return BAD_FUNC_ARG;
    }

    // Resets the index
    idx = 0;

    // Import ML-DSA Component
    if ((ret = wc_dilithium_import_public(mldsa_Buffer, mldsa_BufferLen, key->mldsa_key)) < 0) {
        MADWOLF_DEBUG("failed to import ML-DSA-44 component with code %d", ret);
        return ret;
    }

   // Verify Individual Key Components: 
    switch (comp_level) {

        case D2_WC_MLDSA44_RSAPSS2048_SHA256:
        case D2_WC_MLDSA44_RSA2048_SHA256:
        case D2_WC_MLDSA65_RSAPSS3072_SHA512:
        case D2_WC_MLDSA65_RSA3072_SHA512:
        case WC_MLDSA44_RSAPSS2048_SHA256:
        case WC_MLDSA44_RSA2048_SHA256:
        case WC_MLDSA65_RSAPSS3072_SHA384:
        case WC_MLDSA65_RSA3072_SHA384:
        case WC_MLDSA65_RSAPSS4096_SHA384:
        case WC_MLDSA65_RSA4096_SHA384: {
            MADWOLF_DEBUG0("ML-DSA COMPOSITE: RSA public key import");
            // Checks the RSA pubkey buffer size
            if (other_BufferLen < RSA2048_PUB_KEY_SIZE) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: RSA public key size error (%d vs. %d)", other_BufferLen, RSA2048_PUB_KEY_SIZE);
                return BUFFER_E;
            }
            // if a key is present, free it
            if (key->alt_key.rsa) {
                wc_FreeRsaKey(key->alt_key.rsa);
                key->alt_key.rsa = NULL;
            }
            // Allocates the memory, if needed
            if ((key->alt_key.rsa = (RsaKey*)XMALLOC(sizeof(RsaKey), NULL, DYNAMIC_TYPE_RSA)) == NULL) {
                MADWOLF_DEBUG0("ML-DSA COMPOSITE: failed to allocate RSA component");
                return MEMORY_E;
            }
            // Import RSA Component
            if ((ret = wc_InitRsaKey(key->alt_key.rsa, NULL)) < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: failed to initialize RSA component (key: %p, code %d)", key->alt_key.rsa, ret);
                return ret;
            }
            if ((ret = wc_RsaPublicKeyDecode(other_Buffer, &idx, key->alt_key.rsa, other_BufferLen)) < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: failed to import RSA component with code %d", ret);
                return ret;
            }
            MADWOLF_DEBUG("ML-DSA COMPOSITE: RSA public key imported successfully (idx=%d)", idx);
        } break;

        case D2_WC_MLDSA65_BPOOL256_SHA512:
        case WC_MLDSA65_BPOOL256_SHA384:
        case D2_WC_MLDSA65_NISTP256_SHA512:
        case WC_MLDSA65_NISTP256_SHA384:
        case D2_WC_MLDSA44_NISTP256_SHA256:
        case WC_MLDSA44_NISTP256_SHA256: {
            int curveId = 0;
            int curveSz = 0;

            MADWOLF_DEBUG0("ML-DSA COMPOSITE: ECDSA public key import");
            // Free the ECC key, if any is present
            if (key->alt_key.ecc) {
                wc_ecc_free(key->alt_key.ecc);
                key->alt_key.ecc = NULL;
            }
            // Allocates the memory, if needed
            if ((key->alt_key.ecc = (ecc_key*)XMALLOC(sizeof(ecc_key), NULL, DYNAMIC_TYPE_ECC)) == NULL) {
                MADWOLF_DEBUG0("ML-DSA COMPOSITE: failed to allocate ECDSA component");
                return MEMORY_E;
            }
            XMEMSET(key->alt_key.ecc, 0, sizeof(ecc_key));
            if (wc_ecc_init(key->alt_key.ecc) < 0) {
                MADWOLF_DEBUG0("ML-DSA COMPOSITE: failed to initialize ECDSA component");
                XFREE(key->alt_key.ecc, NULL, DYNAMIC_TYPE_ECC);
                key->alt_key.ecc = NULL;
                return MEMORY_E;
            }

            // Gets the right curveId and curveSz
            if (comp_level == D2_WC_MLDSA65_BPOOL256_SHA512
                || comp_level == WC_MLDSA65_BPOOL256_SHA384) {
                curveId = ECC_BRAINPOOLP256R1;
                curveSz = wc_ecc_get_curve_size_from_id(curveId);
            } else {
                curveId = ECC_SECP256R1;
                curveSz = wc_ecc_get_curve_size_from_id(curveId);
            }
            if ((ret = wc_ecc_import_unsigned(key->alt_key.ecc, 
                    other_Buffer, other_Buffer + curveSz, NULL, curveId)) < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: ECDSA import PubKey failed with %d (curveId: %d, curveSz: %d)", ret, curveId, curveSz);
                return ret;
            }
        } break;

        // case D2_WC_MLDSA65_RSAPSS3072_SHA512:
        // case D2_WC_MLDSA65_RSA3072_SHA512:
        // case WC_MLDSA65_RSAPSS4096_SHA384:
        // case WC_MLDSA65_RSA4096_SHA384:
        // case WC_MLDSA65_RSAPSS3072_SHA384:
        // case WC_MLDSA65_RSA3072_SHA384: {
        //     MADWOLF_DEBUG0("ML-DSA COMPOSITE: RSA public key import");
        //     // Checks the RSA pubkey buffer size
        //     if ((type == WC_MLDSA65_RSAPSS3072_SHA384 || type == WC_MLDSA65_RSA3072_SHA384) 
        //             && (other_BufferLen < RSA3072_PUB_KEY_SIZE)) {
        //         MADWOLF_DEBUG("ML-DSA COMPOSITE: RSA public key size error (%d vs. %d)", other_BufferLen, RSA3072_PUB_KEY_SIZE);
        //         return BUFFER_E;
        //     } else if ((type == WC_MLDSA65_RSAPSS4096_SHA384 || type == WC_MLDSA65_RSA4096_SHA384) 
        //             && (other_BufferLen < RSA4096_PUB_KEY_SIZE)) {
        //         MADWOLF_DEBUG("ML-DSA COMPOSITE: RSA public key size error (%d vs. %d)", other_BufferLen, RSA4096_PUB_KEY_SIZE);
        //         return BUFFER_E;
        //     }

        //     // Frees the RSA key, if any is present
        //     if (key->alt_key.rsa) {
        //         wc_FreeRsaKey(key->alt_key.rsa);
        //         key->alt_key.rsa = NULL;
        //     }

        //     // Allocates the memory, if needed
        //     if ((key->alt_key.rsa = (RsaKey*)XMALLOC(sizeof(RsaKey), NULL, DYNAMIC_TYPE_RSA)) == NULL) {
        //         MADWOLF_DEBUG0("ML-DSA COMPOSITE: failed to allocate RSA component");
        //         return MEMORY_E;
        //     }
        //     // Import RSA Component
        //     if ((ret = wc_InitRsaKey(key->alt_key.rsa, key->heap)) < 0) {
        //         MADWOLF_DEBUG("ML-DSA COMPOSITE: failed to import RSA component with code %d", ret);
        //         return ret;
        //     }
        //     if ((ret = wc_RsaPublicKeyDecode(other_Buffer, &idx, key->alt_key.rsa, other_BufferLen)) < 0) {
        //         MADWOLF_DEBUG("ML-DSA COMPOSITE: failed to import RSA component with code %d", ret);
        //         return ret;
        //     }
        //     if (type == WC_MLDSA65_RSAPSS3072_SHA384 || type == WC_MLDSA65_RSA3072_SHA384) {
        //         if ((ret = wc_RsaEncryptSize(key->alt_key.rsa)) != RSA3072_SIG_SIZE) {
        //             MADWOLF_DEBUG("ML-DSA COMPOSITE: RSA component size error (%d vs. %d)", ret, RSA3072_SIG_SIZE);
        //             return ret;
        //         }
        //     } else {
        //         if ((ret = wc_RsaEncryptSize(key->alt_key.rsa)) != RSA4096_SIG_SIZE) {
        //             MADWOLF_DEBUG("ML-DSA COMPOSITE: RSA component size error (%d vs. %d)", ret, RSA4096_SIG_SIZE);
        //             return ret;
        //         }
        //     }
        // } break;

        case D2_WC_MLDSA44_ED25519_SHA256:
        case WC_MLDSA44_ED25519_SHA256:
        case D2_WC_MLDSA65_ED25519_SHA512:
        case WC_MLDSA65_ED25519_SHA384: {
            
            // Cehcks the ED25519 pubkey buffer size
            if (other_BufferLen != ED25519_PUB_KEY_SIZE) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: ED25519 public key size error (%d vs. %d)", other_BufferLen, ED25519_PUB_KEY_SIZE);
                return BUFFER_E;
            }

            // If a key is present, let's free it
            if (key->alt_key.ed25519) {
                wc_ed25519_free(key->alt_key.ed25519);
                key->alt_key.ed25519 = NULL;
            }

            // Allocates the memory, if needed
            if ((key->alt_key.ed25519 = (ed25519_key*)XMALLOC(sizeof(ed25519_key), NULL, DYNAMIC_TYPE_ED25519)) == NULL) {
                MADWOLF_DEBUG0("ML-DSA COMPOSITE: failed to allocate ED25519 component");
                return MEMORY_E;
            }

            // Import ED25519 Component
            XMEMSET(key->alt_key.ed25519, 0, sizeof(ed25519_key));

            // Initializes the key
            if ((ret = wc_ed25519_init_ex(key->alt_key.ed25519, key->heap, key->devId)) < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: failed to initialize ED25519 component with code %d", ret);
                XFREE(key->alt_key.ed25519, key->heap, DYNAMIC_TYPE_ED25519);
                key->alt_key.ed25519 = NULL;
                return ret;
            }

            // Import ED25519 Component
            if ((ret = wc_ed25519_import_public(other_Buffer, other_BufferLen, key->alt_key.ed25519)) < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: failed to import ED25519 component with code %d", ret);
                XFREE(key->alt_key.ed25519, key->heap, DYNAMIC_TYPE_ED25519);
                key->alt_key.ed25519 = NULL;
                return ret;
            }

        } break;

        case D2_WC_MLDSA87_NISTP384_SHA512:
        case D2_WC_MLDSA87_BPOOL384_SHA512:
        case WC_MLDSA87_NISTP384_SHA384:
        case WC_MLDSA87_BPOOL384_SHA384: {
            int curveSz = 0;
            int curveId = ECC_SECP384R1;
                // Default curveId

            // Gets the Brainpool curveId, if needed
            if (comp_level == D2_WC_MLDSA87_BPOOL384_SHA512 
                || comp_level == WC_MLDSA87_BPOOL384_SHA384) {
                // Brainpool384r1 curve
                curveId = ECC_BRAINPOOLP384R1;
            }

            // Gets the curve size
            curveSz = wc_ecc_get_curve_size_from_id(curveId);
            if (curveSz <= 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: ECDSA curve size error (%d)", curveSz);
                return BAD_STATE_E;
            }

            // If a ecc key is present, let's free it
            if (key->alt_key.ecc) {
                wc_ecc_free(key->alt_key.ecc);
                key->alt_key.ecc = NULL;
            }
            // Allocates the memory
            if ((key->alt_key.ecc = (ecc_key*)XMALLOC(sizeof(ecc_key), NULL, DYNAMIC_TYPE_ECC)) == NULL) {
                MADWOLF_DEBUG0("ML-DSA COMPOSITE: failed to allocate ECDSA component");
                return MEMORY_E;
            }
            // Initializes the key
            XMEMSET(key->alt_key.ecc, 0, sizeof(ecc_key));
            if (wc_ecc_init(key->alt_key.ecc) < 0) {
                MADWOLF_DEBUG0("ML-DSA COMPOSITE: failed to initialize ECDSA component");
                XFREE(key->alt_key.ecc, NULL, DYNAMIC_TYPE_ECC);
                key->alt_key.ecc = NULL;
                return MEMORY_E;
            }

            // Import ECDSA Component
            if ((ret = wc_ecc_import_unsigned(key->alt_key.ecc, 
                    other_Buffer, other_Buffer + curveSz, NULL, curveId)) < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: ECDSA import PubKey failed with %d", ret);
                return ret;
            }
            // // Checks the ECDSA curve (P-384)
            // if (wc_ecc_get_curve_id(key->alt_key.ecc->idx) != ECC_BRAINPOOLP384R1) {
            //     MADWOLF_DEBUG("ML-DSA COMPOSITE: ECDSA import PubKey curve error (%d vs. %d)", key->alt_key.ecc->dp->id, ECC_BRAINPOOLP384R1);
            //     return BAD_STATE_E;
            // }
        } break;

        case D2_WC_MLDSA87_ED448_SHA512:
        case WC_MLDSA87_ED448_SHA384: {
            MADWOLF_DEBUG0("ML-DSA COMPOSITE: ED448 public key import");
            // Checks the ED448 pubkey buffer size
            if (other_BufferLen != ED448_PUB_KEY_SIZE) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: ED448 public key size error (%d vs. %d)", other_BufferLen, ED448_PUB_KEY_SIZE);
                goto err;
            }
            // Frees the ED448 key, if any is present
            if (key->alt_key.ed448) {
                wc_ed448_free(key->alt_key.ed448);
                key->alt_key.ed448 = NULL;
            }
            // Allocates the memory
            if ((key->alt_key.ed448 = (ed448_key*)XMALLOC(sizeof(ed448_key), NULL, DYNAMIC_TYPE_ED448)) == NULL) {
                MADWOLF_DEBUG0("ML-DSA COMPOSITE: failed to allocate ED448 component");
                goto err;
            }
            // Initializes the ED448 Component
            XMEMSET(key->alt_key.ed448, 0, sizeof(ed448_key));
            if ((ret = wc_ed448_init_ex(key->alt_key.ed448, key->heap, key->devId)) < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: failed to initialize ED448 component with code %d", ret);
                goto err;
            }
            // Import ED448 Component
            if ((ret = wc_ed448_import_public(other_Buffer, other_BufferLen, key->alt_key.ed448)) < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: failed to import ED448 component with code %d", ret);
                goto err;
            }
        } break;

        case WC_MLDSA_COMPOSITE_UNDEF:
        default:
            MADWOLF_DEBUG("Unsupported ML-DSA Composite Type: %d", comp_level);
            return BAD_FUNC_ARG;
    }

    // If here, we have successfully imported the public key
    ret = 0;

    // Set the type of key
    key->type = wc_mldsa_composite_level_type(comp_level);

    // Set the public key set flag
    key->pubKeySet = 1;

    return ret;

err:

    // Free the ML-DSA key
    if (key->mldsa_key) {
        wc_dilithium_free(key->mldsa_key);
        key->mldsa_key = NULL;
    }
    // Free the RSA key
    if (key->alt_key.rsa) {
        wc_FreeRsaKey(key->alt_key.rsa);
        key->alt_key.rsa = NULL;
    }

    // Free the ED25519 key
    if (key->alt_key.ed25519) {
        wc_ed25519_free(key->alt_key.ed25519);
        key->alt_key.ed25519 = NULL;
    }

    // Free the ECC key
    if (key->alt_key.ecc) {
        wc_ecc_free(key->alt_key.ecc);
        key->alt_key.ecc = NULL;
    }

    // Free the ED448 key
    if (key->alt_key.ed448) {
        wc_ed448_free(key->alt_key.ed448);
        key->alt_key.ed448 = NULL;
    }

    return ret;
}

int wc_mldsa_composite_export_public(mldsa_composite_key* key, byte* out, word32* outLen)
{
    int ret = 0;
    word32 inLen;

    const ASNItem compositeIT[] = {
    /*  SEQ */    { 0, ASN_SEQUENCE, 1, 1, 0 },
    /*  ML-DSA */   { 1, ASN_OCTET_STRING, 0, 0, 0 },
    /*  Trad */     { 1, ASN_OCTET_STRING, 0, 0, 0 },
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
    if ((key == NULL) || (outLen == NULL)) {
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
    if (!out) {
        return 0;
    }
    if (inLen < *outLen) {
        MADWOLF_DEBUG("Output Public Key Buffer too small (needed: %d, provided: %d)", *outLen, inLen);
        return BUFFER_E;
    }
    if (inLen < *outLen) {
        MADWOLF_DEBUG("Output Public Key Buffer too small (needed: %d, provided: %d)", *outLen, inLen);
        return BAD_FUNC_ARG;
    }

    /* Exports the ML-DSA key */
    if ((ret = wc_MlDsaKey_ExportPubRaw(key->mldsa_key, mldsa_Buffer, &mldsa_BufferLen)) < 0) {
        WOLFSSL_MSG_VSNPRINTF("error cannot export ML-DSA component's public key\n");
        return ret;
    }

    /* Exports the other key */
    switch (key->type) {

        // RSA
        case D2_MLDSA44_RSAPSS2048_SHA256_TYPE:
        case D2_MLDSA44_RSA2048_SHA256_TYPE:
        // case D2_WC_MLDSA44_BPOOL256_SHA256:
        case D2_MLDSA65_RSAPSS3072_SHA512_TYPE:
        case D2_MLDSA65_RSA3072_SHA512_TYPE:

        case MLDSA44_RSAPSS2048_TYPE:
        case MLDSA44_RSA2048_TYPE:
        case MLDSA65_RSAPSS3072_TYPE:
        case MLDSA65_RSA3072_TYPE:
        case MLDSA65_RSAPSS4096_TYPE:
        case MLDSA65_RSA4096_TYPE: {
            if ((ret = wc_RsaPublicKeyDerSize(key->alt_key.rsa, 0)) < 0) {
                return ret;
            }
            if ((ret = wc_RsaKeyToPublicDer_ex(key->alt_key.rsa, other_Buffer, other_BufferLen, 0)) < 0) {
                return ret;
            }
            other_BufferLen = ret;
            ret = 0;
        } break;

        // ED25519
        case D2_MLDSA44_ED25519_SHA256_TYPE:
        case D2_MLDSA65_ED25519_SHA512_TYPE:
        case MLDSA44_ED25519_TYPE:
        case MLDSA65_ED25519_TYPE: {
            if ((ret = wc_ed25519_export_public(key->alt_key.ed25519, 
                    other_Buffer, &other_BufferLen)) < 0) {
                return ret;
            }
        } break;

        // ECDSA (P-256)
        case D2_MLDSA65_NISTP256_SHA512_TYPE:
        case D2_MLDSA44_NISTP256_SHA256_TYPE:
        case MLDSA44_NISTP256_TYPE:
        case MLDSA65_NISTP256_TYPE: {
            if ((ret = wc_ecc_export_x963_ex(key->alt_key.ecc, other_Buffer, &other_BufferLen, ECC_SECP256R1)) < 0) {
                return ret;
            }
        } break;

        // case WC_MLDSA44_BPOOL256_SHA256: {
        //     // word32 pubLenX = 32, pubLenY = 32;
        //     // if ((ret = wc_ecc_export_public_raw(key->alt_key.ecc, 
        //     //         other_Buffer, &pubLenX, &other_Buffer[32], &pubLenY)) < 0) {
        //     //     return ret;
        //     // }
        //     // other_BufferLen = pubLenX + pubLenY;
        //     if ((ret = wc_ecc_export_x963_ex(key->alt_key.ecc, other_Buffer, &other_BufferLen, 0)) < 0) {
        //         return ret;
        //     }
        // } break;

        // case WC_MLDSA65_RSAPSS3072_SHA384:
        // case WC_MLDSA65_RSA3072_SHA384:
        // case WC_MLDSA65_RSAPSS4096_SHA384:
        // case WC_MLDSA65_RSA4096_SHA384: {
        //     if ((ret = wc_RsaPublicKeyDerSize(key->alt_key.rsa, 0)) < 0) {
        //         return ret;
        //     }
        //     if ((ret = wc_RsaKeyToPublicDer_ex(key->alt_key.rsa, 
        //             other_Buffer, other_BufferLen, 0)) < 0) {
        //         return ret;
        //     }
        //     other_BufferLen = ret;
        //     ret = 0;
        // } break;

        // case WC_MLDSA65_ED25519_SHA384: {
        //     if ((ret = wc_ed25519_export_public(key->alt_key.ed25519, 
        //             other_Buffer, &other_BufferLen)) < 0) {
        //         return ret;
        //     }
        // } break;

        // ECDSA (BPOOL-256)
        case D2_MLDSA65_BPOOL256_SHA512_TYPE:
        case MLDSA65_BPOOL256_TYPE: {
            if ((ret = wc_ecc_export_x963_ex(key->alt_key.ecc, other_Buffer, &other_BufferLen, ECC_BRAINPOOLP256R1)) < 0) {
                return ret;
            }
        } break;

        // ECDSA (P-384)
        case D2_MLDSA87_NISTP384_SHA512_TYPE:
        case MLDSA87_NISTP384_TYPE: {
            if ((ret = wc_ecc_export_x963_ex(key->alt_key.ecc, other_Buffer, &other_BufferLen, ECC_SECP384R1)) < 0) {
                return ret;
            }
        } break;

        // ECDSA (BPOOL-384)
        case D2_MLDSA87_BPOOL384_SHA512_TYPE:
        case MLDSA87_BPOOL384_TYPE: {
            if ((ret = wc_ecc_export_x963_ex(key->alt_key.ecc, other_Buffer, &other_BufferLen, ECC_BRAINPOOLP384R1)) < 0) {
                return ret;
            }
        } break;

        // ED448
        case D2_MLDSA87_ED448_SHA512_TYPE:
        case MLDSA87_ED448_TYPE: {
            if ((ret = wc_ed448_export_public(key->alt_key.ed448, 
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

int wc_mldsa_composite_import_private(const byte                * priv, 
                                      word32                      privSz,
                                      mldsa_composite_key       * key,
                                      enum mldsa_composite_level  level)
{
    int ret = 0;
        // Ret value

    word32 idx = 0;
    // word32 algorSum = 0;
        // Index for the ASN.1 data

    byte * keyBuffer = NULL;
        // Buffer to hold the Key Data

    byte mldsa_Buffer[DILITHIUM_ML_DSA_87_PRV_KEY_SIZE];
    word32 mldsa_BufferLen = DILITHIUM_ML_DSA_87_PRV_KEY_SIZE;
        // Buffer to hold the ML-DSA public key

    byte other_Buffer[MLDSA_COMPOSITE_MAX_OTHER_KEY_SZ];
    word32 other_BufferLen = MLDSA_COMPOSITE_MAX_OTHER_KEY_SZ;
        // Buffer to hold the public key of the other DSA component

    // Input checks
    if (!priv || privSz <= 0 || !key || level <= 0) {
        return BAD_FUNC_ARG;
    }

    // Allocates a local copy of the key buffer
    keyBuffer = XMALLOC(privSz, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
    if (!keyBuffer) {
        return MEMORY_E;
    }
    if (XMEMCPY(keyBuffer, priv, privSz) == NULL) {
        return MEMORY_E;
    }

    // // Removes the PKCS8 header
    // if ((ret = ToTraditional_ex(keyBuffer, privSz, &algorSum)) > 0) {
    //     privSz = ret;
    //     // Saves the result in the OID
    //     word32 pkcs8_type = wc_KeySum_to_composite_level(algorSum);
    //     if (type > 0 && type != pkcs8_type) {
    //         MADWOLF_DEBUG("Key type mismatch (%d vs. %d)", type, pkcs8_type);
    //         ret = BAD_FUNC_ARG;
    //         goto err;
    //     }
 
    //     word32 stringSz = 0;
    //     ASNGetData octetStringData[1];
    //     ASNItem dataIT = { 0, ASN_OCTET_STRING, 0, 1, 0 };
    //     GetASN_Buffer(&octetStringData[0], NULL, &stringSz);
    //     if ((ret = GetASN_Items(&dataIT, octetStringData, 1, 0, NULL, &idx, privSz)) < 0) {
    //         MADWOLF_DEBUG("Error while parsing ASN.1 (%d, privSz: %d, idx: %d, type: %d)", ret, privSz, idx, type);
    //         goto err;
    //     }
    // }

    // Parse the ASN.1 data
    if (level == D2_WC_MLDSA44_RSAPSS2048_SHA256
        || level == D2_WC_MLDSA44_RSA2048_SHA256
        || level == D2_WC_MLDSA44_ED25519_SHA256
        || level == D2_WC_MLDSA44_NISTP256_SHA256
        // || type == D2_WC_MLDSA44_BPOOL256_SHA256
        || level == D2_WC_MLDSA65_RSAPSS3072_SHA512
        || level == D2_WC_MLDSA65_RSA3072_SHA512
        || level == D2_WC_MLDSA65_ED25519_SHA512
        || level == D2_WC_MLDSA65_NISTP256_SHA512
        || level == D2_WC_MLDSA65_BPOOL256_SHA512
        || level == D2_WC_MLDSA87_NISTP384_SHA512
        || level == D2_WC_MLDSA87_BPOOL384_SHA512
        || level == D2_WC_MLDSA87_ED448_SHA512) {

            // --------- Draft 2 --------------- //
            //
            // This approach works but does not use the ASN template
            // code because of the impossibility to convince the ASN
            // code to retain the outer sequence tag.

            int seqLen = 0;
            byte const * dataPnt = priv;
            int dataLen = privSz;

            // Checks we have a sequence that spans all the buffer
            idx = 0;
            if ((ret = GetSequence(dataPnt, &idx, &seqLen, privSz)) <= 0 || ret != (int)(privSz - idx)) {
                goto err;
            }
            dataPnt += idx;
            dataLen -= idx;

            // Gets the boundary for the ML-DSA key
            idx = 0;
            ret = GetSequence(dataPnt, &idx, &seqLen, dataLen);
            if (ret <= 0) {
                MADWOLF_DEBUG("Error while parsing ASN.1 (%d, privSz: %d, idx: %d, level: %d, type: %d)", ret, privSz, idx, level, key->type);
                goto err;
            }
            mldsa_BufferLen = idx + seqLen;
            XMEMCPY(mldsa_Buffer, dataPnt, dataLen);

            dataPnt += mldsa_BufferLen;
            dataLen -= mldsa_BufferLen;

            // Gets the boundary for the other key
            idx = 0;
            ret = GetSequence(dataPnt, &idx, &seqLen, dataLen);
            if (ret <= 0) {
                MADWOLF_DEBUG("Error while parsing ASN.1 (%d, privSz: %d, idx: %d, level: %d, type: %d)", ret, privSz, idx, level, key->type);
                goto err;
            }
            other_BufferLen = idx + seqLen;
            XMEMCPY(other_Buffer, dataPnt, dataLen);

            // --------- Dreaft 2 --------------- //
            // 
            // The default approach would be to use the usual code for the GetASN_Items(), however
            // the current implementation leaves the two sequences at depth 1 without the outer sequence
            // tag. This is a bug in the current implementation of wolfSSL.
            
            // ASNItem compPrivKeyIT[3] = {
            //     { 0, ASN_SEQUENCE, 1, 1, 0 },
            //         { 1, ASN_SEQUENCE, 1, 0, 0 },
            //         { 1, ASN_SEQUENCE, 1, 0, 0 },
            // };
            //     // ASN.1 items for the composite private key

            // ASNGetData compPrivKeyASN[3];
            //         // ASN.1 data for the composite signature

            // // Sets the buffers to 0
            // XMEMSET(compPrivKeyASN, 0, sizeof(*compPrivKeyASN) * 3);

            // // Initialize the ASN data
            // GetASN_Buffer(&compPrivKeyASN[1], mldsa_Buffer + 4, &mldsa_BufferLen);
            // GetASN_Buffer(&compPrivKeyASN[2], other_Buffer + 4, &other_BufferLen);

            // // -------- Draft 3 (D3) ML-DSA Private Key - SEQ of OCTET STRING ------- //
            // if ((ret = GetASN_Items(compPrivKeyIT, compPrivKeyASN, 3, 0, keyBuffer, &idx, privSz)) < 0) {
            //     MADWOLF_DEBUG("Error while parsing ASN.1 (%d, privSz: %d, idx: %d, type: %d)", ret, privSz, idx, type);
            //     goto err;
            // }

            // ret = SetSequence(mldsa_BufferLen, mldsa_Buffer);
            // if (ret != 4) {
            //     MADWOLF_DEBUG("Wrong number of written bytes for the SEQ (%d vs. 4)", ret);
            //     goto err;
            // }
            // mldsa_BufferLen += ret;

            // ret = SetSequence(other_BufferLen, other_Buffer);
            // if (ret != 4) {
            //     MADWOLF_DEBUG("Wrong number of written bytes for the SEQ (%d vs. 4)", ret);
            //     goto err;
            // }
            // other_BufferLen += ret;

    } else {

        ASNItem compPrivKeyIT[3] = {
            { 0, ASN_SEQUENCE, 1, 1, 0 },
                { 1, ASN_OCTET_STRING, 1, 0, 0 },
                { 1, ASN_OCTET_STRING, 1, 0, 0 },
        };
            // ASN.1 items for the composite private key

        ASNGetData compPrivKeyASN[3];
                // ASN.1 data for the composite signature

        // Sets the buffers to 0
        XMEMSET(compPrivKeyASN, 0, sizeof(*compPrivKeyASN) * 3);

        // Initialize the ASN data
        GetASN_Buffer(&compPrivKeyASN[1], mldsa_Buffer, &mldsa_BufferLen);
        GetASN_Buffer(&compPrivKeyASN[2], other_Buffer, &other_BufferLen);

        // -------- Draft 3 (D3) ML-DSA Private Key - SEQ of OCTET STRING ------- //
        if ((ret = GetASN_Items(compPrivKeyIT, compPrivKeyASN, 3, 0, keyBuffer, &idx, privSz)) < 0) {
            MADWOLF_DEBUG("Error while parsing ASN.1 (%d, privSz: %d, idx: %d, type: %d)", ret, privSz, idx, level);
            goto err;
        }
    }

    // If no passed type, let's check the key type
    if (level <= 0) level = wc_mldsa_composite_level(key);

    idx = mldsa_BufferLen;

    // Allocate the ML-DSA key
    if (key->mldsa_key) {
        wc_dilithium_free(key->mldsa_key);
        key->mldsa_key = NULL;
    }

    // Allocates the memory
    key->mldsa_key = ((dilithium_key*)XMALLOC(sizeof(dilithium_key), key->heap, DYNAMIC_TYPE_DILITHIUM));
    if (!key->mldsa_key) {
        ret = MEMORY_E;
        goto err;
    }

    // Initializes the ML-DSA key
    if ((ret = wc_dilithium_init(key->mldsa_key)) < 0) {
        MADWOLF_DEBUG("failed to init ML-DSA component with code %d", ret);
        goto err;
    }

    // Import the ML-DSA private key 
    switch (level) {

        case D2_WC_MLDSA44_RSAPSS2048_SHA256:
        case D2_WC_MLDSA44_RSA2048_SHA256:
        case D2_WC_MLDSA44_ED25519_SHA256:
        // case D2_WC_MLDSA44_BPOOL256_SHA256:
        case D2_WC_MLDSA44_NISTP256_SHA256:
        case WC_MLDSA44_RSA2048_SHA256:
        case WC_MLDSA44_RSAPSS2048_SHA256:
        case WC_MLDSA44_ED25519_SHA256:
        // case WC_MLDSA44_BPOOL256_SHA256:
        case WC_MLDSA44_NISTP256_SHA256: {
            // Sets the ML-DSA level
            ret = wc_dilithium_set_level(key->mldsa_key, WC_ML_DSA_44);
        } break;

        case D2_WC_MLDSA65_RSAPSS3072_SHA512:
        case D2_WC_MLDSA65_RSA3072_SHA512:
        case D2_WC_MLDSA65_ED25519_SHA512:
        case D2_WC_MLDSA65_NISTP256_SHA512:
        case D2_WC_MLDSA65_BPOOL256_SHA512:
        case WC_MLDSA65_RSAPSS3072_SHA384:
        case WC_MLDSA65_RSA3072_SHA384:
        case WC_MLDSA65_RSAPSS4096_SHA384:
        case WC_MLDSA65_RSA4096_SHA384:
        case WC_MLDSA65_ED25519_SHA384:
        case WC_MLDSA65_NISTP256_SHA384:
        case WC_MLDSA65_BPOOL256_SHA384: {
            // Sets the ML-DSA level
            ret = wc_dilithium_set_level(key->mldsa_key, WC_ML_DSA_65);
         } break;

        case D2_WC_MLDSA87_BPOOL384_SHA512:
        case D2_WC_MLDSA87_NISTP384_SHA512:
        case D2_WC_MLDSA87_ED448_SHA512:
        case WC_MLDSA87_NISTP384_SHA384:
        case WC_MLDSA87_BPOOL384_SHA384:
        case WC_MLDSA87_ED448_SHA384: {
            // Sets the ML-DSA level
            ret = wc_dilithium_set_level(key->mldsa_key, WC_ML_DSA_87);
        } break;

        case WC_MLDSA_COMPOSITE_UNDEF:
        default:
            return BAD_FUNC_ARG;
    }

    if (ret < 0) {
        MADWOLF_DEBUG("failed to set ML-DSA level with code %d", ret);
        goto err;
    }

    // Import PKCS8 ML-DSA Component

    if (level == D2_WC_MLDSA44_RSAPSS2048_SHA256
        || level == D2_WC_MLDSA44_RSA2048_SHA256
        || level == D2_WC_MLDSA44_ED25519_SHA256
        || level == D2_WC_MLDSA44_NISTP256_SHA256
        // || type == D2_WC_MLDSA44_BPOOL256_SHA256
        || level == D2_WC_MLDSA65_RSAPSS3072_SHA512
        || level == D2_WC_MLDSA65_RSA3072_SHA512
        || level == D2_WC_MLDSA65_ED25519_SHA512
        || level == D2_WC_MLDSA65_NISTP256_SHA512
        || level == D2_WC_MLDSA65_BPOOL256_SHA512
        || level == D2_WC_MLDSA87_NISTP384_SHA512
        || level == D2_WC_MLDSA87_BPOOL384_SHA512
        || level == D2_WC_MLDSA87_ED448_SHA512) {

        // // Processes a sequence of PKCS8 objects
        // if ((ret = wc_Dilithium_PrivateKeyDecode(mldsa_Buffer, &idx, key->mldsa_key, mldsa_BufferLen)) < 0) {
        //     MADWOLF_DEBUG("failed to import ML-DSA-44 component with code %d", ret);
        //     goto err;
        //     return ret;
        // }

        // Processes a sequence of OCTET STRING objects
        word32 algorSum = 0;
        ret = ToTraditional_ex(mldsa_Buffer, mldsa_BufferLen, &algorSum);
        if (ret <= 0) {
            MADWOLF_DEBUG(":::: failed to convert ML-DSA-44 component with code %d", ret);
            FILE* f = fopen("mldsa44.bin", "wb");
            if (f) {
                fwrite(mldsa_Buffer, 1, mldsa_BufferLen, f);
                fclose(f);
            }
            goto err;
        }
        mldsa_BufferLen = ret;
        ret = 0;

        // Processes a sequence of PKCS8 objects
        if ((ret = wc_Dilithium_PrivateKeyDecode(mldsa_Buffer, &idx, key->mldsa_key, mldsa_BufferLen)) < 0) {
            MADWOLF_DEBUG("[A] failed to import ML-DSA-44 component with code %d", ret);
            // goto err;
        }

        // // Processes a sequence of OCTET STRING objects
        // if ((ret = wc_dilithium_import_private(mldsa_Buffer, mldsa_BufferLen, key->mldsa_key)) < 0) {
        //     MADWOLF_DEBUG("[B] failed to import ML-DSA component with code %d", ret);
        //     goto err;
        // }

    } else {

        // Processes a sequence of OCTET STRING objects
        if ((ret = wc_dilithium_import_private(mldsa_Buffer, mldsa_BufferLen, key->mldsa_key)) < 0) {
            MADWOLF_DEBUG("[C] failed to import ML-DSA component with code %d", ret);
            goto err;
        }
    }

    // Resets the index
    idx = other_BufferLen;

    // import the other DSA component
    switch (level) {

        case D2_WC_MLDSA65_ED25519_SHA512:
        case D2_WC_MLDSA44_ED25519_SHA256:
        case WC_MLDSA65_ED25519_SHA384:
        case WC_MLDSA44_ED25519_SHA256: {

            // Checks the ED25519 pubkey buffer size
            if (other_BufferLen != ED25519_PRV_KEY_SIZE) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: ED25519 private key size error (%d vs. %d)", other_BufferLen, ED25519_KEY_SIZE);
                ret = BUFFER_E;
                break;
            }
            if (key->alt_key.ed25519) {
                wc_ed25519_free(key->alt_key.ed25519);
                key->alt_key.ed25519 = NULL;
            }

            key->alt_key.ed25519 = (ed25519_key *)XMALLOC(sizeof(ed25519_key), key->heap, DYNAMIC_TYPE_ED25519);
            if (!key->alt_key.ed25519) {
                ret = MEMORY_E;
                break;
            }

            if ((ret = wc_ed25519_init(key->alt_key.ed25519)) < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: failed to init ED25519 component with code %d", ret);
                wc_ed25519_free(key->alt_key.ed25519);
                key->alt_key.ed25519 = NULL;
                break;
            }

#if defined(HAVE_MLDSA_COMPOSITE_DRAFT_3)
            if (level == WC_MLDSA65_ED25519_SHA384 ||
                level == WC_MLDSA44_ED25519_SHA256) {

                if ((ret = wc_ed25519_import_private_key(other_Buffer, ED25519_PRV_KEY_SIZE, NULL, 0, key->alt_key.ed25519)) < 0) {
                    MADWOLF_DEBUG("ML-DSA COMPOSITE: failed to import ED25519 component with code %d, Trying private only", ret);
                    if ((ret = wc_ed25519_import_private_only(other_Buffer, other_BufferLen, key->alt_key.ed25519)) < 0) {
                        MADWOLF_DEBUG("ML-DSA COMPOSITE: failed to import ED25519 private only component with code %d", ret);
                        wc_ed25519_free(key->alt_key.ed25519);
                        key->alt_key.ed25519 = NULL;
                        break;
                    }
                }
            }
            if (level == D2_WC_MLDSA44_ED25519_SHA256 || level == D2_WC_MLDSA65_ED25519_SHA512) {
                if ((ret = wc_Ed25519PrivateKeyDecode(other_Buffer, &idx, key->alt_key.ed25519, other_BufferLen)) < 0) {
                    MADWOLF_DEBUG("ML-DSA COMPOSITE: failed to import ED25519 component with code %d", ret);
                    break;
                }
            }
        } break;

        case D2_WC_MLDSA87_BPOOL384_SHA512:
        case D2_WC_MLDSA87_NISTP384_SHA512:
        case D2_WC_MLDSA65_BPOOL256_SHA512:
        case D2_WC_MLDSA65_NISTP256_SHA512:
        case D2_WC_MLDSA44_NISTP256_SHA256:
        case WC_MLDSA87_BPOOL384_SHA384:
        case WC_MLDSA87_NISTP384_SHA384:
        case WC_MLDSA65_BPOOL256_SHA384:
        // case WC_MLDSA44_BPOOL256_SHA256:
        case WC_MLDSA65_NISTP256_SHA384:
        case WC_MLDSA44_NISTP256_SHA256: {

            int curveId = 0;
            int curveSz = 0;

            if (key->alt_key.ecc) {
                wc_ecc_free(key->alt_key.ecc);
                key->alt_key.ecc = NULL;
            }

            key->alt_key.ecc = (ecc_key *)XMALLOC(sizeof(ecc_key), key->heap, DYNAMIC_TYPE_PRIVATE_KEY);
            if (!key->alt_key.ecc) {
                ret = MEMORY_E;
                break;
            }

            if (wc_ecc_init_ex(key->alt_key.ecc, key->heap, key->devId) < 0) {
                wc_ecc_free(key->alt_key.ecc);
                key->alt_key.ecc = NULL;
                ret = BAD_STATE_E;
                break;
            }

            if (level == WC_MLDSA65_NISTP256_SHA384 || level == WC_MLDSA44_NISTP256_SHA256) {
                curveId = ECC_SECP256R1;
            } else {
                curveId = ECC_BRAINPOOLP256R1;
            }

            // Sets the curve
            curveSz = wc_ecc_get_curve_size_from_id(curveId);
            if (curveSz <= 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: Invalid curve size (%d)", curveSz);
                ret = BAD_FUNC_ARG;
                break;
            }

            ret = wc_ecc_set_curve(key->alt_key.ecc, curveSz, curveId);
            if (ret < 0) {
                MADWOLF_DEBUG("ML-DSA COMPOSITE: failed to set curve with code %d", ret);
                break;
            }

#if defined(HAVE_MLDSA_COMPOSITE_DRAFT_3)
            if (level == WC_MLDSA87_BPOOL384_SHA384 ||
                level == WC_MLDSA87_NISTP384_SHA384 ||
                level == WC_MLDSA65_BPOOL256_SHA384  ||
                // type == WC_MLDSA44_BPOOL256_SHA256  ||
                level == WC_MLDSA65_NISTP256_SHA384 ||
                level == WC_MLDSA44_NISTP256_SHA256) {

                idx = 0;
                ret = wc_EccPrivateKeyDecode(other_Buffer, &idx, key->alt_key.ecc, other_BufferLen);
                if (ret < 0) {
                    MADWOLF_DEBUG("failed to import ECDSA component with code %d (buff_len: %d)", ret, other_BufferLen);
                    wc_ecc_free(key->alt_key.ecc);
                    key->alt_key.ecc = NULL;
                    break;
                }
            }
#elif defined(HAVE_MLDSA_COMPOSITE_DRAFT_2)
            if (type == D2_WC_MLDSA87_BPOOL384_SHA512 ||
                type == D2_WC_MLDSA87_NISTP384_SHA512 ||
                type == D2_WC_MLDSA65_BPOOL256_SHA512 ||
                type == D2_WC_MLDSA65_NISTP256_SHA512 ||
                type == D2_WC_MLDSA44_NISTP256_SHA256) {

                if ((ret = wc_EccPrivateKeyDecode(other_Buffer, &idx, key->alt_key.ecc, other_BufferLen)) < 0) {
                    MADWOLF_DEBUG("failed to import ECDSA component with code %d", ret);
                    break;
                }
                if (type == WC_MLDSA65_NISTP256_SHA384 || type == WC_MLDSA44_NISTP256_SHA256) {
                    // Checks the ECDSA curve (P-256)
                    if (wc_ecc_get_curve_id(key->alt_key.ecc.idx) != ECC_SECP256R1) {
                        MADWOLF_DEBUG("ML-DSA COMPOSITE: ECDSA import PubKey curve error (%d vs. %d)", key->alt_key.ecc.dp->id, ECC_SECP256R1);
                        ret = BAD_STATE_E;
                        break;
                    }
                } else {
                    // Checks the ECDSA curve (BRAINPOOLP256R1)
                    if (wc_ecc_get_curve_id(key->alt_key.ecc.idx) != ECC_BRAINPOOLP256R1) {
                        MADWOLF_DEBUG("ML-DSA COMPOSITE: ECDSA import PubKey curve error (%d vs. %d)", key->alt_key.ecc.dp->id, ECC_BRAINPOOLP256R1);
                        ret = BAD_STATE_E;
                        break;
                    }
                }
            }
#endif
        } break;

        case D2_WC_MLDSA65_RSAPSS3072_SHA512:
        case D2_WC_MLDSA65_RSA3072_SHA512:
        case D2_WC_MLDSA44_RSAPSS2048_SHA256:
        case D2_WC_MLDSA44_RSA2048_SHA256:
        case WC_MLDSA44_RSAPSS2048_SHA256:
        case WC_MLDSA44_RSA2048_SHA256:
        case WC_MLDSA65_RSAPSS4096_SHA384:
        case WC_MLDSA65_RSA4096_SHA384:
        case WC_MLDSA65_RSAPSS3072_SHA384:
        case WC_MLDSA65_RSA3072_SHA384: {
            // Import the RSA component
            word32 rsaSz = 0;
            int sz = 0;

            if (key->alt_key.rsa) {
                wc_FreeRsaKey(key->alt_key.rsa);
                key->alt_key.rsa = NULL;
            }

            key->alt_key.rsa = (RsaKey *)XMALLOC(sizeof(RsaKey), key->heap, DYNAMIC_TYPE_PRIVATE_KEY);
            if (!key->alt_key.rsa) {
                ret = MEMORY_E;
                break;
            }
            
            if (level == D2_WC_MLDSA65_RSAPSS3072_SHA512
                || level == D2_WC_MLDSA65_RSA3072_SHA512
                || level == D2_WC_MLDSA44_RSAPSS2048_SHA256
                || level == D2_WC_MLDSA44_RSA2048_SHA256) {

                // Processes a sequence of OCTET STRING objects
                word32 algorSum = 0;
                ret = ToTraditional_ex(other_Buffer, other_BufferLen, &algorSum);
                if (ret <= 0) {
                    MADWOLF_DEBUG(":::: failed to convert RSA component to traditional with code %d (algorSum: %d)", ret, algorSum);
                    goto err;
                }
                other_BufferLen = ret;

                if ((ret = wc_RsaPrivateKeyDecode(other_Buffer, &rsaSz, key->alt_key.rsa, other_BufferLen)) < 0) {
                    MADWOLF_DEBUG("failed to import RSA component with code %d (other: %d, rsaSz: %d)", ret, other_BufferLen, rsaSz);
                    wc_FreeRsaKey(key->alt_key.rsa);
                    key->alt_key.rsa = NULL;
                    ret = ASN_PARSE_E;
                    break;
                }
            } else {

                if ((ret = wc_RsaPrivateKeyDecode(other_Buffer, &rsaSz, key->alt_key.rsa, other_BufferLen)) < 0) {
                    MADWOLF_DEBUG("failed to import RSA component with code %d (other: %d, rsaSz: %d)", ret, other_BufferLen, rsaSz);
                    wc_FreeRsaKey(key->alt_key.rsa);
                    key->alt_key.rsa = NULL;
                    ret = ASN_PARSE_E;
                    break;
                }
            }
            if ((sz = wc_RsaEncryptSize(key->alt_key.rsa)) < 0) {
                MADWOLF_DEBUG("failed to get RSA encrypt size with code %d", sz);
                wc_FreeRsaKey(key->alt_key.rsa);
                key->alt_key.rsa = NULL;
                ret = BAD_STATE_E;
                break;
            }
            if (level == WC_MLDSA65_RSAPSS4096_SHA384 || 
                level == WC_MLDSA65_RSA4096_SHA384) {

                // Checks it is a RSA4096 key
                if (sz != RSA4096_SIG_SIZE) {
                    MADWOLF_DEBUG("wrong RSA-4096 sig size (%d vs. %d)", rsaSz, sz);
                    wc_FreeRsaKey(key->alt_key.rsa);
                    key->alt_key.rsa = NULL;
                    ret = BAD_STATE_E;
                    break;
                }
            } else if (level == WC_MLDSA65_RSAPSS3072_SHA384 || 
                       level == WC_MLDSA65_RSA3072_SHA384 ||
                       level == D2_WC_MLDSA65_RSAPSS3072_SHA512 ||
                       level == D2_WC_MLDSA65_RSA3072_SHA512) {

                // Checks it is a RSA3072 key
                if (sz != RSA3072_SIG_SIZE) {
                    MADWOLF_DEBUG("wrong RSA-3072 sig size (%d vs. %d)", rsaSz, sz);
                    wc_FreeRsaKey(key->alt_key.rsa);
                    key->alt_key.rsa = NULL;
                    ret = BAD_STATE_E;
                    break;
                }
            } else if (level == WC_MLDSA44_RSAPSS2048_SHA256 || 
                       level == WC_MLDSA44_RSA2048_SHA256 ||
                       level == D2_WC_MLDSA44_RSAPSS2048_SHA256 ||
                       level == D2_WC_MLDSA44_RSA2048_SHA256) {

                // Checks it is a RSA3072 key
                if (sz != RSA2048_SIG_SIZE) {
                    MADWOLF_DEBUG("wrong RSA-2048 sig size (%d vs. %d)", rsaSz, sz);
                    wc_FreeRsaKey(key->alt_key.rsa);
                    key->alt_key.rsa = NULL;
                    ret = BAD_STATE_E;
                    break;
                }
            }
        } break;

        case D2_WC_MLDSA87_ED448_SHA512:
        case WC_MLDSA87_ED448_SHA384: {
#if defined(HAVE_MLDSA_COMPOSITE_DRAFT_3)
            if (level == WC_MLDSA87_ED448_SHA384) {
                // Cehcks the ED448 pubkey buffer size
                if (other_BufferLen != ED448_PRV_KEY_SIZE) {
                    MADWOLF_DEBUG("ML-DSA COMPOSITE: ED448 signature size error (%d vs. %d)", other_BufferLen, ED448_PRV_KEY_SIZE);
                    ret = BUFFER_E;
                    break;
                }
                if (key->alt_key.ed448) {
                    // Free the current key
                    wc_ed448_free(key->alt_key.ed448);
                    key->alt_key.ed448 = NULL;
                }
                key->alt_key.ed448 = (ed448_key *)XMALLOC(sizeof(ed448_key), key->heap, DYNAMIC_TYPE_PRIVATE_KEY);
                if (!key->alt_key.ed448) {
                    ret = MEMORY_E;
                    break;
                }
                if ((ret = wc_ed448_import_private_key_ex(other_Buffer, other_BufferLen, NULL, 0, key->alt_key.ed448, 0)) < 0) {
                    MADWOLF_DEBUG("ML-DSA COMPOSITE: failed to import ED448 component with code %d", ret);
                    wc_ed448_free(key->alt_key.ed448);
                    key->alt_key.ed448 = NULL;
                    break;
                }
            }

#elif defined(HAVE_MLDSA_COMPOSITE_DRAFT_2)
            if (type == D2_MLDSA87_ED448_SHA512_TYPE) {
                if ((ret = wc_Ed448PrivateKeyDecode(other_Buffer, &idx, key->alt_key.ed448, other_BufferLen)) < 0) {
                    MADWOLF_DEBUG("ML-DSA COMPOSITE: failed to import ED448 component with code %d", ret);
                    break;
                }
            }
#endif

        } break;

        case WC_MLDSA_COMPOSITE_UNDEF:
        default:
            MADWOLF_DEBUG("Unsupported ML-DSA Composite Type: %d", level);
            return BAD_FUNC_ARG;
    }

    if (ret == 0) {
        // Set the type of key
        key->type = wc_mldsa_composite_level_type(level);

        // Set the private/public key set flag
        key->prvKeySet = 1;
        key->pubKeySet = 1;
    }

err:

    if (keyBuffer) {
        XFREE(keyBuffer, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
    }
    return ret;
}

int wc_mldsa_composite_export_private(mldsa_composite_key* key, byte* out, word32* outLen)
{
    int ret = 0;
    word32 inLen = 0;

    int composite_level = 0;

    static const ASNItem compPrivKeyIT[3] = {
    /*  SEQ */    { 0, ASN_SEQUENCE, 1, 1, 0 },
    /*  ML-DSA */   { 1, ASN_OCTET_STRING, 0, 0, 0 },
    /*  Trad */     { 1, ASN_OCTET_STRING, 0, 0, 0 },
    };

    ASNSetData compPrivKeyASN[3];
        // Set the ML-DSA public key

    byte * mldsa_Buffer = NULL;
    word32 mldsa_BufferLen = 0;

    byte * other_Buffer = NULL;
    word32 other_BufferLen = 0;

    /* Validate parameters */
    if ((key == NULL) || (key->prvKeySet != 1) || (outLen == NULL || *outLen == 0)) {
        // Error in the function arguments
        MADWOLF_DEBUG("Invalid parameters: key: %p, out: %p, outLen: %p", key, out, outLen);
        return BAD_FUNC_ARG;
    }

    // Get the length passed in for checking
    inLen = *outLen;

    // Get the composite level
    composite_level = wc_mldsa_composite_level(key);
    if (composite_level <= 0) {
        MADWOLF_DEBUG("Invalid ML-DSA Composite Key Type: %d (Level: %d)", key->type, composite_level);
        return BAD_FUNC_ARG;
    }

#ifdef HAVE_MLDSA_COMPOSITE_DRAFT_3

        ret = wc_dilithium_priv_size(key->mldsa_key);
        if (ret <= 0) return WC_KEY_SIZE_E;
        mldsa_BufferLen = ret;

        if (inLen < mldsa_BufferLen) return BUFFER_E;

        mldsa_Buffer = (byte *)XMALLOC(mldsa_BufferLen, key->heap, DYNAMIC_TYPE_PRIVATE_KEY);
        if (mldsa_Buffer == NULL) return MEMORY_E;

        ret = wc_dilithium_export_private(key->mldsa_key, mldsa_Buffer, &mldsa_BufferLen);
        if (ret < 0) {
            MADWOLF_DEBUG("error cannot export ML-DSA component's private key with error %d\n", ret);
            goto err;
        }

#elif defined(HAVE_MLDSA_COMPOSITE_DRAFT_2)
    MADWOLF_DEBUG("Draft-2: Exporting ML-DSA Private Key (type: %d)", key->type);

    ret = wc_Dilithium_KeySize(key->mldsa_key);
    if (mldsa_BufferLen <= 0) return WC_KEY_SIZE_E;
    mldsa_BufferLen = ret;

    if (inLen < mldsa_BufferLen) return BUFFER_E;
    
    mldsa_Buffer = (byte *)XMALLOC(mldsa_BufferLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (mldsa_Buffer == NULL) return MEMORY_E;

    if ((ret = wc_Dilithium_KeyToDer(key->mldsa_key, mldsa_Buffer, mldsa_BufferLen)) < 0) {
        MADWOLF_DEBUG("error cannot export ML-DSA component's private key with error %d\n", ret);
        return ret;
    }
    mldsa_BufferLen = ret;
    ret = 0;
#endif

    /* Exports the other key */
    switch (composite_level) {
        case WC_MLDSA44_ED25519_SHA256: 
        case WC_MLDSA65_ED25519_SHA384: {

#ifdef HAVE_MLDSA_COMPOSITE_DRAFT_3
            
            ret = wc_ed25519_priv_size(key->alt_key.ed25519);
            if (ret <= 0) goto err;
            other_BufferLen = ret;

            if (mldsa_BufferLen + other_BufferLen + 12 > inLen) {
                ret = BUFFER_E;
                goto err;
            }

            other_Buffer = (byte *)XMALLOC(other_BufferLen, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
            if (other_Buffer == NULL) {
                ret = MEMORY_E;
                goto err;
            }

            if ((ret = wc_ed25519_export_private(key->alt_key.ed25519, other_Buffer, &other_BufferLen)) < 0) {
                return ret;
            }

#elif defined(HAVE_MLDSA_COMPOSITE_DRAFT_2)

            ret = wc_Ed25519KeyToDer(key->alt_key.ed25519, NULL, other_BufferLen);
            if (ret <= 0) goto err;
            other_BufferLen = ret;

            if (mldsa_BufferLen + other_BufferLen + 12 > inLen) {
                ret = BUFFER_E;
                goto err;
            }
            other_Buffer = (byte *)XMALLOC(other_BufferLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (other_Buffer == NULL) {
                err = MEMORY_E;
                goto err;
            }
            if ((ret = wc_Ed25519KeyToDer(key->alt_key.ed25519, other_Buffer, other_BufferLen)) < 0) {
                goto err;
            }
            other_BufferLen = ret;
            ret = 0;
#endif
        } break;

        // ----- current ----- //
        // case WC_MLDSA44_BPOOL256_SHA256:
        case WC_MLDSA44_NISTP256_SHA256: 
        case WC_MLDSA65_NISTP256_SHA384:
        case WC_MLDSA65_BPOOL256_SHA384:
        case WC_MLDSA87_NISTP384_SHA384:
        case WC_MLDSA87_BPOOL384_SHA384: {
            int curveId = ECC_SECP256R1;
            int curveSz = 0;

            // Sets the curve ID
            if (composite_level == WC_MLDSA44_NISTP256_SHA256
                || composite_level == WC_MLDSA65_NISTP256_SHA384)
                curveId = ECC_SECP256R1;
            else if (composite_level == WC_MLDSA65_BPOOL256_SHA384)
                curveId = ECC_BRAINPOOLP256R1;
            else if (composite_level == WC_MLDSA87_NISTP384_SHA384)
                curveId = ECC_SECP384R1;
            else if (composite_level == WC_MLDSA87_BPOOL384_SHA384)
                curveId = ECC_BRAINPOOLP384R1;

            // Gets the curve size and checks for errors
            curveSz = wc_ecc_get_curve_size_from_id(curveId);
            if (curveId <= 0 || curveSz <= 0) {
                ret = BAD_FUNC_ARG;
                goto err;
            }

            // Checks we have a non-zero pointer
            if (key->alt_key.ecc == NULL) {
                ret = BAD_FUNC_ARG;
                goto err;
            }

            // Gets the size of the ECDSA component
            ret = wc_EccKeyDerSize(key->alt_key.ecc, 1);
            if (ret < 0) goto err;

            // Allocates memory for the ECDSA component
            other_BufferLen = ret;
            other_Buffer = (byte *)XMALLOC(other_BufferLen, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
            if (other_Buffer == NULL) {
                ret = MEMORY_E;
                goto err;
            }

            // Encodes the ECDSA component
            if (wc_EccKeyToDer(key->alt_key.ecc, other_Buffer, other_BufferLen) < 0) {
                MADWOLF_DEBUG("failed to export ECDSA component with code %d", ret);
                goto err;
            }
            ret = 0;

#if defined(HAVE_MLDSA_COMPOSITE_DRAFT_2)

            ret = wc_ecc_size(key->alt_key.ecc);
            if (ret <= 0) {
                goto err;
            }
            other_BufferLen = ret;

            if (mldsa_BufferLen + other_BufferLen + 12 > inLen) {
                ret = BUFFER_E;
                goto err;
            }
            other_Buffer = (byte *)XMALLOC(other_BufferLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (other_Buffer == NULL) {
                ret = MEMORY_E;
                goto err;
            }

            if ((ret = wc_EccPrivateKeyToDer(key->alt_key.ecc, other_Buffer, other_BufferLen)) < 0) {
                goto err;
            }
            other_BufferLen = ret;
            ret = 0;
#endif
        } break;

        case WC_MLDSA87_ED448_SHA384: {
#ifdef HAVE_MLDSA_COMPOSITE_DRAFT_3

            // if ((ret = wc_Ed448KeyToDer(key->alt_key.ed448, NULL, other_BufferLen)) < 0) {
            //     MADWOLF_DEBUG("failed to get estimate size of DER for ED448 with code %d", ret);
            //     goto err;
            // }

            // Allocates memory for the ED448 component
            other_BufferLen = ED448_PRV_KEY_SIZE;
            other_Buffer = (byte *)XMALLOC(other_BufferLen, NULL, DYNAMIC_TYPE_ED448);
            if (other_Buffer == NULL) {
                ret = MEMORY_E;
                goto err;
            }
            if ((ret = wc_ed448_export_private(key->alt_key.ed448, other_Buffer, &other_BufferLen)) < 0) {
                MADWOLF_DEBUG("failed to export ED448 component with code %d", ret);
                goto err;
            }
            // if ((ret = wc_Ed448KeyToDer(key->alt_key.ed448, other_Buffer, other_BufferLen)) < 0) {
            //     MADWOLF_DEBUG("failed to export ED448 component with code %d", ret);
            //     goto err;
            // }

#elif defined(HAVE_MLDSA_COMPOSITE_DRAFT_2)
            
            ret = wc_Ed448KeyToDer(key->alt_key.ed448, NULL, other_BufferLen);
            if (ret <= 0) goto err;
            other_BufferLen = ret;

            if (mldsa_BufferLen + other_BufferLen + 12 > inLen) {
                ret = BUFFER_E;
                goto err;
            }
            other_Buffer = (byte *)XMALLOC(other_BufferLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (other_Buffer == NULL) {
                ret = MEMORY_E;
                goto err;
            }

            if ((ret = wc_Ed448KeyToDer(key->alt_key.ed448, other_Buffer, other_BufferLen)) < 0) {
                goto err;
            }
            other_BufferLen = ret;
            ret = 0;
#endif
        } break;

        // Placeholders for the other DSA components
        case WC_MLDSA44_RSA2048_SHA256:
        case WC_MLDSA44_RSAPSS2048_SHA256:
        case WC_MLDSA65_RSAPSS3072_SHA384:
        case WC_MLDSA65_RSA3072_SHA384:
        case WC_MLDSA65_RSAPSS4096_SHA384:
        case WC_MLDSA65_RSA4096_SHA384: {
            if (key->alt_key.rsa->type != RSA_PRIVATE) {
                MADWOLF_DEBUG0("RSA component is not private key");
                return ALGO_ID_E;
            }
#ifdef HAVE_MLDSA_COMPOSITE_DRAFT_3
            ret = wc_RsaKeyToDer(key->alt_key.rsa, NULL, RSA4096_PRV_KEY_SIZE);
            if (ret < 0) {
                MADWOLF_DEBUG("failed to export RSA component with code %d", ret);
                goto err;
            }
            other_BufferLen = ret;

            other_Buffer = (byte *)XMALLOC(other_BufferLen, key->heap, DYNAMIC_TYPE_PRIVATE_KEY);
            if (other_Buffer == NULL) {
                MADWOLF_DEBUG("failed to allocate memory for RSA component with size %d", other_BufferLen);
                ret = MEMORY_E;
                goto err;
            }

            ret = wc_RsaKeyToDer(key->alt_key.rsa, other_Buffer, other_BufferLen);
            if (ret < 0) {
                MADWOLF_DEBUG("failed to export RSA component with code %d", ret);
                goto err;
            }
            ret = 0;

#elif defined(HAVE_MLDSA_COMPOSITE_DRAFT_2)
            ret = wc_RsaPrivateKeySize(key->alt_key.rsa);
            if (ret <= 0) goto err;
            other_BufferLen = ret;

            if (mldsa_BufferLen + other_BufferLen + 12 > inLen) {
                ret = BUFFER_E;
                goto err;
            }
            other_Buffer = (byte *)XMALLOC(other_BufferLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (other_Buffer == NULL) {
                ret = MEMORY_E;
                goto err;
            }
            // Set the buffer length
            other_BufferLen = ret;

            // Resets the return value
            ret = 0;
#endif

        } break;

        // ----- Draft 2 ----- //
        case D2_WC_MLDSA44_RSAPSS2048_SHA256:
        case D2_WC_MLDSA44_RSA2048_SHA256:
        case D2_WC_MLDSA44_NISTP256_SHA256:
        // case D2_WC_MLDSA44_BPOOL256_SHA256:
        case D2_WC_MLDSA44_ED25519_SHA256:
        case D2_WC_MLDSA65_RSAPSS3072_SHA512:
        case D2_WC_MLDSA65_RSA3072_SHA512:
        case D2_WC_MLDSA65_NISTP256_SHA512:
        case D2_WC_MLDSA65_BPOOL256_SHA512:
        case D2_WC_MLDSA65_ED25519_SHA512:
        case D2_WC_MLDSA87_BPOOL384_SHA512:
        case D2_WC_MLDSA87_NISTP384_SHA512:
        case D2_WC_MLDSA87_ED448_SHA512:
            MADWOLF_DEBUG("Export of ML-DSA Composite (Draft 2) Unsupported (Type: %d)", key->type);
            return ALGO_ID_E;

        case WC_MLDSA_COMPOSITE_UNDEF:
        default:
            MADWOLF_DEBUG("Unsupported ML-DSA Composite Level: %d (type: %d)", composite_level, key->type);
            return ALGO_ID_E;
    }

    // Clear the memory
    XMEMSET(compPrivKeyASN, 0, sizeof(ASNSetData) * mldsaCompASN_Length);

    // Let's set the ASN1 data
    SetASN_Buffer(&compPrivKeyASN[MLDSA_COMPASN_IDX_MLDSA], mldsa_Buffer, mldsa_BufferLen);
    SetASN_Buffer(&compPrivKeyASN[MLDSA_COMPASN_IDX_OTHER], other_Buffer, other_BufferLen);

    // Let's calculate the size of the ASN1 data
    int encSz = 0;
    if (SizeASN_Items(compPrivKeyIT, compPrivKeyASN, mldsaCompASN_Length, &encSz) < 0) {
        return BAD_STATE_E;  
    }

    if (encSz > (int)(inLen)) {
        return BUFFER_E;
    }

    // Let's encode the ASN1 data
    int encodedLen = SetASN_Items(compPrivKeyIT, compPrivKeyASN, mldsaCompASN_Length, out);
    if (encodedLen <= 0) {
        return ASN_PARSE_E;
    }
    *outLen = encodedLen;

err:

    if (mldsa_Buffer != NULL) {
        XFREE(mldsa_Buffer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (other_Buffer != NULL) {
        XFREE(other_Buffer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return ret;
}

#endif /* WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY */

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
int wc_mldsa_composite_import_key(const byte* priv, word32 privSz,
    const byte* pub, word32 pubSz, mldsa_composite_key* key, enum mldsa_composite_level composite_level)
{
    int ret = 0;

    /* Validate parameters. */
    if ((priv == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    /* If the type is not set, use the key type */
    if (composite_level <= 0)
        composite_level = wc_mldsa_composite_type(key);

    if (composite_level < 0) {
        MADWOLF_DEBUG("Invalid ML-DSA Composite Key Type: %d", key->type);
        return BAD_FUNC_ARG;
    }

    /* Imports the private key first */
    ret = wc_mldsa_composite_import_private(priv, privSz, key, composite_level);
    if (ret == 0 && (pub != NULL && pubSz > 0)) {
        /* If the input buffer is not NULL, import the public key */
        ret = wc_mldsa_composite_import_public(pub, pubSz, key, composite_level);
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
    MADWOLF_DEBUG("Exported private key with size %d", *privSz);

    if (ret == 0) {
        /* Export public key. */
        ret = wc_mldsa_composite_export_public(key, pub, pubSz);
        MADWOLF_DEBUG("Exported public key with size %d", *pubSz);
    }

    // MADWOLF_DEBUG("Exporting succssful (%d)", ret);

    return ret;
}
#endif /* WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY */

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_ASN1
#if defined(WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY)
int wc_MlDsaComposite_PrivateKeyDecode(const byte* input, word32* inOutIdx,
    mldsa_composite_key* key, word32 inSz, enum mldsa_composite_level composite_level)
{
    int ret = 0;
    const byte* privKey = NULL;
    const byte* pubKey = NULL;
    word32 privKeyLen = 0;
    word32 pubKeyLen = 0;
    int keySum = 0;

    byte * local_buffer = NULL;
    word32 local_buffer_len = 0;

    /* Validate parameters. */
    if ((input == NULL) || (inOutIdx == NULL) || (key == NULL) || (inSz == 0) || (composite_level <= 0)) {
        ret = BAD_FUNC_ARG;
    }

    /* Creates a local copy of the input buffer */
    local_buffer = (byte *)XMALLOC(inSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (local_buffer == NULL) {
        return MEMORY_E;
    }
    XMEMCPY(local_buffer, input, inSz);

    /* Retrieves the OID SUM for the key type*/
    if ((keySum = wc_composite_level_key_sum(composite_level)) < 0) {
        WOLFSSL_MSG_VSNPRINTF("error cannot get ML-DSA Composite type");
    }

    /* Remove the PKCS8 outer shell if present. */
    ret = ToTraditional_ex(local_buffer, inSz, (word32 *)&keySum);
    if (ret < 0 || keySum <= 0) {
        MADWOLF_DEBUG("error cannot get ML-DSA Composite type from PKCS8 or type (%d)", composite_level);
        ret = BAD_FUNC_ARG;
        goto err;
    }
    // Sets the size of the stripped buffer
    // and resets the return code
    local_buffer_len = ret;
    ret = 0;

    MADWOLF_DEBUG(">>>>> Removed PKCS8 Header (type: %d; inSz: %d, localSz: %d)", keySum, inSz, local_buffer_len);

    if (keySum == D2_MLDSA44_RSAPSS2048k
            || keySum == D2_MLDSA44_RSA2048k
            || keySum == D2_MLDSA44_NISTP256k
            || keySum == D2_MLDSA44_BPOOL256k
            || keySum == D2_MLDSA44_ED25519k
            || keySum == D2_MLDSA65_RSAPSS3072k
            || keySum == D2_MLDSA65_RSA3072k
            || keySum == D2_MLDSA65_NISTP256k
            || keySum == D2_MLDSA65_BPOOL256k
            || keySum == D2_MLDSA65_ED25519k
            || keySum == D2_MLDSA87_NISTP384k
            || keySum == D2_MLDSA87_BPOOL384k
            || keySum == D2_MLDSA87_ED448k) {
                
        // -------- Draft 2 -------- //
        privKey = local_buffer;
        privKeyLen = local_buffer_len;
        pubKey = NULL;
        pubKeyLen = 0;

    } else {
    
        if (ret == 0) {
            /* Decode the asymmetric key and get out private and public key data. */
            *inOutIdx = 0;
            ret = DecodeAsymKey_Assign(local_buffer, inOutIdx, inSz, &privKey, &privKeyLen,
                &pubKey, &pubKeyLen, &keySum);
            if (ret < 0) {
                MADWOLF_DEBUG("error cannot decode ML-DSA Composite key with code %d", ret);
                goto err;
            }
        }
    }
    if (ret == 0) {
        /* Check whether public key data was found. */
#if defined(WOLFSSL_DILITHIUM_PUBLIC_KEY)
        if (pubKeyLen == 0)
#endif
        {
            /* No public key data, only import private key data. */
            ret = wc_mldsa_composite_import_private(privKey, privKeyLen, key, composite_level);
        }
#if defined(WOLFSSL_DILITHIUM_PUBLIC_KEY)
        else {
            /* Import private and public key data. */
            ret = wc_mldsa_composite_import_key(privKey, privKeyLen, pubKey,
                pubKeyLen, key, composite_level);
        }
#endif
    }

    (void)pubKey;
    (void)pubKeyLen;

err:

    if (local_buffer) {
        XFREE(local_buffer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return ret;
}

#endif /* WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY */

#endif /* WOLFSSL_MLDSA_COMPOSITE_NO_ASN1 */

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
int wc_MlDsaComposite_PublicKeyDecode(const byte* input, word32* inOutIdx,
    mldsa_composite_key* key, word32 inSz, enum mldsa_composite_level composite_level)
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
        if (composite_level <= 0) composite_level = wc_mldsa_composite_level(key);

        /* Try to import the key directly. */
        ret = wc_mldsa_composite_import_public(input, inSz, key, composite_level);
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
            switch (composite_level) {
                case WC_MLDSA44_RSA2048_SHA256:
                    keytype = MLDSA44_RSAPSS2048k;
                    break;
                case WC_MLDSA44_RSAPSS2048_SHA256:
                    keytype = MLDSA44_RSA2048k;
                    break;
                case WC_MLDSA44_ED25519_SHA256:
                    keytype = MLDSA44_ED25519k;
                    break;
                case WC_MLDSA44_NISTP256_SHA256:
                    keytype = MLDSA44_NISTP256k;
                    break;
                // case WC_MLDSA44_BPOOL256_SHA256:
                //     keytype = MLDSA44_BPOOL256k;
                //     break;
                case WC_MLDSA65_RSAPSS4096_SHA384:
                    keytype = MLDSA65_RSAPSS4096k;
                    break;
                case WC_MLDSA65_RSA4096_SHA384:
                    keytype = MLDSA65_RSA4096k;
                    break;
                case WC_MLDSA65_RSAPSS3072_SHA384:
                    keytype = MLDSA65_RSAPSS3072k;
                    break;
                case WC_MLDSA65_RSA3072_SHA384:
                    keytype = MLDSA65_RSA3072k;
                    break;
                case WC_MLDSA65_ED25519_SHA384:
                    keytype = MLDSA65_ED25519k;
                    break;
                case WC_MLDSA65_NISTP256_SHA384:
                    keytype = MLDSA65_NISTP256k;
                    break;
                case WC_MLDSA65_BPOOL256_SHA384:
                    keytype = MLDSA65_BPOOL256k;
                    break;
                case WC_MLDSA87_NISTP384_SHA384:
                    keytype = MLDSA87_NISTP384k;
                    break;
                case WC_MLDSA87_BPOOL384_SHA384:
                    keytype = MLDSA87_BPOOL384k;
                    break;
                case WC_MLDSA87_ED448_SHA384:
                    keytype = MLDSA87_ED448k;
                    break;
                
                // --------- Draft 2 ------------ //
                case D2_WC_MLDSA44_RSAPSS2048_SHA256:
                    keytype = D2_MLDSA44_RSAPSS2048k;
                    break;
                case D2_WC_MLDSA44_RSA2048_SHA256:
                    keytype = D2_MLDSA44_RSA2048k;
                    break;
                case D2_WC_MLDSA44_ED25519_SHA256:
                    keytype = D2_MLDSA44_ED25519k;
                    break;
                case D2_WC_MLDSA44_NISTP256_SHA256:
                    keytype = D2_MLDSA44_NISTP256k;
                    break;
                case D2_WC_MLDSA65_RSAPSS3072_SHA512:
                    keytype = D2_MLDSA65_RSAPSS3072k;
                    break;
                case D2_WC_MLDSA65_RSA3072_SHA512:
                    keytype = D2_MLDSA65_RSA3072k;
                    break;
                case D2_WC_MLDSA65_ED25519_SHA512:
                    keytype = D2_MLDSA65_ED25519k;
                    break;
                case D2_WC_MLDSA65_NISTP256_SHA512:
                    keytype = D2_MLDSA65_NISTP256k;
                    break;
                case D2_WC_MLDSA65_BPOOL256_SHA512:
                    keytype = D2_MLDSA65_BPOOL256k;
                    break;
                case D2_WC_MLDSA87_NISTP384_SHA512:
                    keytype = D2_MLDSA87_NISTP384k;
                    break;
                case D2_WC_MLDSA87_BPOOL384_SHA512:
                    keytype = D2_MLDSA87_BPOOL384k;
                    break;
                case D2_WC_MLDSA87_ED448_SHA512:
                    keytype = D2_MLDSA87_ED448k;
                    break;

                case WC_MLDSA_COMPOSITE_UNDEF:
                default:
                    ret = BAD_FUNC_ARG;
            }
            if (ret == 0) {
                /* Decode the asymmetric key and get out public key data. */
                ret = DecodeAsymKeyPublic_Assign(input, inOutIdx, inSz, &pubKey,
                    &pubKeyLen, (int *)&keytype);
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
                ret = wc_mldsa_composite_import_public(pubKey, pubKeyLen, key, composite_level);
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
    int keySum = 0;

    /* Validate parameters. */
    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    /* Check we have a public key to encode. */
    if ((ret == 0) && (!key->pubKeySet) ) {
        WOLFSSL_MSG_VSNPRINTF("public key not set, cannot export it");
        ret = BAD_FUNC_ARG;
    }

    keySum = wc_mldsa_composite_key_sum(key);
    if (keySum < 0) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        byte *pubKey = NULL;
            // Buffer to hold the public key
        word32 pubKeyLen = 0;
            // Length of the public key

        // Gets the size of the public key
        if ((ret = wc_mldsa_composite_export_public(key, NULL, &pubKeyLen)) < 0) {
            MADWOLF_DEBUG("Cannot export the ML-DSA Composite public key with code %d", ret);
            return ret;
        }

        // Allocates memory for the public key
        pubKey = (byte *)XMALLOC(pubKeyLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (pubKey == NULL) {
            return MEMORY_E;
        }

        /* Encode the public key. */
        ret = SetAsymKeyDerPublic(pubKey, pubKeyLen, output, len, keySum,
                withAlg);

        // Free the public key buffer
        XFREE(pubKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        pubKey = NULL; // Safety
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
        enum Key_Sum keySum = 0;
        int privkey_sz = 0;

        // Gets the key type (SUM)
        if ((keySum = wc_mldsa_composite_key_sum(key)) < 0) {
            return BAD_FUNC_ARG;
        }

        // Export the private key
        if ((ret = wc_mldsa_composite_export_private(key, privKey_Buffer, &privKey_BufferLen)) < 0) {
            return MEMORY_E;
        }

        // Check the private key buffer size
        if ((privkey_sz = SetAsymKeyDer(privKey_Buffer, privKey_BufferLen, NULL, 0, NULL, 0, keySum)) < 0) {
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
            ret = SetAsymKeyDer(privKey_Buffer, privKey_BufferLen, NULL, 0, output, privkey_sz, keySum);
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

int wc_MlDsaComposite_KeyToDer(mldsa_composite_key* key, byte* output, word32 len) {
    int ret = WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    int composite_level = 0;

    byte privKey_Buffer[MLDSA_COMPOSITE_MAX_PRV_KEY_SIZE];
    word32 privKey_BufferLen = MLDSA_COMPOSITE_MAX_PRV_KEY_SIZE;
        // Buffer to hold the private key

    /* Validate parameters and check private key set. */
    if ((key != NULL) && key->prvKeySet) {
        enum Key_Sum keySum = 0;
        int privkey_sz = 0;

        // Gets the key type (SUM)
        composite_level = wc_mldsa_composite_level(key);
        if ((keySum = wc_composite_level_key_sum(composite_level)) < 0) {
            return BAD_FUNC_ARG;
        }

        // Export the private key
        if ((ret = wc_mldsa_composite_export_private(key, privKey_Buffer, &privKey_BufferLen)) < 0) {
            return MEMORY_E;
        }

        // Check the private key buffer size
        if ((privkey_sz = SetAsymKeyDer(privKey_Buffer, privKey_BufferLen, NULL, 0, NULL, 0, keySum)) < 0) {
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
            ret = SetAsymKeyDer(privKey_Buffer, privKey_BufferLen, NULL, 0, output, privkey_sz, keySum);
            if (ret < 0) {
                return ret;
            }
        } else {
            ret = privkey_sz;
        }
    }

    return ret;
}
#endif /* WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY */
#endif /* WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY */

#endif /* !WOLFSSL_MLDSA_COMPOSITE_NO_ASN1 */

