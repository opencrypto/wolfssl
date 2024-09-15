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

#ifdef HAVE_MLDSA_COMPOSITE

static const ASNItem compositeIT[] = {
/*  SEQ */    { 0, ASN_SEQUENCE, 1, 1, 0 },
/*  ML-DSA */   { 1, ASN_BIT_STRING, 0, 0, 0 },
/*  Trad */     { 1, ASN_BIT_STRING, 0, 0, 0 },
};
enum {
    MLDSA_COMPASN_IDX_SEQ   = 0,
    MLDSA_COMPASN_IDX_MLDSA = 1,
    MLDSA_COMPASN_IDX_OTHER = 2,
};
#define mldsaCompASN_Length 3

/******************************************************************************
 * Encode/Decode operations
 ******************************************************************************/

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_MAKE_KEY
int wc_mldsa_composite_make_key(mldsa_composite_key* key, WC_RNG* rng)
{
    int ret = 0;
    int mldsa_level = WC_ML_DSA_44;

    if (!key || !rng) {
        return BAD_FUNC_ARG;
    }

    switch (key->params.type) {
        case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_ED25519:
            mldsa_level = WC_ML_DSA_44;
            break;
        case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_P256:
            mldsa_level = WC_ML_DSA_44;
            break;
        default:
            return BAD_STATE_E;
    }

    // Initialize and Generate the ML-DSA key
    if ((wc_dilithium_init_ex(&key->mldsa_key, key->heap, key->devId) < 0) ||
        (wc_dilithium_set_level(&key->mldsa_key, mldsa_level) < 0)) {
        return BAD_STATE_E;
    }

    if (wc_dilithium_make_key(&key->mldsa_key, rng) < 0) {
        return CRYPTGEN_E;
    }
    
    // Initialize and Generate the Traditional DSA key
    switch (key->params.type) {

        case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_ED25519: {
            if (wc_ed25519_init_ex(&key->alt_key.ed25519, key->heap, key->devId) < 0)
                return BAD_STATE_E;

            // wc_ed25519_init(&key->alt_key.ed25519);
            // int kSz = wc_ed25519_size(&key->alt_key.ed25519);
            if (wc_ed25519_make_key(rng, ED25519_KEY_SIZE, &key->alt_key.ed25519) < 0)
                return CRYPTGEN_E;
        } break;

        case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_P256: {
            if (wc_ecc_init_ex(&key->alt_key.ecc, key->heap, key->devId) < 0)
                return BAD_STATE_E;
            // wc_ecc_init(&key->alt_key.ecc);
            int kSz = wc_ecc_get_curve_size_from_id(ECC_SECP256R1);
            if (wc_ecc_make_key(rng, kSz, &key->alt_key.ecc) < 0) {
                return CRYPTGEN_E;
            }
        } break;

        default:
            ret = ALGO_ID_E;
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

    word32 idx = 0;
        // Index for the ASN.1 data
   
    ASNGetData compSigsASN[mldsaCompASN_Length];
    ASNItem sigsIT[mldsaCompASN_Length] = {
        { 0, ASN_SEQUENCE, 1, 1, 0 },
            { 1, ASN_BIT_STRING, 0, 0, 0 },
            { 1, ASN_BIT_STRING, 0, 0, 0 },
    };

    byte mldsa_Buffer[DILITHIUM_ML_DSA_44_SIG_SIZE];
    word32 mldsa_BufferLen = DILITHIUM_ML_DSA_44_SIG_SIZE;
        // Buffer to hold the ML-DSA public key

    byte other_Buffer[MLDSA_COMPOSITE_MAX_OTHER_SIG_SZ];
    word32 other_BufferLen = MLDSA_COMPOSITE_MAX_OTHER_SIG_SZ;
        // Buffer to hold the public key of the other DSA component

    // Error Handling: Check for NULL pointers and invalid input lengths. 
    if (!sig || !msg || !res || !key) { 
        return BAD_FUNC_ARG; 
    }
    
    // Sets the error flag to 0 (error)
    *res = 0;

    // Sets the buffers to 0
    XMEMSET(compSigsASN, 0, sizeof(*compSigsASN) * mldsaCompASN_Length);

    // Initialize the ASN data
    GetASN_Buffer(&compSigsASN[MLDSA_COMPASN_IDX_MLDSA], mldsa_Buffer, &mldsa_BufferLen);
    GetASN_Buffer(&compSigsASN[MLDSA_COMPASN_IDX_OTHER], other_Buffer, &other_BufferLen);

    // Parse the ASN.1 data
    if ((ret = GetASN_Items(sigsIT, compSigsASN, 3, 1, sig, &idx, sigLen)) < 0) {
        MADWOLF_DEBUG("Error while parsing ASN.1 (%d)", ret);
        return ret;
    }

    // Verify Individual DSA Components: 
    switch (key->params.type) {

        case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_ED25519: {
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
                        msg, msgLen, res, &key->alt_key.ed25519, (byte)Ed25519, context, contextLen)) < 0) {
                MADWOLF_DEBUG("wc_ed25519_verify_msg_ex failed with %d", ret);
                return ret;
            }
        } break;

        case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_P256: {
            // Checks the ML-DSA key level
            if (key->mldsa_key.level != WC_ML_DSA_44) {
                MADWOLF_DEBUG("ML-DSA key level error (%d vs. %d)", key->mldsa_key.level, WC_ML_DSA_44);
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
                                            msg, msgLen, res, &key->alt_key.ecc)) < 0) {
                MADWOLF_DEBUG("wc_ecc_verify_hash failed with %d", ret);
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
    if ((ret = wc_dilithium_verify_msg(mldsa_Buffer, mldsa_BufferLen, msg, msgLen, res, &key->mldsa_key)) < 0) {
        MADWOLF_DEBUG("wc_dilithium_verify_msg failed with %d", ret);
        return ret;
    }

    // If all components are verified, then the signature is valid
    *res = 1;

    // Unused context
    (void)context;
    (void)contextLen;

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

    (void)context;
    (void)contextLen;

    byte rnd[DILITHIUM_RND_SZ];
        // Random seed for the ML-DSA component
    
    ASNSetData sigsASN[3];
        // ASN1 data for the ML-DSA and traditional DSA components

    byte mldsaSig_buffer[DILITHIUM_ML_DSA_44_SIG_SIZE];
    word32 mldsaSig_bufferLen = DILITHIUM_ML_DSA_44_SIG_SIZE;
        // Buffer to hold the ML-DSA signature

    byte otherSig_buffer[MLDSA_COMPOSITE_MAX_OTHER_SIG_SZ];
    word32 otherSig_bufferLen = MLDSA_COMPOSITE_MAX_OTHER_SIG_SZ;
        // Buffer to hold the signature of the other DSA component

    word32 inSigLen = 0;
        // Length of the input signature buffer

    // Error Handling: Check for NULL pointers and invalid input lengths.
    if (!msg || !sig || !key || !sigLen || !rng) {
        return BAD_FUNC_ARG; 
    }

    /* Saves the length of the output buffer. */
    inSigLen = *sigLen;

    /* Generate a random seed for the ML-DSA component. */
    ret = wc_RNG_GenerateBlock(rng, rnd, DILITHIUM_RND_SZ);
    if (ret != 0) return ret;

    /* Sign the message with the ML-DSA key. */
    ret = wc_MlDsaKey_Sign(&key->mldsa_key, mldsaSig_buffer, &mldsaSig_bufferLen, msg, msgLen, rng);
    if (ret != 0) return ret;

    // Sign The Traditional component
    switch (key->params.type) {

        case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_ED25519: {
            // Sign ED25519 Component
            if (wc_ed25519_sign_msg_ex(msg, msgLen, otherSig_buffer, 
                    &otherSig_bufferLen, &key->alt_key.ed25519, (byte)Ed25519, context, contextLen) < 0) {
                    return ALGO_ID_E;
            }
            if (otherSig_bufferLen != ED25519_SIG_SIZE) {
                return ASN_PARSE_E;
            }
        } break;

        case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_P256: {
            // Sign ECC Component
            if (wc_ecc_sign_hash(msg, msgLen, otherSig_buffer, &otherSig_bufferLen, 
                    rng, &key->alt_key.ecc) < 0) {
                return ALGO_ID_E;
            }
        } break;

        default:
            return ALGO_ID_E;
    }

    // Clears the memory (required because of a bug in wolfSSL)
    XMEMSET(sigsASN, 0, sizeof(sigsASN));

    // Set the ASN1 data for the ML-DSA and traditional DSA components
    SetASN_Buffer(&sigsASN[MLDSA_COMPASN_IDX_MLDSA], mldsaSig_buffer, mldsaSig_bufferLen);
    SetASN_Buffer(&sigsASN[MLDSA_COMPASN_IDX_OTHER], otherSig_buffer, otherSig_bufferLen);

    // Let's calculate the size of the ASN1 data
    if ((ret = SizeASN_Items(compositeIT, sigsASN, 3, (int *)sigLen)) < 0) {
        WOLFSSL_MSG_VSNPRINTF("error cannot calculate SizeASN_Items");
        return ret;
    }

    if (*sigLen > inSigLen) {
        WOLFSSL_MSG_VSNPRINTF("error not enough space for ASN1 data (needed: %d, provided: %d)", *sigLen, inSigLen);
        return BUFFER_E;
    }

    // Let's encode the ASN1 data
    if ((*sigLen = SetASN_Items(compositeIT, sigsASN, 3, sig)) <= 0) { 
        return ASN_PARSE_E;
    }

    // WOLFSSL_MSG_VSNPRINTF("composite context is not used");
    (void)context;
    (void)contextLen;

    return 0;
}

#endif /* !WOLFSSL_MLDSA_COMPOSITE_NO_SIGN */

/* Initialize the MlDsaComposite private/public key.
 *
 * key  [in]  MlDsaComposite key.
 * returns BAD_FUNC_ARG when key is NULL
 */
int wc_mldsa_composite_init(mldsa_composite_key* key)
{
    return wc_mldsa_composite_init_ex(key, NULL, INVALID_DEVID);
}

/* Initialize the MlDsaComposite private/public key.
 *
 * key  [in]  MlDsaComposite key.
 * heap [in]  Heap hint.
 * devId[in]  Device ID.
 * returns BAD_FUNC_ARG when key is NULL
 */
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
        switch (key->params.type) {
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
int wc_mldsa_composite_set_type(mldsa_composite_key* key, byte type)
{
    int ret = 0;

    /* Validate parameters. */
    if (key == NULL || type <= 0) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        /* Sets the combination type */
        switch (type) {
            case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_ED25519:
            case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_P256:
                break;
            default:
                ret = BAD_FUNC_ARG;
        }

        key->params.type = type;
    }

    return ret;
}

/* Get the level of the MlDsaComposite private/public key.
 *
 * key   [in]  MlDsaComposite key.
 * level [out] The level.
 * returns BAD_FUNC_ARG when key is NULL or level has not been set.
 */
int wc_mldsa_composite_get_type(mldsa_composite_key* key, byte* type)
{
    int ret = 0;

    /* Validate parameters. */
    if (!key || key->params.type <= 0 || !type) {
        ret = BAD_FUNC_ARG;
    }

    /* Only recognized combinations are returned */
    if (ret == 0) {
        switch (key->params.type) {
            case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_ED25519:
            case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_P256:
                break;
            default:
                ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {
        /* Return level. */
        *type = key->params.type;
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
        ForceZero(&key->mldsa_key, sizeof(key->mldsa_key));

        /* Free the classic component */
        switch (key->params.type) {
            
            case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_ED25519: {
                wc_ed25519_free(&key->alt_key.ed25519);
                ForceZero(&key->alt_key.ed25519, sizeof(key->alt_key.ed25519));
            } break;
            
            case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_P256: {
                wc_ecc_free(&key->alt_key.ecc);
                ForceZero(&key->alt_key.ecc, sizeof(key->alt_key.ecc));
            } break;

            default: {
                /* Error */
                WOLFSSL_MSG_VSNPRINTF("Invalid MLDSA Composite type: %d", key->params.type);
            }
        }
#endif /* WOLFSSL_WC_MLDSA_COMPOSITE*/

        /* Ensure all private data is zeroized. */
        ForceZero(key, sizeof(*key));
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

    if (!key || !key->params.type) {
        return BAD_FUNC_ARG;
    }

    switch (key->params.type) {
        case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_ED25519:
            ret = MLDSA44_ED25519_KEY_SIZE;
            break;

        case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_P256:
            ret = MLDSA44_P256_KEY_SIZE; // + wc_ecc_get_curve_size_from_id(ECC_SECP256R1);
            break;

        default:
            /* Error */
            ret = ALGO_ID_E;
    }

    return ret;
}

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
/* Returns the size of a MlDsaComposite private plus public key.
 *
 * @param [in] key  MlDsaComposite private/public key.
 * @return  Private key size on success for set level.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
int wc_mldsa_composite_priv_size(mldsa_composite_key* key) {

    int ret = 0;

    if (!key || !key->params.type) {
        return BAD_FUNC_ARG;
    }

    if (key != NULL) {

        switch (key->params.type) {
            case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_ED25519:
                ret = MLDSA44_ED25519_PRV_KEY_SIZE;
                break;

            case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_P256:
                // ret = DILITHIUM_ML_DSA_44_PRV_KEY_SIZE + wc_ecc_get_curve_size_from_id(ECC_SECP256R1);
                ret = MLDSA44_P256_PRV_KEY_SIZE;
                break;

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

    if (!key || !key->params.type) {
        return BAD_FUNC_ARG;
    }

    switch (key->params.type) {
        case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_ED25519:
            ret = MLDSA44_ED25519_PUB_KEY_SIZE;
            break;

        case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_P256:
            ret = MLDSA44_P256_PUB_KEY_SIZE;
            break;

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

    if (key == NULL || key->params.type <= 0) {
        return BAD_FUNC_ARG;
    }

    switch (key->params.type) {
        case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_ED25519:
            ret = DILITHIUM_ML_DSA_44_SIG_SIZE + ED25519_SIG_SIZE + 12;
            break;

        case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_P256:
            ret = DILITHIUM_ML_DSA_44_SIG_SIZE + wc_ecc_sig_size(&key->alt_key.ecc) + 12;
            break;

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
    
    if (key == NULL || key->params.type <= 0 || key->mldsa_key.level < 2) {
        return BAD_FUNC_ARG;
    }


    ret = wc_dilithium_check_key(&key->mldsa_key);

    switch(key->params.type) {

#if defined(HAVE_ED25519)
        case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_ED25519: {
            if (key->mldsa_key.level != WC_ML_DSA_44)
                return ALGO_ID_E;
            ret = wc_ed25519_check_key(&key->alt_key.ed25519);
        } break;
#endif

#if defined(HAVE_ECC)
        case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_P256: {
            if (key->mldsa_key.level != WC_ML_DSA_44 ||
                ECC_SECP256R1 != wc_ecc_get_curve_id(key->alt_key.ecc.idx)) {
                return ALGO_ID_E;
            }
            ret = wc_ecc_check_key(&key->alt_key.ecc);
        } break;
#endif

        default: {
            ret = ALGO_ID_E;
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
int wc_mldsa_composite_import_public(const byte* in, word32 inLen, mldsa_composite_key* key, word32 type)
{
    int ret = 0;

    /* Validate parameters. */
    if ((in == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Copy the private key data in or copy pointer. */
    #ifndef WOLFSSL_MLDSA_COMPOSITE_ASSIGN_KEY
        XMEMCPY(key->p, in, inLen);
    #else
        key->p = in;
    #endif

        /* Unpacks The SEQUENCE */
        /*
         * TODO:
         *
         * 1. Start the ASN1 parser, open a SEQUENCE
         * 2. Extract the contents of each OCTET STRING
         * 3. Checks the Key Type against the expected one (type)
         * 4. Import the extracted contents into the public key
        */

        /* Public key is set. */
        key->pubKeySet = 1;
    }

    (void)type;

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

    /* Get length passed in for checking. */
    inLen = *outLen;

    // Gets the expected size of the pub key
    *outLen = wc_mldsa_composite_pub_size(key);

    // Checks if the buffer is too small
    if (inLen < *outLen) {
        WOLFSSL_MSG_VSNPRINTF("Output Signature Buffer too small (needed: %d, provided: %d)", *outLen, inLen);
        return BUFFER_E;
    }

    /* Exports the ML-DSA key */
    if (wc_MlDsaKey_ExportPubRaw(&key->mldsa_key, mldsa_Buffer, &mldsa_BufferLen) < 0) {
        WOLFSSL_MSG_VSNPRINTF("error cannot export ML-DSA component's public key\n");
        return BUFFER_E;
    }

    /* Exports the other key */
    switch (key->params.type) {
        case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_ED25519: {
            if ((ret = wc_ed25519_export_public(&key->alt_key.ed25519, 
                    other_Buffer, &other_BufferLen)) < 0) {
                return ret;
            }
        } break;

        case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_P256: {
            word32 pubLenX = 32, pubLenY = 32;
            if ((ret = wc_ecc_export_public_raw(&key->alt_key.ecc, 
                    other_Buffer, &pubLenX, &other_Buffer[32], &pubLenY)) < 0) {
                return ALGO_ID_E;
            }
            other_BufferLen = pubLenX + pubLenY;
        } break;

        default:
            return ALGO_ID_E;
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
        WOLFSSL_MSG_VSNPRINTF("error outLen > tmpLen: %d > %d", *outLen, inLen);
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
 * @param [in]      type    WC_MLDSA_COMPOSITEKEY_TYPE_* values
 * @return  0 otherwise.
 * @return  BAD_FUNC_ARG when a parameter is NULL or privSz is less than size
 *          required for level,
 */
int wc_mldsa_composite_import_private(const byte* priv, word32 privSz,
    mldsa_composite_key* key, wc_MlDsaCompositeType type)
{
    int ret = 0;

    /* Validate parameters. */
    if ((priv == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    /* Unpacks The SEQUENCE */
    /*
        * TODO:
        *
        * 1. Start the ASN1 parser, open a SEQUENCE
        * 2. Extract the contents of each OCTET STRING
        * 3. Checks the Key Type against the expected one (type)
        * 4. Import the extracted contents into the private key
    */

    if (ret == 0) {
        ret = wc_MlDsaKey_ImportPrivRaw(&key->mldsa_key, priv, privSz);
        /* Private key is set. */
        
    }

    (void)type;

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
int wc_mldsa_composite_export_private(mldsa_composite_key* key, byte* out,
    word32* outLen)
{
    int ret = 0;
    word32 inLen;

    MADWOLF_DEBUG0("wc_mldsa_composite_export_private");

    /* Validate parameters */
    if ((key == NULL) || (out == NULL) || (outLen == NULL || *outLen == 0)) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        /* Get length passed in for checking. */
        inLen = *outLen;
        *outLen = wc_mldsa_composite_priv_size(key);
        if (inLen < *outLen) {
            WOLFSSL_MSG_VSNPRINTF("in buffer: sz = %d, required buffer: sz = %d", 
                inLen, *outLen);
            ret = BUFFER_E;
        }
    }
    if (ret == 0) {

        ASNSetData keysASN[3];
            // Set the ML-DSA public key

        byte mldsa_Buffer[DILITHIUM_ML_DSA_87_PUB_KEY_SIZE];
        word32 mldsa_BufferLen = DILITHIUM_ML_DSA_87_PUB_KEY_SIZE;
            // Buffer to hold the ML-DSA public key

        byte other_Buffer[MLDSA_COMPOSITE_MAX_OTHER_KEY_SZ];
        word32 other_BufferLen = MLDSA_COMPOSITE_MAX_OTHER_KEY_SZ;
            // Buffer to hold the public key of the other DSA component

        word32 tmpLen = *outLen;
            // Temporary length

        /* Exports the ML-DSA key */
        /*
         * NOTE: There seem to be a bug in the MsDsa export function
         *       since the wc_MlDsaKey_ExportPrivRaw MACRO points to
         *       an undefined function (wc_dilithium_export_private_raw).
         * 
         *       We use the `wc_dilithium_export_private` function directly.
         */
        
        if (wc_dilithium_export_private(&key->mldsa_key, mldsa_Buffer, &mldsa_BufferLen) < 0) {
            return ALGO_ID_E;
        }

        MADWOLF_DEBUG("mldsa export public: sz = %d", mldsa_BufferLen);

        /* Exports the other key */
        switch (key->params.type) {
            case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_ED25519: {
                if (wc_ed25519_export_private(&key->alt_key.ed25519, other_Buffer, &other_BufferLen) < 0) {
                    return ALGO_ID_E;
                }
            } break;

            case WC_MLDSA_COMPOSITE_TYPE_MLDSA44_P256: {
                // word32 pubLenX = 32, pubLenY = 32;
                // if (wc_ecc_export_public_raw(&key->alt_key.ecc, other_Buffer, &pubLenX, &other_Buffer[32], &pubLenY) < 0) {
                //     return ALGO_ID_E;
                // }
                word32 privLen = 32;
                if (wc_ecc_export_private_only(&key->alt_key.ecc, other_Buffer, &privLen) < 0) {
                    return ALGO_ID_E;
                }
            } break;

            default:
                return ALGO_ID_E;
        }

        MADWOLF_DEBUG("other export private: sz = %d", other_BufferLen);

        // Let's set the ASN1 data
        SetASN_Buffer(&keysASN[MLDSA_COMPASN_IDX_MLDSA], mldsa_Buffer, mldsa_BufferLen);
        SetASN_Buffer(&keysASN[MLDSA_COMPASN_IDX_OTHER], other_Buffer, other_BufferLen);

        // Let's calculate the size of the ASN1 data
        int encSz = 0;
        if (SizeASN_Items(compositeIT, keysASN, 3, &encSz) < 0) {
            return BAD_STATE_E;  
        }
        
        if (encSz > (int)(*outLen)) {
            WOLFSSL_MSG_VSNPRINTF("error encSz > : %d > %d", *outLen, tmpLen);
            return BAD_STATE_E;
        }

        MADWOLF_DEBUG("composite exported private: sz = %d", *outLen);

        // Let's encode the ASN1 data
        if (SetASN_Items(compositeIT, keysASN, 3, out) < 0) {
            return ASN_PARSE_E;
        }
    }

    return ret;
}

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
int wc_mldsa_composite_import_key(const byte* priv, word32 privSz,
    const byte* pub, word32 pubSz, mldsa_composite_key* key)
{
    int ret = 0;

    /* Validate parameters. */
    if ((priv == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if ((pub == NULL) && (pubSz != 0)) {
        ret = BAD_FUNC_ARG;
    }

    /*
     * TODO:
     *
     * Go Through the SEQUENCE and import the keys
     * 
     * 1. Open The ASN1 SEQUENCE
     * 2. For Each ASN1 STRING, process the component
     *    2.a) Parse the key from the content
     *    2.b) If n = 0, import the ML-DSA key
     *    2.c) If n = 1, import the Traditional key
     * 3. Done
     */

    if ((ret == 0) && (pub != NULL)) {
        /* Import public key. */
        ret = wc_MlDsaKey_ImportPrivRaw(&key->mldsa_key, pub, pubSz);
    }

    (void)priv;
    (void)privSz;

    return ret;
}
#endif /* WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY */

int wc_mldsa_composite_export_key(mldsa_composite_key* key, byte* priv, word32 *privSz,
    byte* pub, word32 *pubSz)
{
    int ret;

    /* Export private key only. */
    ret = wc_mldsa_composite_export_private(key, priv, privSz);
    if (ret == 0) {
        /* Export public key. */
        ret = wc_mldsa_composite_export_public(key, pub, pubSz);
    }

    return ret;
}
#endif /* WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY */

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_ASN1
#if defined(WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY)
int wc_MlDsaComposite_PrivateKeyDecode(const byte* input, word32* inOutIdx,
    mldsa_composite_key* key, word32 inSz)
{
    int ret = 0;
    const byte* privKey = NULL;
    const byte* pubKey = NULL;
    word32 privKeyLen = 0;
    word32 pubKeyLen = 0;
    int keytype = 0;

    /* Validate parameters. */
    if ((input == NULL) || (inOutIdx == NULL) || (key == NULL) || (inSz == 0)) {
        ret = BAD_FUNC_ARG;
    }

    keytype = MLDSA44_ED25519k;

    if (ret == 0) {
        /* Decode the asymmetric key and get out private and public key data. */
        ret = DecodeAsymKey_Assign(input, inOutIdx, inSz, &privKey, &privKeyLen,
            &pubKey, &pubKeyLen, keytype);
    }
    if ((ret == 0) && (pubKey == NULL) && (pubKeyLen == 0)) {
        // /* Check if the public key is included in the private key. */
        // if ((key->level == WC_ML_DSA_44) &&
        //     (privKeyLen == DILITHIUM_LEVEL2_PRV_KEY_SIZE)) {
        //     pubKey = privKey + DILITHIUM_LEVEL2_KEY_SIZE;
        //     pubKeyLen = DILITHIUM_LEVEL2_PUB_KEY_SIZE;
        //     privKeyLen -= DILITHIUM_LEVEL2_PUB_KEY_SIZE;
        // }
        // else if ((key->level == WC_ML_DSA_65) &&
        //          (privKeyLen == DILITHIUM_LEVEL3_PRV_KEY_SIZE)) {
        //     pubKey = privKey + DILITHIUM_LEVEL3_KEY_SIZE;
        //     pubKeyLen = DILITHIUM_LEVEL3_PUB_KEY_SIZE;
        //     privKeyLen -= DILITHIUM_LEVEL3_PUB_KEY_SIZE;
        // }
        // else if ((key->level == WC_ML_DSA_87) &&
        //          (privKeyLen == DILITHIUM_LEVEL5_PRV_KEY_SIZE)) {
        //     pubKey = privKey + DILITHIUM_LEVEL5_KEY_SIZE;
        //     pubKeyLen = DILITHIUM_LEVEL5_PUB_KEY_SIZE;
        //     privKeyLen -= DILITHIUM_LEVEL5_PUB_KEY_SIZE;
        // }
    }

    if (ret == 0) {
        /* Check whether public key data was found. */
#if defined(WOLFSSL_DILITHIUM_PUBLIC_KEY)
        if (pubKeyLen == 0)
#endif
        {
            /* No public key data, only import private key data. */
            ret = wc_dilithium_import_private(privKey, privKeyLen, &key->mldsa_key);
        }
#if defined(WOLFSSL_DILITHIUM_PUBLIC_KEY)
        else {
            /* Import private and public key data. */
            ret = wc_dilithium_import_key(privKey, privKeyLen, pubKey,
                pubKeyLen, &key->mldsa_key);
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
    mldsa_composite_key* key, word32 inSz)
{
    int ret = 0;
    const byte* pubKey;
    word32 pubKeyLen = 0;

    /* Validate parameters. */
    if ((input == NULL) || (inOutIdx == NULL) || (key == NULL) || (inSz == 0)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Try to import the key directly. */
        ret = wc_mldsa_composite_import_public(input, inSz, key, key->params.type);
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
            /* Get OID sum for type. */
            if (key->params.type == WC_MLDSA_COMPOSITE_TYPE_MLDSA44_ED25519) {
                keytype = MLDSA44_ED25519k;
            }
            else if (key->params.type == WC_MLDSA_COMPOSITE_TYPE_MLDSA44_P256) {
                keytype = MLDSA44_P256k;
            }
            else {
                /* Level not set. */
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
            if (key->params.type == WC_MLDSA_COMPOSITE_TYPE_MLDSA44_ED25519) {
                oid = mldsa44_ed25519_oid;
                oidLen = (int)sizeof(mldsa44_ed25519_oid);
            }
            else
        #endif
        #ifndef WOLFSSL_NO_MLDSA44_P256
            if (key->level == WC_MLDSA_COMPOSITE_TYPE_MLDSA44_P256) {
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
                ret = wc_mldsa_composite_import_public(pubKey, pubKeyLen, key, key->params.type);
            }
        }
    }
    return ret;
}

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_ASN1

#ifdef WC_ENABLE_ASYM_KEY_EXPORT
int wc_MlDsaComposite_PublicKeyToDer(mldsa_composite_key* key, byte* output, word32 len,
    int withAlg)
{
    int ret = 0;
    int keytype = 0;
    int pubKeyLen = 0;

    /* Validate parameters. */
    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    /* Check we have a public key to encode. */
    if ((ret == 0) && (!key->pubKeySet)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Get OID and length for level. */
        if (key->params.type == WC_MLDSA_COMPOSITE_TYPE_MLDSA44_ED25519) {
            keytype = MLDSA44_ED25519k;
            pubKeyLen = MLDSA44_ED25519_KEY_SIZE;
        }
        else if (key->params.type == WC_MLDSA_COMPOSITE_TYPE_MLDSA44_P256) {
            keytype = MLDSA44_P256k;
            pubKeyLen = MLDSA44_P256_KEY_SIZE;
        }
        else {
            /* Level not set. */
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {
        ret = SetAsymKeyDerPublic(key->p, pubKeyLen, output, len, keytype,
            withAlg);
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
    int ret = BAD_FUNC_ARG;

    /* Validate parameters and check private key set. */
    if ((key != NULL) && key->prvKeySet) {
        // ret = wc_Dilithium_PrivateKeyToDer(&key->mldsa_key, len);
        ret = NOT_COMPILED_IN;
    }

    (void)output;
    (void)len;

    return ret;
}

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY

int wc_MlDsaComposite_KeyToDer(mldsa_composite_key* key, byte* output, word32 len)
{
    int ret = BAD_FUNC_ARG;

    // /* Validate parameters and check public and private key set. */
    // if ((key != NULL) && key->prvKeySet && key->pubKeySet) {
    //     /* Create DER for level. */
    //     if (key->level == WC_ML_DSA_44) {
    //         ret = SetAsymKeyDer(key->k, DILITHIUM_LEVEL2_KEY_SIZE, key->p,
    //             DILITHIUM_LEVEL2_PUB_KEY_SIZE, output, len, DILITHIUM_LEVEL2k);
    //     }
    //     else if (key->level == WC_ML_DSA_65) {
    //         ret = SetAsymKeyDer(key->k, DILITHIUM_LEVEL3_KEY_SIZE, key->p,
    //             DILITHIUM_LEVEL3_PUB_KEY_SIZE, output, len, DILITHIUM_LEVEL3k);
    //     }
    //     else if (key->level == WC_ML_DSA_87) {
    //         ret = SetAsymKeyDer(key->k, DILITHIUM_LEVEL5_KEY_SIZE, key->p,
    //             DILITHIUM_LEVEL5_PUB_KEY_SIZE, output, len, DILITHIUM_LEVEL5k);
    //     }
    // }
    
    ret = NOT_COMPILED_IN;
    (void)output;
    (void)len;
    (void)key;

    return ret;
}
#endif /* WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY */
#endif /* WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY */

#endif /* !WOLFSSL_MLDSA_COMPOSITE_NO_ASN1 */


#endif /* HAVE_MLDSA_COMPOSITE */
