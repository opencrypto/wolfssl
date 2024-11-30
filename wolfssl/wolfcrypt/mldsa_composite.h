/* mldsa_composite.h
 */

/*!
    \file wolfssl/wolfcrypt/mldsa_composite.h
*/

/* Interfaces for Composite Signatures */

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

/* in case user set HAVE_ECC there */
#include <wolfssl/wolfcrypt/settings.h>

#ifndef WOLF_CRYPT_MLDSA_COMPOSITE_H
#define WOLF_CRYPT_MLDSA_COMPOSITE_H

#ifndef WOLF_CRYPT_TYPES_H
#include <wolfssl/wolfcrypt/types.h>
#endif

#ifndef WOLF_CRYPT_ASN_H
#include <wolfssl/wolfcrypt/asn.h>
#endif

#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif

#ifndef WOLFSSL_LOGGING_H
#include <wolfssl/wolfcrypt/logging.h>
#endif

#if defined(HAVE_MLDSA_COMPOSITE)
#include <wolfssl/wolfcrypt/dilithium.h>

#if defined(HAVE_ECC)
#include <wolfssl/wolfcrypt/ecc.h>
#endif

#if defined(HAVE_ED25519)
#include <wolfssl/wolfcrypt/ed25519.h>
#endif

#if defined(HAVE_ED448)
#include <wolfssl/wolfcrypt/ed448.h>
#endif

#if defined(HAVE_FALCON)
#include <wolfssl/wolfcrypt/falcon.h>
#endif

#ifndef NO_RSA
#include <wolfssl/wolfcrypt/rsa.h>
#endif

#ifdef __cplusplus
    extern "C" {
#endif

/* Macros Definitions */

#ifdef HAVE_MLDSA_COMPOSITE

#if defined(WOLFSSL_MLDSA_COMPOSITE_NO_MAKE_KEY) && \
        defined(WOLFSSL_MLDSA_COMPOSITE_NO_SIGN) && \
        !defined(WOLFSSL_MLDSA_COMPOSITE_NO_VERIFY) && \
        !defined(WOLFSSL_MLDSA_COMPOSITE_VERIFY_ONLY)
    #define WOLFSSL_MLDSA_COMPOSITE_VERIFY_ONLY
#endif
#ifdef WOLFSSL_MLDSA_COMPOSITE_VERIFY_ONLY
    #ifndef WOLFSSL_MLDSA_COMPOSITE_NO_MAKE_KEY
        #define WOLFSSL_MLDSA_COMPOSITE_NO_MAKE_KEY
    #endif
    #ifndef WOLFSSL_MLDSA_COMPOSITE_NO_SIGN
        #define WOLFSSL_MLDSA_COMPOSITE_NO_SIGN
    #endif
#endif

#if !defined(WOLFSSL_MLDSA_COMPOSITE_NO_MAKE_KEY) || \
        !defined(WOLFSSL_MLDSA_COMPOSITE_NO_VERIFY)
    #define WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
#endif
#if !defined(WOLFSSL_MLDSA_COMPOSITE_NO_MAKE_KEY) || \
        !defined(WOLFSSL_MLDSA_COMPOSITE_NO_SIGN)
    #define WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY
#endif

#if defined(WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY) && \
        defined(WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY) && \
        !defined(WOLFSSL_MLDSA_COMPOSITE_NO_CHECK_KEY) && \
        !defined(WOLFSSL_MLDSA_COMPOSITE_CHECK_KEY)
    #define WOLFSSL_MLDSA_COMPOSITE_CHECK_KEY
#endif

#define RSA1024_KEY_SIZE                256
#define RSA1024_SIG_SIZE                128
#define RSA1024_PUB_KEY_SIZE            192
#define RSA1024_PRV_KEY_SIZE            608

#define RSA2048_KEY_SIZE                512
#define RSA2048_SIG_SIZE                256
#define RSA2048_PUB_KEY_SIZE            270
#define RSA2048_PRV_KEY_SIZE            1191

#define RSA3072_KEY_SIZE                768
#define RSA3072_SIG_SIZE                384
#define RSA3072_PUB_KEY_SIZE            398
#define RSA3072_PRV_KEY_SIZE            1768

#define RSA4096_KEY_SIZE                1024
#define RSA4096_SIG_SIZE                512
#define RSA4096_PUB_KEY_SIZE            526
#define RSA4096_PRV_KEY_SIZE            2350

// Sizes Returned by the API Functions
// TODO: @madwolf Values need to be checked

#define MLDSA44_RSA2048_KEY_SIZE        DILITHIUM_ML_DSA_44_KEY_SIZE + RSA2048_KEY_SIZE + 12
#define MLDSA44_RSA2048_SIG_SIZE        DILITHIUM_ML_DSA_44_SIG_SIZE + RSA2048_SIG_SIZE + 12 + 2
#define MLDSA44_RSA2048_PUB_KEY_SIZE    DILITHIUM_ML_DSA_44_PUB_KEY_SIZE + RSA2048_PUB_KEY_SIZE + 14
#define MLDSA44_RSA2048_PRV_KEY_SIZE    DILITHIUM_ML_DSA_44_PRV_KEY_SIZE + RSA2048_PRV_KEY_SIZE + 14 + 2

#define MLDSA44_NISTP256_KEY_SIZE       DILITHIUM_ML_DSA_44_KEY_SIZE + 32 + 12
#define MLDSA44_NISTP256_SIG_SIZE       DILITHIUM_ML_DSA_44_SIG_SIZE + 72 + 12
#define MLDSA44_NISTP256_PUB_KEY_SIZE   DILITHIUM_ML_DSA_44_PUB_KEY_SIZE + 64 + 12
#define MLDSA44_NISTP256_PRV_KEY_SIZE   DILITHIUM_ML_DSA_44_KEY_SIZE + 32 + 12

/*
 * NOTE: There seems to be an issue with the _PRV_ sizes definitions
 *       that seem to include the _PUB_ sizes twice.
 * #define MLDSA44_NISTP256_PRV_KEY_SIZE   \
 *      MLDSA44_NISTP256_PUB_KEY_SIZE + MLDSA44_NISTP256_SHA256_KEY_SIZE)
*/

#define MLDSA44_ED25519_KEY_SIZE       DILITHIUM_ML_DSA_44_KEY_SIZE + ED25519_KEY_SIZE + ED25519_PUB_KEY_SIZE + 10
#define MLDSA44_ED25519_SIG_SIZE       DILITHIUM_ML_DSA_44_SIG_SIZE + ED25519_SIG_SIZE + 12
#define MLDSA44_ED25519_PUB_KEY_SIZE   DILITHIUM_ML_DSA_44_PUB_KEY_SIZE + ED25519_PUB_KEY_SIZE + 12
#define MLDSA44_ED25519_PRV_KEY_SIZE   DILITHIUM_ML_DSA_44_PRV_KEY_SIZE + ED25519_KEY_SIZE + 12

#define MLDSA44_BPOOL256_KEY_SIZE      DILITHIUM_ML_DSA_44_KEY_SIZE + 32 + 12
#define MLDSA44_BPOOL256_SIG_SIZE      DILITHIUM_ML_DSA_44_SIG_SIZE + 72 + 12
#define MLDSA44_BPOOL256_PUB_KEY_SIZE  DILITHIUM_ML_DSA_44_PUB_KEY_SIZE + 64 + 12
#define MLDSA44_BPOOL256_PRV_KEY_SIZE  DILITHIUM_ML_DSA_44_PRV_KEY_SIZE + 32 + 12

/* NOTE: There seems to be an issue with the _PRV_ sizes definitions
 *       that seem to include the _PUB_ sizes twice.
 * #define MLDSA44_ED25519_PRV_KEY_SIZE  \
 *     (MLDSA44_ED25519_PUB_KEY_SIZE + MLDSA44_ED25519_KEY_SIZE)
*/

#define MLDSA65_NISTP256_KEY_SIZE           DILITHIUM_ML_DSA_65_KEY_SIZE + 32 + 16 + 7
#define MLDSA65_NISTP256_SIG_SIZE           DILITHIUM_ML_DSA_65_SIG_SIZE + 72 + 16 + 7
#define MLDSA65_NISTP256_PUB_KEY_SIZE       DILITHIUM_ML_DSA_65_PUB_KEY_SIZE + 64 + 16 + 7
#define MLDSA65_NISTP256_PRV_KEY_SIZE       DILITHIUM_ML_DSA_65_PRV_KEY_SIZE + 32 + 16 + 7

#define MLDSA65_ED25519_KEY_SIZE       DILITHIUM_ML_DSA_65_KEY_SIZE + ED25519_KEY_SIZE + 16 + 7
#define MLDSA65_ED25519_SIG_SIZE       DILITHIUM_ML_DSA_65_SIG_SIZE + ED25519_SIG_SIZE + 16 + 7
#define MLDSA65_ED25519_PUB_KEY_SIZE   DILITHIUM_ML_DSA_65_PUB_KEY_SIZE + ED25519_PUB_KEY_SIZE + 16 + 7
#define MLDSA65_ED25519_PRV_KEY_SIZE   DILITHIUM_ML_DSA_65_PRV_KEY_SIZE + ED25519_PRV_KEY_SIZE + 16 + 7

#define MLDSA65_RSA3072_KEY_SIZE       DILITHIUM_ML_DSA_65_KEY_SIZE + RSA3072_KEY_SIZE + 16 + 2
#define MLDSA65_RSA3072_SIG_SIZE       DILITHIUM_ML_DSA_65_SIG_SIZE + RSA3072_SIG_SIZE + 16 + 2
#define MLDSA65_RSA3072_PUB_KEY_SIZE   DILITHIUM_ML_DSA_65_PUB_KEY_SIZE + RSA3072_PUB_KEY_SIZE + 16
#define MLDSA65_RSA3072_PRV_KEY_SIZE   DILITHIUM_ML_DSA_65_PRV_KEY_SIZE + RSA3072_PRV_KEY_SIZE + 16

#define MLDSA65_RSA4096_KEY_SIZE       DILITHIUM_ML_DSA_65_KEY_SIZE + RSA4096_KEY_SIZE + 16 + 2
#define MLDSA65_RSA4096_SIG_SIZE       DILITHIUM_ML_DSA_65_SIG_SIZE + RSA4096_SIG_SIZE + 16 + 2
#define MLDSA65_RSA4096_PUB_KEY_SIZE   DILITHIUM_ML_DSA_65_PUB_KEY_SIZE + RSA4096_PUB_KEY_SIZE + 16
#define MLDSA65_RSA4096_PRV_KEY_SIZE   DILITHIUM_ML_DSA_65_PRV_KEY_SIZE + RSA4096_PRV_KEY_SIZE + 16

#define MLDSA87_NISTP384_KEY_SIZE      DILITHIUM_ML_DSA_87_KEY_SIZE + 48 + 16 + 7
#define MLDSA87_NISTP384_SIG_SIZE      DILITHIUM_ML_DSA_87_SIG_SIZE + 96 + 16 + 7
#define MLDSA87_NISTP384_PUB_KEY_SIZE  DILITHIUM_ML_DSA_87_PUB_KEY_SIZE + 64 + 16 + 7
#define MLDSA87_NISTP384_PRV_KEY_SIZE  DILITHIUM_ML_DSA_87_PRV_KEY_SIZE + 48 + 16 + 7

#define MLDSA87_ED448_KEY_SIZE         DILITHIUM_ML_DSA_87_KEY_SIZE + ED448_KEY_SIZE + 16 + 7
#define MLDSA87_ED448_SIG_SIZE         DILITHIUM_ML_DSA_87_SIG_SIZE + ED448_SIG_SIZE + 16 + 7
#define MLDSA87_ED448_PUB_KEY_SIZE     DILITHIUM_ML_DSA_87_PUB_KEY_SIZE + ED448_PUB_KEY_SIZE + 16 + 7
#define MLDSA87_ED448_PRV_KEY_SIZE     DILITHIUM_ML_DSA_87_PRV_KEY_SIZE + ED448_PRV_KEY_SIZE + 16 + 7

#define MLDSA_COMPOSITE_MAX_OTHER_SIG_SZ RSA4096_SIG_SIZE + 16 + 7
#define MLDSA_COMPOSITE_MAX_OTHER_KEY_SZ RSA4096_PRV_KEY_SIZE 

#define MLDSA_COMPOSITE_MIN_KEY_SIZE   MLDSA_ED25519_KEY_SIZE
#define MLDSA_COMPOSITE_MAX_KEY_SIZE   DILITHIUM_LEVEL5_KEY_SIZE + MLDSA_COMPOSITE_MAX_OTHER_KEY_SZ + 16 + 7
#define MLDSA_COMPOSITE_MIN_SIG_SIZE   MLDSA_ED25519_SIG_SIZE
#define MLDSA_COMPOSITE_MAX_SIG_SIZE   DILITHIUM_LEVEL5_SIG_SIZE + MLDSA_COMPOSITE_MAX_OTHER_SIG_SZ + 16 + 7

#define MLDSA_COMPOSITE_MIN_PUB_KEY_SIZE MLDSA44_ED25519_PUB_KEY_SIZE
#define MLDSA_COMPOSITE_MAX_PUB_KEY_SIZE DILITHIUM_ML_DSA_87_PUB_KEY_SIZE + MLDSA_COMPOSITE_MAX_OTHER_KEY_SZ + 16 + 7 + 30
#define MLDSA_COMPOSITE_MIN_PRV_KEY_SIZE MLDSA44_ED25519_PRV_KEY_SIZE
#define MLDSA_COMPOSITE_MAX_PRV_KEY_SIZE DILITHIUM_ML_DSA_87_PRV_KEY_SIZE + MLDSA_COMPOSITE_MAX_OTHER_KEY_SZ + 16 + 7 + 300

#ifdef WOLF_PRIVATE_KEY_ID
#define MLDSA_COMPOSITE_MAX_ID_LEN    32
#define MLDSA_COMPOSITE_MAX_LABEL_LEN 32
#endif

                    // ===============
                    // Data Structures
                    // ===============


enum mldsa_composite_type {
    WC_MLDSA_COMPOSITE_UNDEF = 0,

    // ---------- Draft 2 ----------
    D2_WC_MLDSA44_RSAPSS2048_SHA256,
    D2_WC_MLDSA44_RSA2048_SHA256,
    D2_WC_MLDSA44_NISTP256_SHA256,
    // D2_WC_MLDSA44_BPOOL256_SHA256,
    D2_WC_MLDSA44_ED25519_SHA256,
    D2_WC_MLDSA65_RSAPSS3072_SHA512,
    D2_WC_MLDSA65_RSA3072_SHA512,
    D2_WC_MLDSA65_NISTP256_SHA512,
    D2_WC_MLDSA65_BPOOL256_SHA512,
    D2_WC_MLDSA65_ED25519_SHA512,
    D2_WC_MLDSA87_NISTP384_SHA512,
    D2_WC_MLDSA87_BPOOL384_SHA512,
    D2_WC_MLDSA87_ED448_SHA512,

    // ---------- Draft 3 ----------
    WC_MLDSA44_RSAPSS2048_SHA256,
    WC_MLDSA44_RSA2048_SHA256,
    WC_MLDSA44_ED25519_SHA256,
    WC_MLDSA44_NISTP256_SHA256,
    // WC_MLDSA44_BPOOL256_SHA256,
    WC_MLDSA65_RSAPSS3072_SHA384,
    WC_MLDSA65_RSA3072_SHA384,
    WC_MLDSA65_RSAPSS4096_SHA384,
    WC_MLDSA65_RSA4096_SHA384,
    WC_MLDSA65_NISTP256_SHA384,
    WC_MLDSA65_BPOOL256_SHA384,
    WC_MLDSA65_ED25519_SHA384,
    WC_MLDSA87_NISTP384_SHA384,
    WC_MLDSA87_BPOOL384_SHA384,
    WC_MLDSA87_ED448_SHA384,
};

// Size of the MLDSA Composite Types
#define MLDSA_COMPOSITE_TYPE_MIN                         1
#define MLDSA_COMPOSITE_TYPE_MAX                         26

// Size of the MLDSA Composite Types (with the Unknown Type)
#define MLDSA_COMPOSITE_TYPE_SZ                          27

// Size of the OID Data
#define MLDSA_COMPOSITE_OID_DATA_SZ                      13

// Max Size for the composite tbs data
#define MLDSA_COMPOSITE_TBS_DATA_MAX_SZ                  333
#define MLDSA_COMPOSITE_TBS_DATA_MIN_SZ                  46

// OID Data (see mldsa_composite.c for the actual data)
extern const byte mldsa_composite_oid_data[][13];

// Composite Key Parameters
struct mldsa_composite_params {

    enum mldsa_composite_type type;

    union {

        struct {
            word16 bits;
            enum wc_HashType mask_gen_param;
            enum wc_HashType digest_alg_param;
            int salt_len;
        } rsapss;

        struct rsa {
            word16 bits;
            int padding; /* WC_RSA_PKCSV15_PAD or WC_RSA_PSS_PAD */
        } rsa;
        
        struct ecc {
            ecc_curve_id curve_id;
        } ecc;

        struct mldsa{
            byte level;
        } mldsa;

        struct fndsa {
            byte level;
        } fndsa;

    } values; 
};

#endif

// See ans_public.h for type definitions
struct mldsa_composite_key {

    int devId;
        /* should use wc_CryptoCb_DefaultDevID() */

#ifdef WOLF_CRYPTO_CB
    void devCtx;
#endif /* WOLF_CRYPTO_CB */

#ifdef WOLF_PRIVATE_KEY_ID
    byte * id;
    int idLen;

    byte * label;
    int labelLen;
#endif /* WOLF_PRIVATE_KEY_ID */
    
    byte pubKeySet;
        /* Public Key Set Flag */

    byte prvKeySet;
        /* Private Key Set Flag */

    void* heap;
        /* heap hint */

    enum mldsa_composite_type compType;
        /* Type of Composite Key */

    struct mldsa_composite_params mldsa_kp;
        /* PQ Key Parameters */

    MlDsaKey * mldsa_key;
        /* ML-DSA Key */

    struct mldsa_composite_params alkey_kp;
        /* Alternative Key Parameters */

    union {
        RsaKey * rsa; /* RSAOAEPk, RSAPSSk */
        ecc_key * ecc; /* ECDSAk */
        ed25519_key * ed25519; /* ED25519k */
        ed448_key * ed448; /* ED448k */
    } alt_key;
        /* Alternative Key */
};

#ifndef WC_MLDSA_COMPOSITEKEY_TYPE_DEFINED
    typedef struct mldsa_composite_key mldsa_composite_key;
    typedef enum wc_mldsa_composite_type wc_MlDsaCompositeType;
    typedef struct mldsa_composite_params wc_MlDsaCompositeKeyParams;
    #define mldsa_composite_key MlDsaCompositeKey
    #define WC_MLDSA_COMPOSITEKEY_TYPE_DEFINED
    const mldsa_composite_key mldsacomposite_params[] = {
        { MLDSA44_ED25519k, SHA256, { { DILITHIUM_LEVEL2k, 2 }, { } }, NULL, { NULL } },
        { MLDSA44_P256k, SHA256, { { DILITHIUM_LEVEL2k, 2 }, { ECC_SECP256R1 } }, NULL, { NULL } },
    };
#endif

/* Functions */

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_MAKE_KEY
/* Make a key from a random seed.
 *
 * @param [in, out] key  Dilithium key.
 * @param [in]      type ML-DSA composite type.
 * @param [in]      rng  Random number generator.
 * @return  0 on success.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
WOLFSSL_API int wc_mldsa_composite_make_key(mldsa_composite_key       * key, 
                                            enum mldsa_composite_type   type, 
                                            WC_RNG                    * rng);
#endif /* ! WOLFSSL_MLDSA_COMPOSITE_NO_MAKE_KEY */

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_VERIFY

/* Verify signature of message using public key.
 * @param [in]      sig     Signature to verify message.
 * @param [in]      sigLen  Length of message in bytes.
 * @param [in]      msg     Message to verify.
 * @param [in]      msgLen  Length of message in bytes.
 * @param [out]     res     Result of verification.
 * @param [in, out] key     ML-DSA composite key.
 * @return  0 on success.
 * @return  SIG_VERIFY_E when hint is malformed.
 * @return  BUFFER_E when the length of the signature does not match
 *          parameters.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
WOLFSSL_API int wc_mldsa_composite_verify_msg(const byte* sig, word32 sigLen, const byte* msg,
    word32 msgLen, int* res, mldsa_composite_key* key);

/* Verify signature of message using public key and context.
 * @param [in]      sig     Signature to verify message.
 * @param [in]      sigLen  Length of message in bytes.
 * @param [in]      msg     Message to verify.
 * @param [in]      msgLen  Length of message in bytes.
 * @param [out]     res     Result of verification.
 * @param [in, out] key     ML-DSA composite key.
 * @param [in]      context  Extra signing data.
 * @param [in]      contextLen  Length of extra signing data
 * @return  0 on success.
 * @return  SIG_VERIFY_E when hint is malformed.
 * @return  BUFFER_E when the length of the signature does not match
 *          parameters.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
WOLFSSL_API int wc_mldsa_composite_verify_msg_ex(const byte* sig, word32 sigLen, const byte* msg,
    word32 msgLen, int* res, mldsa_composite_key* key, const byte* context, byte contextLen);

#endif /* !WOLFSSL_MLDSA_COMPOSITE_NO_VERIFY */

#ifndef WOLFSSL_DILITHIUM_VERIFY_ONLY
/* Sign a message with the key and a random number generator.
 *
 * @param [in]      in      Message data to sign
 * @param [in]      inLen   Length of the data to sign in bytes.
 * @param [out]     out     Buffer to hold signature.
 * @param [in, out] outLen  On in, length of buffer in bytes.
 *                          On out, the length of the signature in bytes.
 * @param [in]      key     ML-DSA composite key.
 * @param [in, out] rng     Random number generator.
 * @return  0 on success.
 * @return  BUFFER_E when the signature buffer is too small.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
WOLFSSL_API int wc_mldsa_composite_sign_msg(const byte* in, word32 inLen, byte* out,
    word32 *outLen, mldsa_composite_key* key, WC_RNG* rng);

/* Sign a message with the key and a random number generator.
 *
 * @param [in]      in      Message data to sign
 * @param [in]      inLen   Length of the data to sign in bytes.
 * @param [out]     out     Buffer to hold signature.
 * @param [in, out] outLen  On in, length of buffer in bytes.
 *                          On out, the length of the signature in bytes.
 * @param [in]      key     ML-DSA composite key.
 * @param [in, out] rng     Random number generator.
 * @param [in]      context  Extra signing data.
 * @param [in]      contextLen  Length of extra signing data
 * @return  0 on success.
 * @return  BUFFER_E when the signature buffer is too small.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
WOLFSSL_API int wc_mldsa_composite_sign_msg_ex(const byte* in, word32 inLen, byte* out,
    word32 *outLen, mldsa_composite_key* key, WC_RNG* rng,
    const byte* context, byte contextLen);

#endif

/* Initialize the MlDsaComposite private/public key.
 *
 * @param [in, out] key     ML-DSA composite key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL
 */
WOLFSSL_API int wc_mldsa_composite_init(mldsa_composite_key* key);

/* Initialize the MlDsaComposite private/public key.
 *
 * @param [in, out] key     ML-DSA composite key.
 * @param [in]      heap    Heap hint.
 * @param [in]      devId   Device ID.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL
 */
WOLFSSL_API int wc_mldsa_composite_init_ex(mldsa_composite_key* key, void* heap, int devId);

/* Clears the memory associated with the internals of a mldsa composite key.
 *
 * @param [in, out] key     ML-DSA composite key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL
 */
WOLFSSL_API int wc_mldsa_composite_clear(mldsa_composite_key* key);

#ifdef WOLF_PRIVATE_KEY_ID
WOLFSSL_API
int wc_mldsa_composite_init_id(mldsa_composite_key* key, const unsigned char* id, int len,
    void* heap, int devId);
WOLFSSL_API
int wc_mldsa_composite_init_label(mldsa_composite_key* key, const char* label, void* heap,
    int devId);
#endif

/* Set the level of the MlDsaComposite private/public key.
 *
 * key   [out]  MlDsaComposite key.
 * level [in]   One of WC_MLDSA_COMPOSITE_TYPE_* values.
 * returns BAD_FUNC_ARG when key is NULL or level is a bad values.
 */
WOLFSSL_API int wc_mldsa_composite_key_set_level(mldsa_composite_key* key, int wc_mldsa_composite_type);

/* Get the level of the MlDsaComposite private/public key.
 *
 * key   [in]  MlDsaComposite key.
 * returns a value from enum mldsa_composite_type.
 * returns BAD_FUNC_ARG when key is NULL or level has not been set.
 */
WOLFSSL_API int wc_mldsa_composite_key_get_level(const mldsa_composite_key* key);

/* Get the KeySum of the MlDsaComposite private/public key.
 *
 * key   [in]  MlDsaComposite key.
 * returns enum Key_Sum value of the key.
 * returns BAD_FUNC_ARG when key is NULL or not initialized.
 */
WOLFSSL_API int wc_mldsa_composite_key_get_keySum(const mldsa_composite_key * key);

/*
* Convert the KeySum to the MlDsaComposite type.
*
* keytype_sum  [in]  enum Key_Sum value.
* returns enum mldsa_composite_type value.
* returns BAD_FUNC_ARG when keytype_sum is not a valid value.
*/
WOLFSSL_API int wc_KeySum_to_composite_level(const enum Key_Sum keytype_sum);

/*
* Convert the MlDsaComposite type to the KeySum.
*
* type  [in]  enum mldsa_composite_type value.
* returns enum Key_Sum value.
* returns BAD_FUNC_ARG when type is not a valid value.
*/
WOLFSSL_API int wc_composite_level_to_keySum(const enum mldsa_composite_type type);

/* Get the type of the composite key.
 *
 * key   [in]  MlDsaComposite key.
 * returns a value from enum CertType for the key.
 * returns BAD_FUNC_ARG when key is NULL or level has not been set.
 */
WOLFSSL_API int wc_mldsa_composite_get_certType(const mldsa_composite_key* key);

/* Get the type of the composite key.
 *
 * key   [in]  MlDsaComposite key.
 * returns a value from enum CertType for the key.
 * returns BAD_FUNC_ARG when key is NULL or level has not been set.
 */
WOLFSSL_API int wc_mldsa_composite_key_level_to_certType(int mldsa_composite_level);

/* Clears the MlDsaComposite key data
 *
 * key  [in]  MlDsaComposite key.
 */
WOLFSSL_API void wc_mldsa_composite_free(mldsa_composite_key* key);

#ifdef WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY
/* Returns the size of a MlDsaComposite private key.
 *
 * @param [in] key  Dilithium private/public key.
 * @return  Private key size on success for set level.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
WOLFSSL_API int wc_mldsa_composite_size(mldsa_composite_key* key);
#endif

#if defined(WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY) && \
    defined(WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY)
/* Returns the size of a MlDsaComposite private plus public key.
 *
 * @param [in] key  MlDsaComposite private/public key.
 * @return  Private key size on success for set level.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
WOLFSSL_API int wc_mldsa_composite_priv_size(mldsa_composite_key* key);
#endif

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
/* Returns the size of a MlDsaComposite public key.
 *
 * @param [in] key  MlDsaComposite private/public key.
 * @return  Public key size on success for set level.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
WOLFSSL_API int wc_mldsa_composite_pub_size(mldsa_composite_key* key);
#endif

/* Returns the size of a MlDsaComposite public key.
 *
 * @param [in]  key  MlDsaComposite private/public key.
 * @param [out] len  Public key size for set level.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
WOLFSSL_API int wc_MlDsaCompositeKey_GetPubLen(mldsa_composite_key* key, int* len);

#if !defined(WOLFSSL_MLDSA_COMPOSITE_NO_SIGN) || !defined(WOLFSSL_MLDSA_COMPOSITE_NO_VERIFY)
/* Returns the size of a MlDsaComposite signature.
 *
 * @param [in] key  MlDsaComposite private/public key.
 * @return  Signature size on success for set level.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
WOLFSSL_API int wc_mldsa_composite_sig_size(mldsa_composite_key* key);
#endif

/* Returns the size of a MlDsaComposite signature.
 *
 * @param [in]  key  MlDsaComposite private/public key.
 * @param [out] len  Signature size for set level.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
WOLFSSL_API int wc_MlDsaCompositeKey_GetSigLen(mldsa_composite_key* key, int* len);

#ifdef WOLFSSL_MLDSA_COMPOSITE_CHECK_KEY
/* Check the public key of the MlDsaComposite key matches the private key.
 *
 * @param [in] key  MlDsaComposite private/public key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL or no private key available,
 * @return  PUBLIC_KEY_E when the public key is not set or doesn't match,
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
WOLFSSL_API int wc_mldsa_composite_check_key(mldsa_composite_key* key);
#endif

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
/* Import a MlDsaComposite public key from a byte array.
 *
 * Public key encoded in big-endian.
 *
 * @param [in]      in     Array holding public key.
 * @param [in]      inLen  Number of bytes of data in array.
 * @param [in]      type   ML-DSA Composite Type (e.g., WC_MLDSA44_NISTP256_SHA256)
 * @param [in, out] key    MlDsaComposite public key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when in or key is NULL or key format is not supported.
 */
WOLFSSL_API int wc_mldsa_composite_import_public(const byte* in, word32 inLen,
    mldsa_composite_key* key, enum mldsa_composite_type type);

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
WOLFSSL_API int wc_mldsa_composite_export_public(mldsa_composite_key* key, byte* out, word32* outLen);
#endif /* WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY */

#ifdef WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY
/* Import a mldsa_composite private key from a byte array.
 *
 * @param [in]      priv    Array holding private key.
 * @param [in]      privSz  Number of bytes of data in array.
 * @param [in, out] key     mldsa_composite private key.
 * @return  0 otherwise.
 * @return  BAD_FUNC_ARG when a parameter is NULL or privSz is less than size
 *          required for level,
 */
WOLFSSL_API int wc_mldsa_composite_import_private(const byte* priv, word32 privSz,
    mldsa_composite_key* key, enum mldsa_composite_type type);

/* Export the mldsa_composite private key.
 *
 * @param [in]      key     mldsa_composite private key.
 * @param [out]     out     Array to hold private key.
 * @param [in, out] outLen  On in, the number of bytes in array.
 *                          On out, the number bytes put into array.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BUFFER_E when outLen is less than DILITHIUM_LEVEL2_KEY_SIZE.
 */
WOLFSSL_API int wc_mldsa_composite_export_private(mldsa_composite_key* key, byte* out, word32* outLen);

/* Define for import private only */
#define wc_mldsa_composite_import_private_only    wc_mldsa_composite_import_private

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
/* Import a mldsa_composite private and public keys from byte array(s).
 *
 * @param [in] priv    Array holding private key or private+public keys
 * @param [in] privSz  Number of bytes of data in private key array.
 * @param [in] pub     Array holding public key (or NULL).
 * @param [in] pubSz   Number of bytes of data in public key array (or 0).
 * @param [in] key     mldsa_composite private/public key.
 * @param [in] type    ML-DSA Composite Type (e.g., WC_MLDSA44_NISTP256_SHA256)
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a required parameter is NULL an invalid
 *          combination of keys/lengths is supplied.
 */
WOLFSSL_API int wc_mldsa_composite_import_key(const byte* priv, word32 privSz,
    const byte* pub, word32 pubSz, mldsa_composite_key* key, enum mldsa_composite_type type);

/* Export the mldsa_composite private and public key.
 *
 * @param [in]      key     mldsa_composite private/public key.
 * @param [out]     priv    Array to hold private key.
 * @param [in, out] privSz  On in, the number of bytes in private key array.
 *                          On out, the number bytes put into private key.
 * @param [out]     pub     Array to hold  public key.
 * @param [in, out] pubSz   On in, the number of bytes in public key array.
 *                          On out, the number bytes put into public key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a key, priv, privSz, pub or pubSz is NULL.
 * @return  BUFFER_E when privSz or pubSz is less than required size.
 */
WOLFSSL_API int wc_mldsa_composite_export_key(mldsa_composite_key* key, byte* priv, word32 *privSz,
    byte* pub, word32 *pubSz);

#endif /* WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY */
#endif /* WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY */

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_ASN1
#if defined(WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY)
/* Decode the DER encoded mldsa_composite key.
 *
 * @param [in]      input     Array holding DER encoded data.
 * @param [in, out] inOutIdx  On in, index into array of start of DER encoding.
 *                            On out, index into array after DER encoding.
 * @param [in, out] key       mldsa_composite key to store key.
 * @param [in]      inSz      Total size of data in array.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when input, inOutIdx or key is NULL or inSz is 0.
 * @return  BAD_FUNC_ARG when level not set.
 * @return  Other negative on parse error.
 */
WOLFSSL_API int wc_MlDsaComposite_PrivateKeyDecode(const byte* input,
    word32* inOutIdx, mldsa_composite_key* key, word32 inSz, enum mldsa_composite_type type);

#endif /* WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY */
#endif /* WOLFSSL_MLDSA_COMPOSITE_NO_ASN1 */

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
/* Decode the DER encoded mldsa_composite public key.
 *
 * @param [in]      input     Array holding DER encoded data.
 * @param [in, out] inOutIdx  On in, index into array of start of DER encoding.
 *                            On out, index into array after DER encoding.
 * @param [in, out] key       mldsa_composite key to store key.
 * @param [in]      inSz      Total size of data in array.
 * @param [in]      type      ML-DSA Composite Type (e.g., WC_MLDSA44_NISTP256_SHA256)
 *                            or WC_MLDSA_COMPOSITE_UNDEF to use the type in the key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when input, inOutIdx or key is NULL or inSz is 0.
 * @return  BAD_FUNC_ARG when level not set.
 * @return  Other negative on parse error.
 */
WOLFSSL_API int wc_MlDsaComposite_PublicKeyDecode(const byte* input,
    word32* inOutIdx, mldsa_composite_key* key, word32 inSz, enum mldsa_composite_type type);
#endif /* WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY */

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_ASN1
#ifdef WC_ENABLE_ASYM_KEY_EXPORT
/* Encode the public part of a mldsa_composite key in DER.
 *
 * Pass NULL for output to get the size of the encoding.
 *
 * @param [in]  key      mldsa_composite key object.
 * @param [out] output   Buffer to put encoded data in.
 * @param [in]  len      Size of buffer in bytes.
 * @param [in]  withAlg  Whether to use SubjectPublicKeyInfo format.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
WOLFSSL_API int wc_MlDsaComposite_PublicKeyToDer(mldsa_composite_key* key, byte* output,
    word32 inLen, int withAlg);
#endif /* WC_ENABLE_ASYM_KEY_EXPORT */

#ifdef WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY
/* Encode the private data of a mldsa_composite key in DER.
 *
 * Pass NULL for output to get the size of the encoding.
 *
 * @param [in]  key     mldsa_composite key object.
 * @param [out] output  Buffer to put encoded data in.
 * @param [in]  len     Size of buffer in bytes.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
WOLFSSL_API int wc_MlDsaComposite_PrivateKeyToDer(mldsa_composite_key* key, byte* output,
    word32 inLen);

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
/* Encode the private and public data of a mldsa_composite key in DER.
 *
 * Pass NULL for output to get the size of the encoding.
 *
 * @param [in]  key     mldsa_composite key object.
 * @param [out] output  Buffer to put encoded data in.
 * @param [in]  len     Size of buffer in bytes.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
WOLFSSL_API int wc_MlDsaComposite_KeyToDer(mldsa_composite_key* key, byte* output,
    word32 inLen);
#endif /* WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY */
#endif /* WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY */
#endif /* !WOLFSSL_MLDSA_COMPOSITE_NO_ASN1 */

// #define MlDsaKey            dilithium_key
#define MlDsaCompositeKey   mldsa_composite_key


#define wc_MlDsaCompositeKey_Init(key, heap, devId)                      \
    wc_mldsa_composite_init_ex(key, heap, devId)
#define wc_MlDsaCompositeKey_SetParams(key, id)                          \
    wc_mldsa_composite_set_level(key, id)
#define wc_MlDsaCompositeKey_GetParams(key, id)                          \
    wc_mldsa_composite_get_level(key, id)
#define wc_MlDsaCompositeKey_MakeKey(key, rng)                           \
    wc_mldsa_composite_make_key(key, rng)
#define wc_MlDsaCompositeKey_Sign(key, sig, sigSz, msg, msgSz, rng)      \
    wc_mldsa_composite_sign_msg(msg, msgSz, sig, sigSz, key, rng)
#define wc_MlDsaCompositeKey_Free(key)                                   \
    wc_mldsa_composite_free(key)
#define wc_MlDsaCompositeKey_ExportPubRaw(key, out, outLen)              \
    wc_mldsa_composite_export_public(key, out, outLen)
#define wc_MlDsaCompositeKey_ImportPubRaw(key, in, inLen)                \
    wc_mldsa_composite_import_public(out, outLen, key)
#define wc_MlDsaCompositeKey_Verify(key, sig, sigSz, msg, msgSz, res)    \
    wc_mldsa_composite_verify_msg(sig, sigSz, msg, msgSz, res, key)

int wc_MlDsaCompositeKey_GetPrivLen(MlDsaCompositeKey* key, int* len);

#ifdef __cplusplus
    }    /* extern "C" */
#endif

#endif /* HAVE_MLDSA_COMPOSITE */
#endif /* WOLF_CRYPT_MLDSA_COMPOSITE_H */
