/* asymkey.h
 */

/*!
    \file wolfssl/wolfcrypt/asymkey.h
*/

/* Interfaces for Asymmetric Keys */

/* Possible Composite options:
 *
 * HAVE_MLDSA_COMPOSITE                                       Default: OFF
 *   Enables the code in this file to be compiled.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* in case user set HAVE_ECC there */
#include <wolfssl/wolfcrypt/settings.h>

#ifndef WOLF_CRYPT_ASYNCKEY_H
#define WOLF_CRYPT_ASYNCKEY_H

#ifndef WOLF_CRYPT_ERROR_H
#include <wolfssl/wolfcrypt/error-crypt.h>
#endif

#ifndef WOLF_CRYPT_TYPES_H
#include <wolfssl/wolfcrypt/types.h>
#endif

#ifndef WOLF_CRYPT_ASN_H
#include <wolfssl/wolfcrypt/asn.h>
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

#ifdef HAVE_MLDSA_COMPOSITE
# ifndef WOLF_CRYPT_MLDSA_COMPOSITE_H
#  include <wolfssl/wolfcrypt/mldsa_composite.h>
# endif
#endif

#ifdef __cplusplus
    extern "C" {
#endif

typedef struct AsymKey {
    /* Type of key - RSA, ECC, etc. */
    int type;
    /* Security Bits */
    union {
        /* RSA key data. */
#ifndef NO_RSA
        RsaKey* rsaKey;
#endif
#ifdef HAVE_ECC
        /* ECC key data. */
        ecc_key* eccKey;
#ifdef HAVE_ED25519
        ed25519_key* ed25519Key;
#endif
#ifdef HAVE_ED448
        ed448_key* ed448Key;
#endif
#endif
#ifdef HAVE_PQC
#ifdef HAVE_FALCON
        falcon_key* falconKey;
#endif
#ifdef HAVE_DILITHIUM
        dilithium_key* dilithiumKey;
#endif
#ifdef HAVE_SPHINCS
        sphincs_key* sphincsKey;
#endif
#ifdef HAVE_MLDSA_COMPOSITE
        mldsa_composite_key * mldsaCompKey;
#endif
#endif
        void * pnt;
    } key;
    /* Key data. */
    word32 secBits;
    /* Useful Security Properties */
    word8 quantumResistant;
} AsymKey;

/* Functions */

#ifndef WOLFSSL_NO_MAKE_KEY
/* Make a key from a random seed.
 *
 * @param [out] key      Asymmetric key.
 * @param [in]  key_type Type of key to make.
 * @param [in]  seed     Random seed.
 * @param [in]  seedSz   Size of seed in bytes.
 * @param [in]  rng      Random number generator.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
WOLFSSL_API int wc_AsymKey_new(AsymKey ** key,
                               int        key_type, 
                               byte     * seed,
                               word32     seedSz,
                               WC_RNG   * rng);
#endif /* ! WOLFSSL_NO_MAKE_KEY */

#ifndef WOLFSSL_NO_VERIFY

/* Free the memory associated with an AsymKey.
 *
 * @param [in] key Asymmetric key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 */
WOLFSSL_API int wc_AsymKey_free(AsymKey * key);

/* Initialize a private/public key.
 *
 * @param [in, out] key     The Asymmetric Key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL
 */
WOLFSSL_API int wc_AsymKey_init(AsymKey* key, int param);

/* Initialize the MlDsaComposite private/public key.
 *
 * @param [in, out] key     ML-DSA composite key.
 * @param [in]      heap    Heap hint.
 * @param [in]      devId   Device ID.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL
 */
WOLFSSL_API int wc_AsymKey_init_ex(AsymKey* key, void* heap, int devId);

/* Set the level of a private/public key.
 *
 * key   [out]  The AsymKey to set the parater for.
 * level [in]   The value for the supported level.
 * returns BAD_FUNC_ARG when key is NULL or level is a bad values.
 */
WOLFSSL_API int wc_AsymKey_set_level(AsymKey* key, int level);

/* Get the level of a private/public key.
 *
 * key   [in]  The public/private keypair to query.
 * returns an integer value for the level of the key (algorithm dependent).
 * returns BAD_FUNC_ARG when key is NULL or level has not been set.
 */
WOLFSSL_API int wc_AsymKey_level(const AsymKey* key);

/* Get the KeySum of a private/public key.
 *
 * key   [in]  The public/private keypair to query.
 * returns enum Key_Sum value of the key.
 * returns BAD_FUNC_ARG when key is NULL or not initialized.
 */
WOLFSSL_API int wc_AsymKey_keySum(const AsymKey * key);

/* Get the type of certificate associated with the key.
 *
 * key   [in]  The public/private keypair to query.
 * returns a value from enum CertType for the key.
 * returns BAD_FUNC_ARG when key is NULL or type has not been set.
 */
WOLFSSL_API int wc_AsymKey_certType(const AsymKey* key);

// /* Returns the size of the private key.
//  *
//  * @param [in] key  The public/private keypair to query.
//  * @return  Private key size on success.
//  * @return  BAD_FUNC_ARG when key is NULL or level not set,
//  */
// WOLFSSL_API int wc_AsymKey_size(const AsymKey* key);

/* Returns the size of a private plus public key.
 *
 * @param [in] key  The public/private keypair to query.
 * @return  Private key size on success.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
WOLFSSL_API int wc_AsymKey_priv_size(const AsymKey* key);

/* Returns the size of a public key.
 *
 * @param [in] key  The public/private keypair to query.
 * @return  Public key size on success for set level.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
WOLFSSL_API int wc_AsymKey_pub_size(const AsymKey* key);

/* Returns the size of a private key signature.
 *
 * @param [in] key  The public/private keypair to query.
 * @return  Signature size on success.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
WOLFSSL_API int wc_AsymKey_sig_size(const AsymKey* key);

/* Check the public key matches the private key.
 *
 * @param [in] key  The public/private keypair to check.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL or no private key available,
 * @return  PUBLIC_KEY_E when the public key is not set or doesn't match,
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
WOLFSSL_API int wc_AsymKey_check(const AsymKey* key);

/* Import a der encoded public key from a byte array.
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
WOLFSSL_API int wc_AsymKey_import_public(AsymKey* key, int type, const byte* in, word32 inLen);

/* Export the public key.
 *
 * @param [in]      key     The keypair to export the public key from.
 * @param [out]     out     Array to hold public key. Use NULL to get the needed the size for `in`.
 * @param [in, out] outLen  On in, the number of bytes in array.
 *                          On out, the number bytes put into array.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BUFFER_E when outLen is less than DILITHIUM_LEVEL2_PUB_KEY_SIZE.
 */
WOLFSSL_API int wc_AsymKey_export_public(const AsymKey* key, byte* out, word32* outLen);
#endif /* WOLFSSL_PUBLIC_KEY */

/* Import a keypair from a byte array.
 *
 * @param [in]      priv    Array holding private key.
 * @param [in]      privSz  Number of bytes of data in array.
 * @param [in, out] key     mldsa_composite private key.
 * @return  0 otherwise.
 * @return  BAD_FUNC_ARG when a parameter is NULL or privSz is less than size
 *          required for level,
 */
WOLFSSL_API int wc_AsymKey_import_private(const byte* priv, word32 privSz,
    AsymKey* key, int type);

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
WOLFSSL_API int wc_AsymKey_export_private(mldsa_composite_key* key, byte* out, word32* outLen);

/* Import a keypair from the DER representation of a PKCS8 data structure.
 *
 * @param [in]      pkcsData    Array holding the PKCS#8 encoded KeyPair.
 * @param [in]      pkcsDataSz  Number of bytes of data in array.
 * @param [in, out] type        The `enum Key_Sum` value for the used Key.
 * 
 */
WOLFSSL_API int wc_PKCS8_import(const byte* pkcsData, word32 pkcsDataSz, enum Key_Sum *type, AsymKey* key);

/* Export the mldsa_composite private and public key.
 *
 * @param [in]      pkcsData    Array to hold the PKCS#8 encoded KeyPair.
 * @param [in, out] pkcsDataSz  On in, the number of bytes in private key array.
 *                              On out, the number bytes put into private key.
 * @param [out]     keySum      The `enum Key_Sum` value for the used Key.
 * @param [in]      key         Destination for the parsed keypair.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a key, priv, privSz, pub or pubSz is NULL.
 * @return  BUFFER_E when privSz or pubSz is less than required size.
 */
WOLFSSL_API int wc_PKCS8_export(byte* pkcsData, word32 *pkcsDataSz, word32 * oid, const AsymKey** key);

/* Retrieves the OID of the keypair.
 *
 * @param [in]  p8_data    Array holding the PKCS#8 encoded KeyPair.
 * @param [in]  p8_dataSz  Number of bytes of data in array.
 * @param [out] oid        The OID of the keypair.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when p8_data or p8_dataSz is NULL.
 */
WOLFSSL_API int wc_PKCS8_info(byte * p8_data, word32 p8_dataSz, word32 * oid);

#ifdef __cplusplus
    }    /* extern "C" */
#endif

#endif /* HAVE_MLDSA_COMPOSITE */
#endif /* WOLF_CRYPT_MLDSA_COMPOSITE_H */
