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

#ifndef WOLF_CRYPT_ASYMKEY_H
#define WOLF_CRYPT_ASYMKEY_H

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

#if defined(HAVE_SPHINCS)
#include <wolfssl/wolfcrypt/sphincs.h>
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
    int param;
    union {
#ifndef NO_RSA
        RsaKey rsaKey;
#endif
#ifdef HAVE_ECC
        ecc_key eccKey;
#ifdef HAVE_ED25519
        ed25519_key ed25519Key;
#endif
#ifdef HAVE_ED448
        ed448_key ed448Key;
#endif
#endif
#ifdef HAVE_PQC
#ifdef HAVE_FALCON
        falcon_key falconKey;
#endif
#ifdef HAVE_DILITHIUM
        dilithium_key dilithiumKey;
#endif
#ifdef HAVE_SPHINCS
        sphincs_key sphincsKey;
#endif
#ifdef HAVE_MLDSA_COMPOSITE
        mldsa_composite_key mldsaCompKey;
#endif
#endif
#ifdef HAVE_SPHINCS
        sphincs_key sphincsKey;
#endif
    } val;
    word32 secBits;
    word8 isPQC;
    word8 isHybrid;
} AsymKey;

/* Type Defs for More Expressive Names */
typedef struct Cert wc_509Cert;
typedef struct Cert wc_509Req;

/* Functions */

/* Allocates the memory associated with a new AsymKey.
 *
 * @return  MEMORY_E when memory allocation fails.
 * @return  the pointer to the new AsymKey.
 */
WOLFSSL_API AsymKey * wc_AsymKey_new(void);

/* Free the memory associated with an AsymKey.
 *
 * @param [in] key The Asymmetric key. The memory associated with the
 *                 key pointer will not be freed, the caller still
 *                 needs to call XFREE on the key pointer.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 */
WOLFSSL_API int wc_AsymKey_free(AsymKey * key);

#ifndef WOLFSSL_NO_MAKE_KEY
/* Generates a new keypair of a specified type.
 *
 * @param [out] key      Asymmetric key.
 * @param [in]  type     Type of key to make.
 * @param [in]  param    Key parameter (e.g., 2048 for RSA).
 * @param [in]  seed     Random seed.
 * @param [in]  seedSz   Size of seed in bytes.
 * @param [in]  rng      Random number generator.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
WOLFSSL_API int wc_AsymKey_gen(AsymKey      ** key,
                               enum Key_Sum    type,
                               int             param,
                               byte          * seed,
                               word32          seedSz,
                               WC_RNG        * rng);
#endif /* ! WOLFSSL_NO_MAKE_KEY */

#ifndef WOLFSSL_NO_VERIFY

/* Get the KeySum of a private/public key.
 *
 * key   [in]  The public/private keypair to query.
 * returns enum Key_Sum value of the key.
 * returns BAD_FUNC_ARG when key is NULL or not initialized.
 */
WOLFSSL_API int wc_AsymKey_Oid(const AsymKey * key);

/* Get the type of certificate associated with the key.
 *
 * key   [in]  The public/private keypair to query.
 * returns a value from enum CertType for the key.
 * returns BAD_FUNC_ARG when key is NULL or type has not been set.
 */
WOLFSSL_API int wc_AsymKey_CertType(const AsymKey* key);

/* Returns the size of a private plus public key.
 *
 * @param [in] key  The public/private keypair to query.
 * @return  Private key size on success.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
WOLFSSL_API int wc_AsymKey_size(const AsymKey* key);

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
WOLFSSL_API int wc_AsymKey_Public_import(AsymKey* key, int type, const byte* in, word32 inLen, int format);

/* Export the public key.
 *
 * @param [in]      buff   Array to hold public key.
 * @param [in]      buffLen  Number of bytes in array.
 * @param [in]      withAlg  Whether to use SubjectPublicKeyInfo format.
 * @param [in]      format  Format of key data (1 = PEM, 0 = DER).
 * @param [in]      key     An asymmetric key object (AsymKey *).
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BUFFER_E when outLen is less than the required size
 */
WOLFSSL_API int wc_AsymKey_Public_export(byte* buff, word32 buffLen, int withAlg, int format, const AsymKey* key);

#endif /* WOLFSSL_PUBLIC_KEY */

/* Import a keypair from a byte array.
 *
 * @param [out] key     Asymmetric key.
 * @param [in]  type    Type of key to make.
 * @param [in]  data    Key data.
 * @param [in]  dataSz  Size of key data.
 * @param [in]  format  Format of key data (1 = PEM, 0 = DER).
 * @return BAD_FUNC_ARG when a parameter is NULL or buffer is too small.
 * @return MEMORY_E when memory allocation fails.
 * @return The number of bytes written to the buffer.
 */
WOLFSSL_API int wc_AsymKey_import(AsymKey* key, const byte* data, word32 dataSz, int format);

/* Import a keypair from a byte array.
 *
 * @param [out] key     Asymmetric key.
 * @param [in]  type    Type of key to make.
 * @param [in]  data    Key data.
 * @param [in]  dataSz  Size of key data.
 * @param [in]  format  Format of key data (1 = PEM, 0 = DER).
 * @param [in]  passwd  Password for the keypair, NULL if not encrypted.
 * @param [in]  devId   Device ID for hardware acceleration.
 * @return BAD_FUNC_ARG when a parameter is NULL or buffer is too small.
 * @return MEMORY_E when memory allocation fails.
 * @return The number of bytes written to the buffer.
 */
WOLFSSL_API int wc_AsymKey_import_ex(AsymKey* key, const byte* data, word32 dataSz, int format, const char* passwd, int devId);

/* Export a keypair to a byte array.
 *
 * @param [in]  key       The keypair to export.
 * @param [out] buff      Array to hold the exported keypair.
 * @param [in]  buffLen   Number of bytes in the array.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BUFFER_E when outLen is less than DILITHIUM_LEVEL2_KEY_SIZE.
 */
WOLFSSL_API int wc_AsymKey_export(const AsymKey* key, byte* buff, word32* buffLen);

/* Export a keypair to a byte array.
 *
 * @param [in]  key       The keypair to export.
 * @param [out] buff      Array to hold the exported keypair.
 * @param [in]  buffLen   Number of bytes in the array.
 * @param [in]  passwd    Password for the keypair, NULL if not encrypted.
 * @param [in]  passwdSz  Size of the password in bytes, 0 if not encrypted.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BUFFER_E when outLen is less than DILITHIUM_LEVEL2_KEY_SIZE.
 */
WOLFSSL_API int wc_AsymKey_export_ex(const AsymKey* key, byte* buff, word32* buffLen, const byte* passwd, word32 passwdSz);

/* Retrieves the OID of the keypair.
 *
 * @param [out] oid        The OID of the keypair.
 * @param [in]  pkcsData    Array holding the PKCS#8 encoded KeyPair.
 * @param [in]  pkcsDataSz  Number of bytes of data in array.
 * @param [in]  format      Format of key data (1 = PEM, 0 = DER).
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when p8_data or p8_dataSz is NULL.
 */
WOLFSSL_API int wc_AsymKey_PrivateKeyInfo(word32 * oid, byte * pkcsData, word32 pkcsDataSz, int format);

/* Decode a PKCS8 private key.
 *
 * @param [in] key     The key to decode.
 * @param [in] data    The data to decode.
 * @param [in] dataSz  The size of the data.
 * @param [in] format  The format of the data.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 */
WOLFSSL_API int wc_AsymKey_PrivateKeyDecode(AsymKey* key, const byte* data, word32 dataSz, int format);

/* Decode an encrypted PKCS8 private key.
 *
 * @param [in] key     The key to decode.
 * @param [in] data    The data to decode.
 * @param [in] dataSz  The size of the data.
 * @param [in] format  The format of the data.
 * @param [in] passwd  The password for the key.
 * @param [in] devId   The device ID for hardware acceleration.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 */
WOLFSSL_API int wc_AsymKey_PrivateKeyDecode_ex(AsymKey* key, const byte* data, word32 dataSz, int format, const char* passwd, int devId);

/* Exports a Private and Public Key in PKCS#8 format 
*
* @param [in]  key     The key to export.
* @param [out] buff    Array to hold the exported keypair.
* @param [in]  buffLen Number of bytes in the array.
* @param [in]  format  Format of key data (1 = PEM, 0 = DER).
* @return  the number of written bytes on success.
* @return  BAD_FUNC_ARG when a parameter is NULL.
* @return  BUFFER_E when outLen is less than required.
*/
WOLFSSL_API int wc_AsymKey_PrivateKeyToDer(const AsymKey * key,
                               byte          * buff,
                               word32        * buffLen);

/* Exports a Private and Public Key in PKCS#8 format.
*
* @param [in]  key     The key to export.
* @param [out] buff    Array to hold the exported keypair.
* @param [in]  buffLen Number of bytes in the array.
* @param [in]  format  Format of key data (1 = PEM, 0 = DER).
* @param [in]  passwd  Password for the keypair, NULL if not encrypted.
* @param [in]  passwdSz  Size of the password in bytes, 0 if not encrypted.
* @return  the number of written bytes on success.
* @return  BAD_FUNC_ARG when a parameter is NULL.
* @return  BUFFER_E when outLen is less than required.
*/
WOLFSSL_API int wc_AsymKey_PrivateKeyToDer_ex(const AsymKey * key,
                                              byte          * buff,
                                              word32        * buffLen,
                                              const byte    * passwd,
                                              word32          passwdSz);


/* Make a new certificate request (PKCS#10).
 *
 * @param [in]  der     The DER encoded certificate request.
 * @param [in]  derSz   The size of the DER encoded certificate request.
 * @param [out] req     The certificate request.
 * @param [in]  key     The key to make the request with.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  NOT_COMPILED_IN when the function is not compiled in.
 */
WOLFSSL_API int wc_AsymKey_MakeReq(const byte* der, word32 derSz, wc_509Req* req, const AsymKey* key);

/* Make a new certificate (X509).
 *
 * @param [in]  req     The certificate request.
 * @param [in]  dn      Distinguished Name.
 * @param [in]  key     The key to make the certificate with.
 * @param [in]  rng     Random number generator.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  NOT_COMPILED_IN when the function is not compiled in.
 */
WOLFSSL_API int wc_AsymKey_MakeCert(const byte * der, word32 derLen, wc_509Cert* req, const AsymKey* key, WC_RNG* rng);

/* Sign a message with the key.
 *
 * @param [out] sig    Array to hold the signature.
 * @param [in, out] sigLen  On in, the number of bytes in array.
 *                          On out, the number bytes put into array.
 * @param [in] msg     Message to sign.
 * @param [in] msgLen  Number of bytes in message.
 * @param [in] key     The key to sign with.
 * @param [in] rng     Random number generator.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  NOT_COMPILED_IN when the function is not compiled in.
 */
WOLFSSL_API int wc_AsymKey_Sign(byte* sig, word32* sigLen, const byte* msg, word32 msgLen,
                                enum wc_HashType hashType, const AsymKey* key, WC_RNG* rng);

/*
* Sign a message with the key.
*
* @param [in] key     The key to sign with.
* @param [in] in      Message to sign.
* @param [in] inLen   Number of bytes in message.
* @param [out] out    Array to hold the signature.
* @param [in, out] outLen  On in, the number of bytes in array.
*                          On out, the number bytes put into array.
* @param [in] hashType  Hash type to use for the signature.
* @param [in] rng     Random number generator.
* @param [in] context Context for the signature.
* @param [in] contextLen  Number of bytes in context.
* @return  0 on success.
* @return  BAD_FUNC_ARG when a parameter is NULL.
* @return  NOT_COMPILED_IN when the function is not compiled in.
*/
WOLFSSL_API int wc_AsymKey_Sign_ex(byte* out, word32* outLen, 
        const byte* in, word32 inLen, enum wc_HashType hashType,
        const byte* context, byte contextLen,
        const AsymKey* key, WC_RNG* rng);

/* Verify a message with the key.
*
* @param [in] sig     Signature to verify.
* @param [in] sigLen  Number of bytes in signature.
* @param [in] msg     Message to verify.
* @param [in] msgLen  Number of bytes in message.
* @param [in] hashType  Hash type to use for the signature.
* @param [in] key     The key to verify with.
* @return  0 on success.
* @return  BAD_FUNC_ARG when a parameter is NULL.
* @return  NOT_COMPILED_IN when the function is not compiled in.
*/
WOLFSSL_API int wc_AsymKey_Verify(const byte* sig, word32 sigLen,
        const byte* msg, word32 msgLen, enum wc_HashType hashType, const AsymKey* key);

/*
* Verify a message with the key.
*
* @param [in] key     The key to verify with.
* @param [in] sig     Signature to verify.
* @param [in] sigLen  Number of bytes in signature.
* @param [in] in      Message to verify.
* @param [in] inLen   Number of bytes in message.
* @param [out] res    Result of the verification.
* @param [in] context Context for the signature.
* @param [in] contextLen  Number of bytes in context.
* @return  0 on success.
* @return  BAD_FUNC_ARG when a parameter is NULL.
* @return  NOT_COMPILED_IN when the function is not compiled in.
*/
WOLFSSL_API int wc_AsymKey_Verify_ex(const byte* sig, word32 sigLen, const byte* in, word32 inLen, enum wc_HashType hashType, const AsymKey* key, const byte* context, byte contextLen);

WOLFSSL_API int wc_X509_Req_Sign(const byte * der, word32 derLen, wc_509Req * req, enum wc_HashType htype, const AsymKey* key, WC_RNG* rng);
WOLFSSL_API int wc_X509_Req_Sign_ex(const byte * der, word32 derLen, wc_509Req * req, enum wc_HashType htype, const byte* context, byte contextLen, const AsymKey* key, WC_RNG* rng);

WOLFSSL_API int wc_X509_Req_Verify(const byte * der, word32 derLen);
WOLFSSL_API int wc_X509_Req_Verify_ex(const byte * der, word32 derLen, const byte* context, byte contextLen, const AsymKey* caKey);

WOLFSSL_API int wc_X509_Cert_Sign(const byte * der, word32 derLen, wc_509Req * req, enum wc_HashType htype, const AsymKey* caKey, WC_RNG* rng);
WOLFSSL_API int wc_X509_Cert_Sign_ex(const byte * der, word32 derLen, wc_509Req * req, enum wc_HashType htype, const byte* context, byte contextLen, const AsymKey* key, WC_RNG* rng);

WOLFSSL_API int wc_X509_Cert_Verify(const byte * der, word32 derLen, const AsymKey * key);
WOLFSSL_API int wc_X509_Cert_Verify_ex(const byte * der, word32 derLen, const byte* context, byte contextLen, const AsymKey * caKey);
#ifdef __cplusplus
    }    /* extern "C" */
#endif

#endif /* HAVE_MLDSA_COMPOSITE */
#endif /* WOLF_CRYPT_MLDSA_COMPOSITE_H */
