/* asymkey.c */

#ifndef WOLF_CRYPT_ASYNCKEY_H
#include <wolfssl/wolfcrypt/asymkey.h>
#endif

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
                               int        type,
                               int        param,
                               byte     * seed,
                               word32     seedSz,
                               WC_RNG   * rng) {

  int ret = 0;
  int outSz = 0;
#ifndef NO_RSA
  RsaKey rsaKey;
#endif
#ifdef HAVE_DSA
  dsa_key dsaKey;
#endif
#ifdef HAVE_ECC
  ecc_key ecKey;
#endif
#ifdef HAVE_ED25519
  ed25519_key ed25519Key;
#endif
#ifdef HAVE_ED448
  ed448_key ed448Key;
#endif
#ifdef HAVE_DILITHIUM
  MlDsaKey mldsaKey;
#endif
#ifdef HAVE_MLDSA_COMPOSITE
  mldsa_composite_key mldsa_compositeKey;
#endif
  void* keyPtr = NULL;
  WC_RNG rng;
  int rngAlloc = 0;

#ifdef HAVE_MLDSA_COMPOSITE
    byte der[MLDSA_COMPOSITE_MAX_PRV_KEY_SIZE];
#else
    byte der[10192]; /* 10k */
#endif

    (void)der;
    (void)outSz;

  if (!key)
      return BAD_FUNC_ARG;

    switch (type) {
#ifdef HAVE_DSA
    case DSA_TYPE:
        keyPtr = &dsaKey;
        ret = wc_InitDsaKey(&dsaKey, NULL);
        break;
#endif
#ifndef NO_RSA
    case RSA_TYPE:
        if (param < 2048) {
          return BAD_FUNC_ARG;
        }
        keyPtr = (void*)XMALLOC(sizeof(RsaKey), NULL, DYNAMIC_TYPE_RSA);
        if (keyPtr == NULL)
            return MEMORY_E;
        ret = wc_InitRsaKey(&rsaKey, rsaKey.heap);
        if (ret < 0) {
            XFREE(keyPtr, NULL, DYNAMIC_TYPE_RSA);
            return ret;
        }
        ret = wc_MakeRsaKey(&rsaKey, param, WC_RSA_EXPONENT, &rng);
        if (ret < 0) {
            wc_FreeRsaKey(&rsaKey);
            XFREE(keyPtr, NULL, DYNAMIC_TYPE_RSA);
            return ret;
        }
        break;
#endif
#ifdef HAVE_ECC
    case ECC_TYPE:
        // keyPtr = &ecKey;
        // ret = wc_ecc_init(&ecKey);
        // int keySz = 32;
        // if (param <= 0)
        //     param = ECC_SECP256R1;
        // if (ret == 0) {
        //     if ((keySz = wc_ecc_get_curve_size_from_id(param)) < 0)
        //         ret = keySz;
        //     if (ret == 0)
        //         ret = wc_ecc_make_key_ex(&rng, keySz, keyPtr, param);
        // }
        int keySz = wc_ecc_get_curve_size_from_id(param);
        if (keySz < 0)
                return keySz;
      
        if (param <= 0)
          param = ECC_SECP256R1;

        keyPtr = (void*)XMALLOC(sizeof(ecc_key), NULL, DYNAMIC_TYPE_ECC);
        if (keyPtr == NULL)
            return MEMORY_E;

        ret = wc_ecc_init(keyPtr);
        if (ret < 0) {
            XFREE(keyPtr, NULL, DYNAMIC_TYPE_ECC);
            return ret;
        }
        ret = wc_ecc_make_key_ex(&rng, keySz, keyPtr, param);
        if (ret < 0) {
            wc_ecc_free(keyPtr);
            XFREE(keyPtr, NULL, DYNAMIC_TYPE_ECC);
            return ret;
        }
        break;

#endif
#ifdef HAVE_ED25519
    case ED25519_TYPE:
        keyPtr = (void *)XMALLOC(sizeof(ed25519_key), NULL, DYNAMIC_TYPE_ED25519);
        if (keyPtr == NULL)
            return MEMORY_E;
        ret = wc_ed25519_init(&ed25519Key);
        if (ret < 0)
            return ret;
        ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, keyPtr);
        if (ret < 0) {
            wc_ed25519_free(keyPtr);
            XFREE(keyPtr, NULL, DYNAMIC_TYPE_ED25519);
            return ret;
        }
        break;
#endif
#ifdef HAVE_ED448
    case ED448_TYPE:
        keyPtr = (void *)XMALLOC(sizeof(ed448_key), NULL, DYNAMIC_TYPE_ED448);
        if (keyPtr == NULL)
            return MEMORY_E;
        ret = wc_ed448_init(&ed448Key);
        if (ret < 0)
            return ret;
        ret = wc_ed448_make_key(&rng, ED448_KEY_SIZE, keyPtr);
        if (ret < 0) {
            wc_ed448_free(keyPtr);
            XFREE(keyPtr, NULL, DYNAMIC_TYPE_ED448);
            return ret;
        }
        break;
#endif
#ifdef HAVE_DILITHIUM
    case ML_DSA_LEVEL2_TYPE:
    case ML_DSA_LEVEL3_TYPE:
    case ML_DSA_LEVEL5_TYPE:
        keyPtr = (void *)XMALLOC(sizeof(dilithium_key), NULL, DYNAMIC_TYPE_DILITHIUM);
        if (keyPtr == NULL)
          return MEMORY_E;

        ret = wc_dilithium_init(keyPtr);
        if (ret < 0) {
          XFREE(keyPtr, NULL, DYNAMIC_TYPE_DILITHIUM);
          return ret;
        }

        if (type == ML_DSA_LEVEL2k)
          ret = wc_dilithium_set_level(keyPtr, WC_ML_DSA_44);
        else if (type == ML_DSA_LEVEL3k)
          ret = wc_dilithium_set_level(keyPtr, WC_ML_DSA_65);
        else if (type == ML_DSA_LEVEL5k)
          ret = wc_dilithium_set_level(keyPtr, WC_ML_DSA_87);
        else {
          XFREE(keyPtr, NULL, DYNAMIC_TYPE_DILITHIUM);
          return BAD_FUNC_ARG;
        }

        ret = wc_dilithium_make_key(&mldsaKey, &rng);
        if (ret < 0) {
          wc_dilithium_free(keyPtr);
          XFREE(keyPtr, NULL, DYNAMIC_TYPE_DILITHIUM);
          return ret;
        }
        break;
#endif

#ifdef HAVE_MLDSA_COMPOSITE
    case MLDSA44_RSAPSS2048_TYPE:
    case MLDSA44_RSA2048_TYPE:
    case MLDSA44_NISTP256_TYPE:
    // case MLDSA44_BPOOL256k:
    case MLDSA44_ED25519_TYPE:
    case MLDSA65_ED25519_TYPE:
    case MLDSA65_RSAPSS4096_TYPE:
    case MLDSA65_RSA4096_TYPE:
    case MLDSA65_RSAPSS3072_TYPE:
    case MLDSA65_RSA3072_TYPE:
    case MLDSA65_NISTP256_TYPE:
    case MLDSA65_BPOOL256_TYPE:
    case MLDSA87_BPOOL384_TYPE:
    case MLDSA87_NISTP384_TYPE:
    case MLDSA87_ED448_TYPE:
        int composite_level = wc_composite_level_type(type);
        keyPtr = (void *)XMALLOC(sizeof(mldsa_composite_key), NULL, DYNAMIC_TYPE_MLDSA_COMPOSITE);
        if (keyPtr == NULL)
            return MEMORY_E;
        ret = wc_mldsa_composite_init(keyPtr);
        if (ret < 0) {
            wc_mldsa_composite_free(keyPtr);
            XFREE(keyPtr, NULL, DYNAMIC_TYPE_MLDSA_COMPOSITE);
            return ret;
        }
        if (ret == 0)
            ret = wc_mldsa_composite_make_key(&mldsa_compositeKey, composite_level, &rng);

        break;
#endif

        default:
            printf("ERROR: Invalid key type (%d)\n", type);
            return BAD_FUNC_ARG;
    }

    // Returns the key
    if (ret == 0) {
        *key = keyPtr;
    }

#ifdef HAVE_MLDSA_COMPOSITE
    (void)mldsa_compositeKey;
#endif
#ifdef HAVE_MLDSA
    (void)mldsaKey;
#endif
#ifdef HAVE_ED448
    (void)ed448Key;
#endif
#ifdef HAVE_ED25519
    (void)ed25519Key;
#endif
#ifdef HAVE_ECC
    (void)ecKey;
#endif
#ifndef NO_RSA
    (void)rsaKey;
#endif
#ifdef HAVE_DSA
    (void)dsaKey;
#endif
    wc_FreeRng(&rng);

    return 0;
}
#endif /* ! WOLFSSL_NO_MAKE_KEY */

#ifndef WOLFSSL_NO_VERIFY

/* Free the memory associated with an AsymKey.
 *
 * @param [in] key Asymmetric key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 */
WOLFSSL_API int wc_AsymKey_free(AsymKey * key) {

}

/* Initialize a private/public key.
 *
 * @param [in, out] key     The Asymmetric Key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL
 */
WOLFSSL_API int wc_AsymKey_init(AsymKey* key, int param) {

}

/* Initialize the MlDsaComposite private/public key.
 *
 * @param [in, out] key     ML-DSA composite key.
 * @param [in]      heap    Heap hint.
 * @param [in]      devId   Device ID.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL
 */
WOLFSSL_API int wc_AsymKey_init_ex(AsymKey* key, void* heap, int devId) {

}

/* Set the level of a private/public key.
 *
 * key   [out]  The AsymKey to set the parater for.
 * level [in]   The value for the supported level.
 * returns BAD_FUNC_ARG when key is NULL or level is a bad values.
 */
WOLFSSL_API int wc_AsymKey_set_level(AsymKey* key, int level) {

}

/* Get the level of a private/public key.
 *
 * key   [in]  The public/private keypair to query.
 * returns an integer value for the level of the key (algorithm dependent).
 * returns BAD_FUNC_ARG when key is NULL or level has not been set.
 */
WOLFSSL_API int wc_AsymKey_level(const AsymKey* key) {

}

/* Get the KeySum of a private/public key.
 *
 * key   [in]  The public/private keypair to query.
 * returns enum Key_Sum value of the key.
 * returns BAD_FUNC_ARG when key is NULL or not initialized.
 */
WOLFSSL_API int wc_AsymKey_keySum(const AsymKey * key) {

}

/* Get the type of certificate associated with the key.
 *
 * key   [in]  The public/private keypair to query.
 * returns a value from enum CertType for the key.
 * returns BAD_FUNC_ARG when key is NULL or type has not been set.
 */
WOLFSSL_API int wc_AsymKey_certType(const AsymKey* key) {

}

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
WOLFSSL_API int wc_AsymKey_priv_size(const AsymKey* key) {

}

/* Returns the size of a public key.
 *
 * @param [in] key  The public/private keypair to query.
 * @return  Public key size on success for set level.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
WOLFSSL_API int wc_AsymKey_pub_size(const AsymKey* key) {

}

/* Returns the size of a private key signature.
 *
 * @param [in] key  The public/private keypair to query.
 * @return  Signature size on success.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
WOLFSSL_API int wc_AsymKey_sig_size(const AsymKey* key) {

}

/* Check the public key matches the private key.
 *
 * @param [in] key  The public/private keypair to check.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL or no private key available,
 * @return  PUBLIC_KEY_E when the public key is not set or doesn't match,
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
WOLFSSL_API int wc_AsymKey_check(const AsymKey* key) {

}

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
WOLFSSL_API int wc_AsymKey_import_public(AsymKey* key, int type, const byte* in, word32 inLen) {

}

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
WOLFSSL_API int wc_AsymKey_export_public(const AsymKey* key, byte* out, word32* outLen) {

}

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
                                          AsymKey* key, int type) {

}

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
WOLFSSL_API int wc_AsymKey_export_private(mldsa_composite_key* key, byte* out, word32* outLen) {

}

/* Retrieves the OID of the keypair.
 *
 * @param [in]  p8_data    Array holding the PKCS#8 encoded KeyPair.
 * @param [in]  p8_dataSz  Number of bytes of data in array.
 * @param [out] oid        The OID of the keypair.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when p8_data or p8_dataSz is NULL.
 */
WOLFSSL_API int wc_PKCS8_info(byte * p8_data, word32 p8_dataSz, word32 * oid) {
  
}

/* Import a keypair from the DER representation of a PKCS8 data structure.
 *
 * @param [in]      pkcsData    Array holding the PKCS#8 encoded KeyPair.
 * @param [in]      pkcsDataSz  Number of bytes of data in array.
 * @param [in, out] type        The `enum Key_Sum` value for the used Key.
 * 
 */
WOLFSSL_API int wc_PKCS8_import(const byte* pkcsData, word32 pkcsDataSz, enum Key_Sum *type, AsymKey* key) {

}

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
WOLFSSL_API int wc_PKCS8_export(byte* pkcsData, word32 *pkcsDataSz, word32 * oid, const AsymKey** key) {

}


