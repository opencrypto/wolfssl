/* asymkey.c */

#ifndef WOLF_CRYPT_ASYNCKEY_H
#include <wolfssl/wolfcrypt/asymkey.h>
#endif

/* Functions */

/* Allocates the memory associated with a new AsymKey.
 *
 * @return  MEMORY_E when memory allocation fails.
 * @return  the pointer to the new AsymKey.
 */
WOLFSSL_API AsymKey * wc_AsymKey_new(void) {

  AsymKey * ret = NULL;

  ret = (AsymKey *)XMALLOC(sizeof(AsymKey), NULL, DYNAMIC_TYPE_PRIVATE_KEY);
  if (ret == NULL) return NULL;

  XMEMSET(ret, 0, sizeof(AsymKey));

  return ret;
}

/* Free the memory associated with an AsymKey.
 *
 * @param [in] key The Asymmetric key. The memory associated with the
 *                 key pointer will not be freed, the caller still
 *                 needs to call XFREE on the key pointer.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 */
WOLFSSL_API int wc_AsymKey_free(AsymKey * key) {

  if (!key)
    return BAD_FUNC_ARG;

  switch (key->type) {
#ifdef HAVE_DSA
    case DSA_TYPE:
        if (!key->key.dsaKey) {
          wc_FreeDsaKey(key->key.dsaKey);
          XFREE(key->key.dsaKey, NULL, DYNAMIC_TYPE_DSA);
          key->key.dsaKey = NULL;
        }
        break;
#endif
#ifndef NO_RSA
    case RSA_TYPE:
        if (!key->key.rsaKey) {
          wc_FreeRsaKey(key->key.rsaKey);
          XFREE(key->key.rsaKey, NULL, DYNAMIC_TYPE_RSA);
          key->key.rsaKey = NULL;
        } break;
#endif
#ifdef HAVE_ECC
    case ECC_TYPE:
        if (!key->key.eccKey) {
          wc_ecc_free(key->key.eccKey);
          XFREE(key->key.eccKey, NULL, DYNAMIC_TYPE_ECC);
          key->key.eccKey = NULL;
        } break;
#endif
#ifdef HAVE_ED25519
    case ED25519_TYPE: {
        if (!key->key.ed25519Key) {
          wc_ed25519_free(key->key.ed25519Key);
          XFREE(key->key.ed25519Key, NULL, DYNAMIC_TYPE_ED25519);
          key->key.ed25519Key = NULL;
        }
    } break;

#endif
#ifdef HAVE_ED448
    case ED448_TYPE:{
        if (!key->key.ed448Key) {
          wc_ed448_free(key->key.ed448Key);
          XFREE(key->key.ed448Key, NULL, DYNAMIC_TYPE_ED448);
          key->key.ed448Key = NULL;
        }
    } break;
#endif
#ifdef HAVE_DILITHIUM
    case ML_DSA_LEVEL2_TYPE:
    case ML_DSA_LEVEL3_TYPE:
    case ML_DSA_LEVEL5_TYPE: {
        if (!key->key.dilithiumKey) {
          wc_dilithium_free(key->key.dilithiumKey);
          XFREE(key->key.dilithiumKey, NULL, DYNAMIC_TYPE_DILITHIUM);
          key->key.dilithiumKey = NULL;
        }
    } break;
#endif
#ifdef HAVE_FALCON
    case FALCON_LEVEL1_TYPE:
    case FALCON_LEVEL5_TYPE: {
        if (!key->key.falconKey) {
          wc_falcon_free(key->key.falconKey);
          XFREE(key->key.falconKey, NULL, DYNAMIC_TYPE_FALCON);
          key->key.falconKey = NULL;
        }
    } break;
#endif
#ifdef HAVE_SPHINCS
    case SPHINCS_HARAKA_128S_ROBUST_TYPE:
    case SPHINCS_HARAKA_128S_SIMPLE_TYPE:
    case SPHINCS_HARAKA_192S_ROBUST_TYPE:
    case SPHINCS_HARAKA_192S_SIMPLE_TYPE:
    case SPHINCS_HARAKA_256S_ROBUST_TYPE:
    case SPHINCS_HARAKA_256S_SIMPLE_TYPE:
    case SPHINCS_SHAKE_128S_ROBUST_TYPE:
    case SPHINCS_SHAKE_128S_SIMPLE_TYPE:
    case SPHINCS_SHAKE_192S_ROBUST_TYPE:
    case SPHINCS_SHAKE_192S_SIMPLE_TYPE:
    case SPHINCS_SHAKE_256S_ROBUST_TYPE:
    case SPHINCS_SHAKE_256S_SIMPLE_TYPE: {
        if (!key->key.sphincsKey) {
          wc_sphincs_free(key->key.sphincsKey);
          XFREE(key->key.sphincsKey, NULL, DYNAMIC_TYPE_SPHINCS);
          key->key.sphincsKey = NULL;
        }
    } break;
#endif
#ifdef HAVE_MLDSA_COMPOSITE
    case MLDSA44_RSAPSS2048_TYPE:
    case MLDSA44_RSA2048_TYPE:
    case MLDSA44_NISTP256_TYPE:
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
    case MLDSA87_ED448_TYPE: {
        if (!key->key.mldsaCompKey) {
          wc_mldsa_composite_free(key->key.mldsaCompKey);
          XFREE(key->key.mldsaCompKey, NULL, DYNAMIC_TYPE_MLDSA_COMPOSITE);
          key->key.mldsaCompKey = NULL;
        }
    } break;
#endif
    default:
        return BAD_FUNC_ARG;
  }

  // Resets the type
  key->type = 0;

  return 0;
}


#ifndef WOLFSSL_NO_MAKE_KEY
/* Generates a new keypair of a specified type.
 *
 * @param [out] key      Asymmetric key.
 * @param [in]  type     Type of key to make.
 * @param [in]  param    Key parameter.
 * @param [in]  seed     Random seed.
 * @param [in]  seedSz   Size of seed in bytes.
 * @param [in]  rng      Random number generator.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
WOLFSSL_API int wc_AsymKey_gen(AsymKey ** key,
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
  // int rngAlloc = 0;

#ifdef HAVE_MLDSA_COMPOSITE
    byte der[MLDSA_COMPOSITE_MAX_PRV_KEY_SIZE];
#else
    byte der[10192]; /* 10k */
#endif

    (void)der;
    (void)outSz;
    (void)seed;
    (void)seedSz;

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
        ret = wc_MakeRsaKey(&rsaKey, param, WC_RSA_EXPONENT, rng);
        if (ret < 0) {
            wc_FreeRsaKey(&rsaKey);
            XFREE(keyPtr, NULL, DYNAMIC_TYPE_RSA);
            return ret;
        }
        break;
#endif
#ifdef HAVE_ECC
    case ECC_TYPE:
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
        ret = wc_ecc_make_key_ex(rng, keySz, keyPtr, param);
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
        ret = wc_ed25519_make_key(rng, ED25519_KEY_SIZE, keyPtr);
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
        ret = wc_ed448_make_key(rng, ED448_KEY_SIZE, keyPtr);
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

        ret = wc_dilithium_make_key(&mldsaKey, rng);
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
        int composite_level = wc_mldsa_composite_level_type(type);
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
            ret = wc_mldsa_composite_make_key(&mldsa_compositeKey, composite_level, rng);

        break;
#endif

        default:
            printf("ERROR: Invalid key type (%d)\n", type);
            return BAD_FUNC_ARG;
    }

    // Returns the key
    if (ret == 0) {
        *key = keyPtr;
        (*key)->type = type;
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

    return 0;
}
#endif /* ! WOLFSSL_NO_MAKE_KEY */

/* Get the KeySum of a private/public key.
 *
 * key   [in]  The public/private keypair to query.
 * returns enum Key_Sum value of the key.
 * returns BAD_FUNC_ARG when key is NULL or not initialized.
 */
WOLFSSL_API int wc_AsymKey_Oid(const AsymKey * key) {

  (void)key;
  return NOT_COMPILED_IN;
}

/* Get the type of certificate associated with the key.
 *
 * key   [in]  The public/private keypair to query.
 * returns a value from enum CertType for the key.
 * returns BAD_FUNC_ARG when key is NULL or type has not been set.
 */
WOLFSSL_API int wc_AsymKey_type(const AsymKey* key) {

  if (!key || key->type <= 0)
    return BAD_FUNC_ARG;

  return key->type;
}

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
WOLFSSL_API int wc_AsymKey_pub_size(const AsymKey* key) {

  (void)key;
  return NOT_COMPILED_IN;
}

/* Returns the size of a private key signature.
 *
 * @param [in] key  The public/private keypair to query.
 * @return  Signature size on success.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
WOLFSSL_API int wc_AsymKey_sig_size(const AsymKey* key) {

  (void)key;
  return NOT_COMPILED_IN;
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

  (void)key;
  return NOT_COMPILED_IN;
}

/* Import a public key from a byte array.
 *
 * @param [out] key     Asymmetric key.
 * @param [in]  type    Type of Public key to import.
 * @param [in]  in      Key data.
 * @param [in]  inLen   Size of key data.
 * @param [in]  format  Format of key data (1 = PEM, 0 = DER).
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when in or key is NULL or key format is not supported.
 */
WOLFSSL_API int wc_AsymKey_Public_import(AsymKey* key, int type, const byte* in, word32 inLen, int format) {

  (void)key;
  (void)type;
  (void)in;
  (void)inLen;
  (void)format;

  return NOT_COMPILED_IN;
}

/* Export a Public key.
 *
 * @param [out]  buff      Array to hold the exported public key.
 * @param [in]   buffLen   Number of bytes in the array.
 * @param [in]   format    Format of key data (1 = PEM, 0 = DER).
 * @param [in]   key       The public key to export.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BUFFER_E when outLen is less than DILITHIUM_LEVEL2_PUB_KEY_SIZE.
 */
WOLFSSL_API int wc_AsymKey_Public_export(byte* buff, word32 buffLen, int format, const AsymKey* key) {
  
  (void)key;
  (void)buff;
  (void)buffLen;
  (void)format;

  return NOT_COMPILED_IN;
}

/* Import a keypair from a byte array.
 *
 * @param [out] key     Asymmetric key.
 * @param [in]  type    Type of key to make.
 * @param [in]  data    Key data.
 * @param [in]  dataSz  Size of key data.
 * @param [in]  passwd  Password for the keypair, NULL if not encrypted.
 * @param [in]  passwdSz  Size of the password in bytes, 0 if not encrypted.
 * @return  0 otherwise.
 * @return  BAD_FUNC_ARG when a parameter is NULL or privSz is less than size
 *          required for level,
 */
WOLFSSL_API int wc_AsymKey_import(AsymKey* key, const byte* data, word32 dataSz, int standard, int format, const byte* passwd, word32 passwdSz) {

  (void)key;
  (void)data;
  (void)dataSz;
  (void)format;
  (void)standard;
  (void)passwd;
  (void)passwdSz;

  return NOT_COMPILED_IN;
}

/* Export a keypair to a byte array.
 *
 * @param [in]  key       The keypair to export.
 * @param [out] buff      Array to hold the exported keypair.
 * @param [in]  buffLen   Number of bytes in the array.
 * @param [in]  standard Use 1 for standard (pkcs8) or 0 for legacy (pkcs1).
 * @param [in]  format  Format of key data (1 = PEM, 0 = DER).
 * @param [in]  passwd    Password for the keypair, NULL if not encrypted.
 * @param [in]  passwdSz  Size of the password in bytes, 0 if not encrypted.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BUFFER_E when outLen is less than DILITHIUM_LEVEL2_KEY_SIZE.
 */
WOLFSSL_API int wc_AsymKey_export(byte* buff, word32 buffLen, int standard, int format, const byte* passwd, word32 passwdSz, const AsymKey* key) {

  (void)key;
  (void)buff;
  (void)buffLen;
  (void)standard;
  (void)format;
  (void)passwd;
  (void)passwdSz;

  return NOT_COMPILED_IN;
}


/* Retrieves the OID of the keypair.
 *
 * @param [in]  p8_data    Array holding the PKCS#8 encoded KeyPair.
 * @param [in]  p8_dataSz  Number of bytes of data in array.
 * @param [out] oid        The OID of the keypair.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when p8_data or p8_dataSz is NULL.
 */
WOLFSSL_API int wc_Pkcs8_info(byte * pkcsData, word32 pkcsDataSz, word32 * oid) {
  int ret = 0;
    word32 algorSum = 0;

    if (!pkcsData || !pkcsDataSz) {
        return BAD_FUNC_ARG;
    }

    // Creates a copy of the data
    byte * buff = XMALLOC(pkcsDataSz, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
    if (buff == NULL) {
        ret = MEMORY_E;
    }
    if (ret == 0) {
      // Copies the data
      XMEMCPY(buff, pkcsData, pkcsDataSz);

#if defined(HAVE_PKCS8) || defined(HAVE_PKCS12)

      // Removes the PKCS8 header
      ret = ToTraditional_ex(buff, pkcsDataSz, &algorSum);
      *oid = algorSum;
#else
    ret = NOT_COMPILED_IN;
#endif // HAVE_PKCS8 || HAVE_PKCS12


      // Frees the buffer
      if (buff) XFREE(buff, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
      buff = NULL;
    }

    return ret;
}

WOLFSSL_API int wc_AsymKey_Sign(byte* sig, word32* sigLen, const byte* msg, word32 msgLen, const AsymKey* key,
    WC_RNG* rng) {

  (void)sig;
  (void)sigLen;
  (void)msg;
  (void)msgLen;
  (void)key;
  (void)rng;

  return NOT_COMPILED_IN;
}

WOLFSSL_API int wc_AsymKey_Verify(const AsymKey* key, const byte* sig, word32 sigLen,
        const byte* msg, word32 msgLen, int* res) {

  (void)key;
  (void)sig;
  (void)sigLen;
  (void)msg;
  (void)msgLen;
  (void)res;

  return NOT_COMPILED_IN;
}

WOLFSSL_API int wc_AsymKey_Sign_ex(const AsymKey* key, const byte* in, word32 inLen,
        byte* out, word32* outLen, WC_RNG* rng, const byte* context, byte contextLen) {

  (void)key;
  (void)in;
  (void)inLen;
  (void)out;
  (void)outLen;
  (void)rng;
  (void)context;
  (void)contextLen;

  return NOT_COMPILED_IN;
}

WOLFSSL_API int wc_AsymKey_Verify_ex(const AsymKey* key, const byte* sig, word32 sigLen,
        const byte* in, word32 inLen, int* res, const byte* context, byte contextLen) {

  (void)key;
  (void)sig;
  (void)sigLen;
  (void)in;
  (void)inLen;
  (void)res;
  (void)context;
  (void)contextLen;

  return NOT_COMPILED_IN;
}


