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

  int ret = 0;
  void* keyPtr = NULL;

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

  if (!key)
    return BAD_FUNC_ARG;

  switch (key->type) {
#ifdef HAVE_DSA
    case DSA_TYPE:
        return DSAk;
        break;
#endif
#ifndef NO_RSA
    case RSA_TYPE:
        return RSAk;
        break;
#endif
#ifdef HAVE_ECC
    case ECC_TYPE:
        return ECDSAk;
        break;
#endif
#ifdef HAVE_ED25519
    case ED25519_TYPE:
        return ED25519k;
        break;
#endif
#ifdef HAVE_ED448
    case ED448_TYPE:
        return ED448k;
        break;
#endif
#ifdef HAVE_DILITHIUM
    case ML_DSA_LEVEL2_TYPE:
        return ML_DSA_LEVEL2k;
        break;
    case ML_DSA_LEVEL3_TYPE:
        return ML_DSA_LEVEL3k;
        break;
    case ML_DSA_LEVEL5_TYPE:
        return ML_DSA_LEVEL5k;
        break;
#endif
#ifdef HAVE_FALCON
    case FALCON_LEVEL1_TYPE:
        return FALCON_LEVEL1k;
        break;
    case FALCON_LEVEL5_TYPE:
        return FALCON_LEVEL5k;
        break;
#endif
#ifdef HAVE_MLDSA_COMPOSITE
    case MLDSA44_RSAPSS2048_TYPE:
        return MLDSA44_RSAPSS2048k;
        break;
    case MLDSA44_RSA2048_TYPE:
        return MLDSA44_RSA2048k;
        break;
    case MLDSA44_NISTP256_TYPE:
        return MLDSA44_NISTP256k;
        break;
    case MLDSA44_ED25519_TYPE:
        return MLDSA44_ED25519k;
        break;
    case MLDSA65_ED25519_TYPE:
        return MLDSA65_ED25519k;
        break;
    case MLDSA65_RSAPSS4096_TYPE:
        return MLDSA65_RSAPSS4096k;
        break;
    case MLDSA65_RSA4096_TYPE:
        return MLDSA65_RSA4096k;
        break;
    case MLDSA65_RSAPSS3072_TYPE:
        return MLDSA65_RSAPSS3072k;
        break;
    case MLDSA65_RSA3072_TYPE:
        return MLDSA65_RSA3072k;
        break;
    case MLDSA65_NISTP256_TYPE:
        return MLDSA65_NISTP256k;
        break;
    case MLDSA65_BPOOL256_TYPE:
        return MLDSA65_BPOOL256k;
        break;
    case MLDSA87_BPOOL384_TYPE:
        return MLDSA87_BPOOL384k;
        break;
    case MLDSA87_NISTP384_TYPE:
        return MLDSA87_NISTP384k;
        break;
    case MLDSA87_ED448_TYPE:
        return MLDSA87_ED448k;
        break;
    // ------- Draft 2 ------
    case D2_MLDSA44_RSAPSS2048_SHA256_TYPE:
        return D2_MLDSA44_RSAPSS2048k;
        break;
    case D2_MLDSA44_RSA2048_SHA256_TYPE:
        return D2_MLDSA44_RSA2048k;
        break;
    case D2_MLDSA44_NISTP256_SHA256_TYPE:
        return D2_MLDSA44_NISTP256k;
        break;
    case D2_MLDSA44_ED25519_SHA256_TYPE:
        return D2_MLDSA44_ED25519k;
        break;
    case D2_MLDSA65_ED25519_SHA512_TYPE:
        return D2_MLDSA65_ED25519k;
        break;
    case D2_MLDSA65_BPOOL256_SHA512_TYPE:
        return D2_MLDSA65_BPOOL256k;
        break;
    case D2_MLDSA65_NISTP256_SHA512_TYPE:
      return D2_MLDSA65_NISTP256k;
      break;
    case D2_MLDSA65_RSAPSS3072_SHA512_TYPE:
      return D2_MLDSA65_RSAPSS3072k;
      break;
    case D2_MLDSA65_RSA3072_SHA512_TYPE:
      return D2_MLDSA65_RSA3072k;
      break;
    case D2_MLDSA87_BPOOL384_SHA512_TYPE:
      return D2_MLDSA87_BPOOL384k;
      break;
    case D2_MLDSA87_NISTP384_SHA512_TYPE:
      return D2_MLDSA87_NISTP384k;
      break;
    case D2_MLDSA87_ED448_SHA512_TYPE:
      return D2_MLDSA87_ED448k;
      break;
#endif
#ifdef HAVE_SPHINCS
    case SPHINCS_HARAKA_128S_ROBUST_TYPE:
        return SPHINCS_HARAKA_128S_ROBUSTk;
        break;
    case SPHINCS_HARAKA_128S_SIMPLE_TYPE:
        return SPHINCS_HARAKA_128S_SIMPLEk;
        break;
    case SPHINCS_HARAKA_192S_ROBUST_TYPE:
        return SPHINCS_HARAKA_192S_ROBUSTk;
        break;
    case SPHINCS_HARAKA_192S_SIMPLE_TYPE:
        return SPHINCS_HARAKA_192S_SIMPLEk;
        break;
    case SPHINCS_HARAKA_256S_ROBUST_TYPE:
        return SPHINCS_HARAKA_256S_ROBUSTk;
        break;
    case SPHINCS_HARAKA_256S_SIMPLE_TYPE:
        return SPHINCS_HARAKA_256S_SIMPLEk;
        break;
    case SPHINCS_SHAKE_128S_ROBUST_TYPE:
        return SPHINCS_SHAKE_128S_ROBUSTk;
        break;
    case SPHINCS_SHAKE_128S_SIMPLE_TYPE:
        return SPHINCS_SHAKE_128S_SIMPLEk;
        break;
    case SPHINCS_SHAKE_192S_ROBUST_TYPE:
        return SPHINCS_SHAKE_192S_ROBUSTk;
        break;
    case SPHINCS_SHAKE_192S_SIMPLE_TYPE:
        return SPHINCS_SHAKE_192S_SIMPLEk;
        break;
    case SPHINCS_SHAKE_256S_ROBUST_TYPE:
        return SPHINCS_SHAKE_256S_ROBUSTk;
        break;
    case SPHINCS_SHAKE_256S_SIMPLE_TYPE:
        return SPHINCS_SHAKE_256S_SIMPLEk;
        break;
#endif

    default:
        return BAD_FUNC_ARG;
  }
  
  return 0;
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
WOLFSSL_API int wc_AsymKey_size(const AsymKey* key) {

  int ret = 0;

    if (!key)
        return BAD_FUNC_ARG;

    switch (key->type) {
#ifdef HAVE_DSA
        case DSA_TYPE:
            ret = wc_DsaKeyToDer(key->key.dsaKey, NULL, 0);
            break;
#endif
#ifndef NO_RSA
        case RSA_TYPE:
            ret = wc_RsaKeyToDer(key->key.rsaKey, NULL, 0);
            break;
#endif
#ifdef HAVE_ECC
        case ECC_TYPE:
            byte eccBuff[512];
            word32 * eccSz = sizeof(eccBuff);
            if ((wc_ecc_export_x963(key->key.eccKey, eccBuff, &eccSz) < 0)) {
                ret = BAD_STATE_E;
            } else {
                ret = eccSz;
            }
            break;
#endif
#ifdef HAVE_ED25519
    case ED25519_TYPE:
        ret = wc_Ed25519KeyToDer(key->key.ed25519Key, NULL, 0);
        break;
#endif
#ifdef HAVE_ED448
    case ED448_TYPE:
        ret = wc_Ed448KeyToDer(key->key.ed448Key, NULL, 0);
        break;
#endif
#ifdef HAVE_DILITHIUM
    case ML_DSA_LEVEL2_TYPE:
    case ML_DSA_LEVEL3_TYPE:
    case ML_DSA_LEVEL5_TYPE:
        ret = wc_DilithiumKeyToDer(key->key.dilithiumKey, NULL, 0);
        break;
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
    case MLDSA87_ED448_TYPE:
        ret = wc_MlDsaCompositeKeyToDer(key->key.mldsaCompKey, NULL, 0);
        break;
#endif
#ifdef HAVE_FALCON
    case FALCON_LEVEL1_TYPE:
    case FALCON_LEVEL5_TYPE:
        ret = wc_FalconKeyToDer(key->key.falcon, NULL, 0);
        break;
#endif
#ifdef HAVE_SPHINCS
    case SPHINCS_FAST_LEVEL1_TYPE:
    case SPHINCS_FAST_LEVEL3_TYPE:
    case SPHINCS_FAST_LEVEL5_TYPE:
    case SPHINCS_SMALL_LEVEL1_TYPE:
    case SPHINCS_SMALL_LEVEL3_TYPE:
    case SPHINCS_SMALL_LEVEL5_TYPE:
        ret = wc_SphincsKeyToDer(key->key.sphincs, NULL, 0);
        break;
#endif

    default:
        ret = BAD_FUNC_ARG;
  }

    return ret;

}

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
 * @param [in]  data    Key data.
 * @param [in]  dataSz  Size of key data.
 * @param [in]  format  Format of key data (1 = PEM, 0 = DER, -1 = TRY BOTH).
 * @param [in]  passwd  Password for the keypair, NULL if not encrypted.
 * @param [in]  passwdSz  Size of the password in bytes, 0 if not encrypted.
 * @return  0 otherwise.
 * @return  BAD_FUNC_ARG when a parameter is NULL or privSz is less than size
 *          required for level,
 */
WOLFSSL_API int wc_AsymKey_import(AsymKey* key, const byte* data, word32 dataSz, int format, const char* passwd) {

  byte * buff = NULL;
  word32 buffSz = 0;

  byte * der = NULL;
  word32 derSz = 0;

  word32 algorSum = 0;
  word32 idx = 0;
  
  int ret = 0;

  if (!key || !data || dataSz <= 0)
    return BAD_FUNC_ARG;

  /* Assumes the input is DER for now */
  derSz = dataSz;

  /* Convert PEM to DER. */
  if (format == 1 || format < 0) {

      // Allocates memory for the buffer (to avoid changing the original key data)
      buff = (byte *)XMALLOC(dataSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
      buffSz = dataSz;

      // Decodes PEM into DER
      if ((ret = wc_KeyPemToDer(data, dataSz, buff, buffSz, passwd)) < 0) {
        XFREE(buff, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
      }

      // If the format was not explicity required, allow for the DER format
      if (format == 1 && ret <= 0) {
        XFREE(buff, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
      }

      if (ret > 0) {
          der = buff;
          derSz  = buffSz;
      } else {
          der = (byte *)data;
      }

  } else {
      der = (byte *)data;
  }

  // Gets the key information (OID or Key_Sum)
  if ((ret = wc_AsymKey_info(&algorSum, der, derSz, 0)) < 0) {
    return ret;
  }

  switch (algorSum) {
#ifndef NO_RSA
    case RSAk:
    case RSAPSSk:
        RsaKey * rsaKey = (RsaKey *)XMALLOC(sizeof(RsaKey), NULL, DYNAMIC_TYPE_PRIVATE_KEY);
        ret = wc_RsaPrivateKeyDecode(der, &idx, rsaKey, derSz);
        if (ret != 0) {
            XFREE(rsaKey, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
            return -1;
        }
        key->key.rsaKey = rsaKey;
        key->type = RSA_TYPE;
        break;
#endif
#ifdef HAVE_ECC
    case ECDSAk:
        ecc_key * ecKey = (ecc_key *)XMALLOC(sizeof(ecc_key), NULL, DYNAMIC_TYPE_PRIVATE_KEY);
        XMEMSET(ecKey, 0, sizeof(ecc_key));
        wc_ecc_init_ex(ecKey, NULL, devId);

        if (wc_EccPrivateKeyDecode(der, &idx, ecKey, derSz) < 0) {
            XFREE(ecKey, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
            return ASN_PARSE_E;
        }
        if (wc_ecc_get_curve_id(ecKey->idx) < 0) {
            return BAD_STATE_E;
        }
        key->key.eccKey = ecKey;
        key->type = ECC_TYPE;
        break;
#endif
#ifdef HAVE_ED25519
    case ED25519k:
        ed25519_key * edKey = (ed25519_key *)XMALLOC(sizeof(ed25519_key), NULL, DYNAMIC_TYPE_PRIVATE_KEY);
        XMEMSET(edKey, 0, sizeof(ed25519_key));
        wc_ed25519_init(edKey);

        if ((ret = wc_Ed25519PrivateKeyDecode(der, &idx, edKey, derSz)) < 0) {
            return ASN_PARSE_E;
        }
        key->key.ed25519Key = edKey;
        key->type = ED25519_TYPE;
        break;
#endif
#ifdef HAVE_ED448
    case ED448k:
        ed448_key * ed448Key = (ed448_key *)XMALLOC(sizeof(ed448_key), NULL, DYNAMIC_TYPE_PRIVATE_KEY);
        XMEMSET(ed448Key, 0, sizeof(ed448_key));

        if ((ret = wc_Ed448PrivateKeyDecode(der, &idx, ed448Key, derSz)) < 0) {
            return ASN_PARSE_E;
        }
        key->key.ed448Key = ed448Key;
        key->type = ED448_TYPE;
        break;
#endif
#ifdef HAVE_DILITHIUM
    case ML_DSA_LEVEL5k:
    case ML_DSA_LEVEL3k:
    case ML_DSA_LEVEL2k:
        MlDsaKey * mlDsaKey = (MlDsaKey *)XMALLOC(sizeof(MlDsaKey), NULL, DYNAMIC_TYPE_PRIVATE_KEY);
        if (mlDsaKey == NULL) {
            return MEMORY_E;
        }
        XMEMSET(mlDsaKey, 0, sizeof(MlDsaKey));

        // Initializes the key and sets the expected level
        wc_dilithium_init(mlDsaKey);
        if (algorSum == ML_DSA_LEVEL5k) {
            wc_dilithium_set_level(mlDsaKey, 5);
            key->type = ML_DSA_LEVEL5_TYPE;
        } else if (algorSum == ML_DSA_LEVEL3k) {
            wc_dilithium_set_level(mlDsaKey, 3);
            key->type = ML_DSA_LEVEL3_TYPE;
        } else if (algorSum == ML_DSA_LEVEL2k) {
            wc_dilithium_set_level(mlDsaKey, 2);
            key->type = ML_DSA_LEVEL2_TYPE;
        }

        // Decodes the key
        if ((ret = wc_Dilithium_PrivateKeyDecode(der, &idx, mlDsaKey, derSz)) < 0) {
            return ret;
        }
        key->key.dilithiumKey = mlDsaKey;
        break;
#endif
#ifdef HAVE_FALCON
    case FALCON_LEVEL1k:
    case FALCON_LEVEL5k:
        falcon_key * falconKey = (falcon_key *)XMALLOC(sizeof(falcon_key), NULL, DYNAMIC_TYPE_PRIVATE_KEY);
        if ((ret = wc_FalconPrivateKeyDecode(der, idx, falconKey, derSz)) < 0) {
            return ret;
        }
        XMEMSET(falconKey, 0, sizeof(falcon_key *));
        wc_falcon_init(falconKey);
        if (algorSum == FALCON_LEVEL1k) {
            wc_falcon_set_level(falconKey, 1);
            key->type = FALCON_LEVEL1_TYPE;
        } else if (algorSum == FALCON_LEVEL5k) {
            wc_falcon_set_level(falconKey, 5);
            key->type = FALCON_LEVEL5_TYPE;
        }
        key->key.falconKey = falconKey;
        break;
#endif
#ifdef HAVE_MLDSA_COMPOSITE
    case MLDSA44_RSA2048k:
    case MLDSA44_RSAPSS2048k:
    case MLDSA44_NISTP256k:
    // case MLDSA44_BPOOL256k:
    case MLDSA44_ED25519k:

    case MLDSA65_RSAPSS3072k:
    case MLDSA65_RSA3072k:
    case MLDSA65_RSAPSS4096k:
    case MLDSA65_RSA4096k:
    case MLDSA65_NISTP256k:
    case MLDSA65_ED25519k:
    case MLDSA65_BPOOL256k:

    case MLDSA87_BPOOL384k:
    case MLDSA87_NISTP384k:
    case MLDSA87_ED448k:
    // ----- Draft 2 ----- //
    case D2_MLDSA44_RSAPSS2048k:
    case D2_MLDSA44_RSA2048k:
    case D2_MLDSA44_NISTP256k:
    case D2_MLDSA44_ED25519k:

    case D2_MLDSA65_RSAPSS3072k:
    case D2_MLDSA65_RSA3072k:
    case D2_MLDSA65_NISTP256k:
    case D2_MLDSA65_ED25519k:
    case D2_MLDSA65_BPOOL256k:

    case D2_MLDSA87_BPOOL384k:
    case D2_MLDSA87_NISTP384k:
    case D2_MLDSA87_ED448k:
        mldsa_composite_key * mldsaCompKey = NULL;
        int level = 0;

        // Gets the composite type
        if ((level = wc_mldsa_composite_key_sum_level(algorSum)) < 0) {
            return ALGO_ID_E;
        }

        // Allocates the memory for the key        
        mldsaCompKey = (mldsa_composite_key *)XMALLOC(sizeof(mldsa_composite_key), NULL, DYNAMIC_TYPE_PRIVATE_KEY);
        if (mldsaCompKey == NULL) {
            return MEMORY_E;
        }
        XMEMSET(mldsaCompKey, 0, sizeof(mldsa_composite_key));

        if ((ret = wc_MlDsaComposite_PrivateKeyDecode(der, &idx, mldsaCompKey, derSz, level)) < 0) {
            XFREE(mldsaCompKey, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
            return ret;
        }
        key->key.mldsaCompKey = mldsaCompKey;
        key->type = wc_mldsa_composite_level_type(level);
        break;
#endif

        default:
            return BAD_FUNC_ARG;
    }

    if (der) XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
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
 * @return  Number of bytes written on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BUFFER_E when outLen is less than DILITHIUM_LEVEL2_KEY_SIZE.
 */
WOLFSSL_API int wc_AsymKey_export(const AsymKey* key, byte* buff, word32 buffLen, int format, const byte* passwd, word32 passwdSz) {

    if (!key)
        return BAD_FUNC_ARG;

    int ret = 0;
    byte * derPtr = NULL;
    word32 derSz = 0;
    word32 p8_outSz = 0;
    byte * p8_data = NULL;

    word32 keySum = wc_AsymKey_Oid(key);

    switch (keySum) {
#ifndef NO_RSA
        case RSAk:
        case RSAPSSk:

#if defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA) || \
    defined(WOLFSSL_KCAPI_RSA) || defined(WOLFSSL_SE050)

            ret = wc_RsaKeyToDer((RsaKey *)key, NULL, sizeof(derPtr));
            if (ret < 0) {
                printf("Error exporting key (%d)\n", ret);
                return -1;
            }
            derSz = ret;
            derPtr = (byte *)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (derPtr == NULL) {
                printf("Memory allocation Error exporting key\n");
                return -1;
            }
            ret = wc_RsaKeyToDer((RsaKey *)key, derPtr, derSz);
            if (ret < 0) {
                printf("RSA: Error exporting key (size: %d, err: %d)\n", derSz, ret);
                return -1;
            }
            // ----------------------
            // Export in PKCS8 format
            // ----------------------

            if ((ret = wc_CreatePKCS8Key(NULL, (word32 *)&p8_outSz, derPtr, derSz, keySum, NULL, 0)) < 0 && ret != LENGTH_ONLY_E) {
                printf("Error creating PKCS8 key (%d)\n", ret);
                return -1;
            }

            p8_data = (byte *)XMALLOC(p8_outSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (p8_data == NULL) {
                printf("Error exporting key\n");
                return -1;
            }
            if ((ret = wc_CreatePKCS8Key(p8_data, (word32 *)&p8_outSz, derPtr, derSz, keySum, NULL, 0)) < 0) {
                printf("Error creating PKCS8 key (%d)\n", ret);
                return -1;
            }

            if (ret < 0) {
                printf("Error exporting key\n");
                return -1;
            }
#else
            return -1;
#endif // WOLFSSL_KEY_GEN || OPENSSL_EXTRA || WOLFSSL_KCAPI_RSA || WOLFSSL_SE050
            break;
#endif
#ifdef HAVE_ECC
        case ECDSAk:

            // Get the size of the DER key
            derSz = wc_EccKeyDerSize((ecc_key *)key, 1);
            if (derSz < 0) {
                printf("Error exporting key (%d)\n", derSz);
                return -1;
            }

            // Allocate memory for the DER key
            derPtr = (byte *)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (derPtr == NULL) {
                printf("Memory Error exporting key (%d)\n", derSz);
                return -1;
            }

            // Export the key to DER format
            ret = wc_EccKeyToDer((ecc_key *)key, derPtr, derSz);
            if (ret < 0) {
                printf("EC: Error exporting key (derPtr: %p, derSz: %d, ret: %d)\n", derPtr, derSz, ret);
                return -1;
            }

            // ----------------------
            // Export in PKCS8 format
            // ----------------------

            byte * curveOid = NULL;
            word32 curveOidSz = 0;
            if ((ret = wc_ecc_get_oid(((ecc_key*)key)->dp->oidSum, (const byte **)&curveOid, &curveOidSz)) < 0){
                printf("Error getting curve OID\n");
                return -1;
            }

            if ((ret = wc_CreatePKCS8Key(NULL, (word32 *)&p8_outSz, derPtr, derSz, ECDSAk, curveOid, curveOidSz)) < 0 && ret != LENGTH_ONLY_E) {
                printf("Error creating PKCS8 key (%d)\n", ret);
                return -1;
            }

            p8_data = (byte *)XMALLOC(p8_outSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (p8_data == NULL) {
                printf("Error exporting key\n");
                return -1;
            }
            if ((ret = wc_CreatePKCS8Key(p8_data, (word32 *)&p8_outSz, derPtr, derSz, keySum, curveOid, curveOidSz)) < 0 && ret != LENGTH_ONLY_E) {
                printf("Error creating PKCS8 key (%d)\n", ret);
                return -1;
            }

            if (ret < 0) {
                printf("Error exporting key\n");
                return -1;
            }
            break;
#endif
#ifdef HAVE_ED25519
        case ED25519k:

            // Get the size of the DER key
            derSz = wc_Ed25519KeyToDer((ed25519_key *)key, NULL, sizeof(derPtr));
            if (derSz < 0) {
                printf("Error exporting key\n");
                return -1;
            }

            // Allocate memory for the DER key
            derPtr = (byte *)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (derPtr == NULL) {
                printf("Error exporting key\n");
                return -1;
            }

            // Export the key to DER format
            derSz = wc_Ed25519KeyToDer((ed25519_key *)key, derPtr, derSz);
            if (derSz < 0) {
                printf("Error exporting key\n");
                return -1;
            }

            p8_data = derPtr;
            p8_outSz = derSz;

            break;
#endif
#ifdef HAVE_ED448
        case ED448k:
            derSz = wc_Ed448KeyToDer((ed448_key *)key, NULL, sizeof(derPtr));
            if (derSz < 0) {
                printf("Error exporting key\n");
                return -1;
            }
            derPtr = (byte *)XMALLOC(derSz, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
            if (derPtr == NULL) {
                printf("Error exporting key\n");
                return -1;
            }
            derSz = wc_Ed448KeyToDer((ed448_key *)key, derPtr, derSz);
            if (derSz < 0) {
                printf("Error exporting key\n");
                return -1;
            }

            // No Need to convert to PKCS8
            p8_data = derPtr;
            p8_outSz = derSz;

            break;
#endif
#ifdef HAVE_DILITHIUM
        case ML_DSA_LEVEL5k:
        case ML_DSA_LEVEL3k:
        case ML_DSA_LEVEL2k:
            derSz = wc_Dilithium_KeyToDer((MlDsaKey *)key, NULL, sizeof(derPtr));
            if (derSz < 0) {
                printf("Error exporting key\n");
                return -1;
            }
            derPtr = (byte *)XMALLOC(derSz, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
            if (derPtr == NULL) {
                printf("Error exporting key\n");
                return -1;
            }
            derSz = wc_Dilithium_KeyToDer((MlDsaKey *)key, derPtr, derSz);
            if (derSz < 0) {
                printf("Error exporting key\n");
                return -1;
            }
            p8_data = derPtr;
            p8_outSz = derSz;
            break;
#endif
#ifdef HAVE_FALCON
        case FALCON_LEVEL1k:
        case FALCON_LEVEL5k:
            derSz = wc_FalconKeyToDer((falcon_key *)key, NULL, sizeof(derPtr));
            if (derSz < 0) {
                printf("Error exporting key\n");
                return -1;
            }
            derPtr = (byte *)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (derPtr == NULL) {
            return MEMORY_E;
            }
            derSz = wc_FalconKeyToDer((falcon_key *)key, derPtr, derSz);
            if (derSz < 0) {
                XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                return derSz;
            }
            break;
#endif
#ifdef HAVE_MLDSA_COMPOSITE
        case MLDSA44_RSAPSS2048k:
        case MLDSA44_RSA2048k:
        case MLDSA44_NISTP256k:
        // case MLDSA44_BPOOL256k:
        case MLDSA44_ED25519k:

        case MLDSA65_RSAPSS3072k:
        case MLDSA65_RSA3072k:
        case MLDSA65_RSAPSS4096k:
        case MLDSA65_RSA4096k:
        case MLDSA65_ED25519k:
        case MLDSA65_NISTP256k:
        case MLDSA65_BPOOL256k:

        case MLDSA87_BPOOL384k:
        case MLDSA87_NISTP384k:
        case MLDSA87_ED448k:

            derSz = wc_MlDsaComposite_KeyToDer((mldsa_composite_key *)key, NULL, 0);
            // derSz = wc_MlDsaComposite_PrivateKeyToDer((mldsa_composite_key *)key, NULL, 0);
            if (derSz < 0) {
                return derSz;
            }
            derPtr = (byte *)XMALLOC(derSz, ((mldsa_composite_key *)key)->heap, DYNAMIC_TYPE_PRIVATE_KEY);
            if (derPtr == NULL) {
                return MEMORY_E;
            }
            derSz = wc_MlDsaComposite_KeyToDer((mldsa_composite_key *)key, derPtr, derSz);
            // derSz = wc_MlDsaComposite_PrivateKeyToDer((mldsa_composite_key *)key, derPtr, derSz);
            if (derSz < 0) {
                XFREE(derPtr, ((mldsa_composite_key *)key)->heap, DYNAMIC_TYPE_PRIVATE_KEY);
                return derSz;
            }
            break;
#endif

        default:
            printf("Unsupported key type (%d)\n", keySum);
            return BAD_FUNC_ARG;
    }

    // keyData = p8_data;
    // outSz = p8_outSz;

    // --------------------
    // Export to PEM format
    // --------------------

#ifdef WOLFSSL_DER_TO_PEM

    if (format == 1) {
        int pem_dataSz = 0;
        byte * pem_data = NULL;

        ret = wc_DerToPem(p8_data, p8_outSz, NULL, 0, PKCS8_PRIVATEKEY_TYPE);
        if (ret <= 0) {
            return ret;
        }
        pem_dataSz = ret;
        pem_data = (byte *)XMALLOC(pem_dataSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (pem_data == NULL) {
            return ret;
        }
        ret = wc_DerToPem(p8_data, p8_outSz, pem_data, pem_dataSz, PKCS8_PRIVATEKEY_TYPE);
        if (ret <= 0) {
            XFREE(pem_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return ret;
        }
        pem_dataSz = ret;
    }
#endif

    // Frees the DER buffer
    if (derPtr) XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    (void)passwd;
    (void)passwdSz;

    return ret;
}


/* Retrieves the OID of the keypair.
 *
 * @param [in]  p8_data    Array holding the PKCS#8 encoded KeyPair.
 * @param [in]  p8_dataSz  Number of bytes of data in array.
 * @param [out] oid        The OID of the keypair.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when p8_data or p8_dataSz is NULL.
 */
WOLFSSL_API int wc_AsymKey_info(word32 * oid, byte * pkcsData, word32 pkcsDataSz, int format) {
  int ret = 0;
    word32 algorSum = 0;

    if (!pkcsData || !pkcsDataSz) {
        return BAD_FUNC_ARG;
    }

    // Creates a copy of the data
    word32 buffSz = pkcsDataSz;
    byte * buff = XMALLOC(pkcsDataSz, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
    if (buff == NULL) {
        ret = MEMORY_E;
    }
    /* Convert PEM to DER. */
    if (format == 1 || format < 0) {

        // Decodes PEM into DER
        if ((ret = wc_KeyPemToDer(pkcsData, pkcsDataSz, buff, buffSz, NULL)) < 0) {
          XFREE(buff, NULL, DYNAMIC_TYPE_TMP_BUFFER);
          return ret;
        }

        // If the format was not explicity required, allow for the DER format
        if (format == 1 && ret <= 0) {
          XFREE(buff, NULL, DYNAMIC_TYPE_TMP_BUFFER);
          return ret;
        }

        if (ret > 0) {
            buffSz = ret;
        } else {
            // Copies the data (allows for trying with DER)
            XMEMCPY(buff, pkcsData, pkcsDataSz);
        }

    } else {
        // Copies the data
        XMEMCPY(buff, pkcsData, pkcsDataSz);
    }
    if (ret == 0) {

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


