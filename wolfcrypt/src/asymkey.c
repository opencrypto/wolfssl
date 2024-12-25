/* asymkey.c */

#ifndef WOLF_CRYPT_ASYMKEY_H
#include <wolfssl/wolfcrypt/asymkey.h>
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
        printf("[%s:%d] %s(): " a "\n", __FILE__, __LINE__, __func__);      \
        fflush(stdout);                               \
    } while (0)


#define MADWOLF_DEBUG(a, ...)                         \
    do {                                              \
        printf("[%s:%d] %s(): " a "\n", __FILE__, __LINE__, __func__, __VA_ARGS__);      \
        fflush(stdout);                               \
    } while (0)


/* Functions */

/* Allocates the memory associated with a new AsymKey.
 *
 * @return  MEMORY_E when memory allocation fails.
 * @return  the pointer to the new AsymKey.
 */
AsymKey * wc_AsymKey_new(void) {

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
int wc_AsymKey_free(AsymKey * key) {

  if (!key)
    return BAD_FUNC_ARG;

  switch (key->type) {
#ifdef HAVE_DSA
    case DSA_TYPE: {
          wc_FreeDsaKey(key->key.dsaKey);
        } break;
#endif
#ifndef NO_RSA
    case RSA_TYPE: {
          wc_FreeRsaKey(&key->val.rsaKey);
        } break;
#endif
#ifdef HAVE_ECC
    case ECC_TYPE: {
          wc_ecc_free(&key->val.eccKey);
    } break;
#endif
#ifdef HAVE_ED25519
    case ED25519_TYPE: {
        wc_ed25519_free(&key->val.ed25519Key);
    } break;

#endif
#ifdef HAVE_ED448
    case ED448_TYPE:{
        wc_ed448_free(&key->val.ed448Key);
    } break;
#endif
#ifdef HAVE_DILITHIUM
    case ML_DSA_LEVEL2_TYPE:
    case ML_DSA_LEVEL3_TYPE:
    case ML_DSA_LEVEL5_TYPE: {
        wc_dilithium_free(&key->val.dilithiumKey);
    } break;
#endif
#ifdef HAVE_FALCON
    case FALCON_LEVEL1_TYPE:
    case FALCON_LEVEL5_TYPE: {
        wc_falcon_free(&key->val.falconKey);
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
        // if (!key->key.mldsaCompKey) {
        //   wc_mldsa_composite_free(key->key.mldsaCompKey);
        //   XFREE(key->key.mldsaCompKey, NULL, DYNAMIC_TYPE_MLDSA_COMPOSITE);
        //   key->key.mldsaCompKey = NULL;
        // }
        wc_mldsa_composite_free(&key->val.mldsaCompKey);
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
int wc_AsymKey_gen(AsymKey      ** key,
                   enum Key_Sum    Oid,
                   int             param,
                   byte          * seed,
                   word32          seedSz,
                   WC_RNG        * rng) {

    int ret = 0;
    // void* keyPtr = NULL;

    // int keyType = 0;
    int rngAlloc = 0;

    // int isPQC = 0;
    // int isHybrid = 0;

    AsymKey aKey = { 0x0 };

    (void)seed;
    (void)seedSz;

    if (!key)
        return BAD_FUNC_ARG;

    if (!rng) {
        rng = (WC_RNG*)XMALLOC(sizeof(WC_RNG), NULL, DYNAMIC_TYPE_RNG);
        if (rng == NULL)
            return MEMORY_E;
        ret = wc_InitRng(rng);
        if (ret < 0) {
            XFREE(rng, NULL, DYNAMIC_TYPE_RNG);
            return ret;
        }
        rngAlloc = 1;
    }

    switch (Oid) {
        case DSAk:
#ifdef HAVE_DSA
            keyPtr = &aKey.val.dsaKey;
            ret = wc_InitDsaKey((DsaKey *)keyPtr, NULL);
            if (ret < 0) {
                XFREE(keyPtr, NULL, DYNAMIC_TYPE_DSA);
                goto err;
            }
            ret = wc_MakeDsaKey(rng, (DsaKey *)keyPtr);
            if (ret < 0) {
                wc_FreeDsaKey((DsaKey *)keyPtr);
                XFREE(keyPtr, NULL, DYNAMIC_TYPE_DSA);
                goto err;
            }
            keyType = DSA_TYPE;
            isPQC = 0;
            isHybrid = 0;
#endif
            break;
        case RSAk:
        case RSAPSSk:
        case RSAESOAEPk:
#ifndef NO_RSA
            RsaKey * rsaKeyPtr = (RsaKey *)&aKey.val.rsaKey;
            if (param < 2048) {
                param = 2048;
                aKey.secBits = 112;
            } else if (param <= 3072) {
                aKey.secBits = 128;
            } else if (param <= 8192) {
                aKey.secBits = 192;
            } else if (param > 16384) {
                param = 16384;
                aKey.secBits = 256;
            }

            wc_FreeRsaKey(rsaKeyPtr);
            ret = wc_InitRsaKey(rsaKeyPtr, NULL);
            if (ret < 0) {
                goto err;
            }
            
            ret = wc_MakeRsaKey(rsaKeyPtr, param, WC_RSA_EXPONENT, rng);
            if (ret < 0) {
                wc_FreeRsaKey(rsaKeyPtr);
                goto err;
            }
            aKey.type = RSA_TYPE;
            aKey.isPQC = 0;
            aKey.isHybrid = 0;
#endif
            break;
    case ECDSAk:
#ifdef HAVE_ECC
            ecc_key * eccKeyPtr = (ecc_key *)&aKey.val.eccKey;

            int keySz = 0;
            if (param <= 0) param = ECC_SECP256R1;

            keySz = wc_ecc_get_curve_size_from_id(param);
            if (keySz < 0) {
                ret = keySz;
                goto err;
            }

            wc_ecc_free(eccKeyPtr);
            ret = wc_ecc_init(eccKeyPtr);
            if (ret < 0) {
                goto err;
            }
            ret = wc_ecc_make_key_ex(rng, keySz, eccKeyPtr, param);
            if (ret < 0) {
                wc_ecc_free(eccKeyPtr);
                goto err;
            }
            aKey.type = ECC_TYPE;
            aKey.isPQC = 0;
            aKey.isHybrid = 0;

            // TODO: Fix this shortcut
            if (keySz >= 32 && keySz < 48) {
                aKey.secBits = 128;
            } else if (keySz < 64) {
                aKey.secBits = 192;
            } else if (keySz < 64) {
                aKey.secBits = 256;
            }
#endif
            break;

        case ED25519k:
#ifdef HAVE_ED25519
            ed25519_key * ed25519Key = (ed25519_key *)&aKey.val.ed25519Key;

            wc_ed25519_free(ed25519Key);
            ret = wc_ed25519_init(ed25519Key);
            if (ret < 0) {
                return ret;
            }
            ret = wc_ed25519_make_key(rng, ED25519_KEY_SIZE, ed25519Key);
            if (ret < 0) {
                wc_ed25519_free(ed25519Key);
                goto err;
            }
            aKey.type = ED25519_TYPE;
            aKey.isPQC = 0;
            aKey.isHybrid = 0;
            aKey.secBits = 128;
#endif
            break;

        case ED448k:
#ifdef HAVE_ED448
            ed448_key * ed448Key = (ed448_key *)&aKey.val.ed448Key;

            wc_ed448_free(ed448Key);
            ret = wc_ed448_init(ed448Key);
            if (ret < 0) {
                return ret;
            }
            ret = wc_ed448_make_key(rng, ED448_KEY_SIZE, ed448Key);
            if (ret < 0) {
                wc_ed448_free(ed448Key);
                goto err;
            }
            aKey.type = ED448_TYPE;
            aKey.isPQC = 0;
            aKey.isHybrid = 0;
            aKey.secBits = 384;
#endif
            break;

        case DILITHIUM_LEVEL2k:
        case DILITHIUM_LEVEL3k:
        case DILITHIUM_LEVEL5k:
        case ML_DSA_LEVEL2k:
        case ML_DSA_LEVEL3k:
        case ML_DSA_LEVEL5k:
#ifdef HAVE_DILITHIUM
            dilithium_key * mldsaKey = (dilithium_key *)&aKey.val.dilithiumKey;
            // keyPtr = (void *)XMALLOC(sizeof(dilithium_key), NULL, DYNAMIC_TYPE_DILITHIUM);
            // if (keyPtr == NULL) {
            //     ret = MEMORY_E;
            //     goto err;
            // }
            wc_dilithium_free(mldsaKey);
            ret = wc_dilithium_init(mldsaKey);
            if (ret < 0) {
                goto err;
            }

            if (Oid == ML_DSA_LEVEL2k || Oid == DILITHIUM_LEVEL2k) {
                ret = wc_dilithium_set_level(mldsaKey, WC_ML_DSA_44);
                aKey.type = ML_DSA_LEVEL2_TYPE;
                aKey.secBits = 128;
            } else if (Oid == ML_DSA_LEVEL3k || Oid == DILITHIUM_LEVEL3k) {
                ret = wc_dilithium_set_level(mldsaKey, WC_ML_DSA_65);
                aKey.type = ML_DSA_LEVEL3_TYPE;
                aKey.secBits = 192;
            } else if (Oid == ML_DSA_LEVEL5k || Oid == DILITHIUM_LEVEL5k) {
                ret = wc_dilithium_set_level(mldsaKey, WC_ML_DSA_87);
                aKey.type = ML_DSA_LEVEL5_TYPE;
                aKey.secBits = 256;
            } else {
                ret = BAD_FUNC_ARG;
                goto err;
            }

            ret = wc_dilithium_make_key(mldsaKey, rng);
            if (ret < 0) {
                wc_dilithium_free(mldsaKey);
                goto err;
            }
            aKey.isPQC = 1;
            aKey.isHybrid = 0;
#endif
            break;

    case FALCON_LEVEL1k:
    case FALCON_LEVEL5k:
#ifdef HAVE_FALCON
        falcon_key * falconKey = (falcon_key *)&aKey.val.falconKey;
        // keyPtr = (void *)XMALLOC(sizeof(falcon_key), NULL, DYNAMIC_TYPE_FALCON);
        // if (keyPtr == NULL)
        //     return MEMORY_E;
        wc_falcon_free(falconKey);
        ret = wc_falcon_init(falconKey);
        if (ret < 0) {
            return ret;
        }
        if (Oid == FALCON_LEVEL1k) {
            ret = wc_falcon_set_level(falconKey, 1);
            aKey.type = FALCON_LEVEL1_TYPE;
            aKey.secBits = 128;
        } else if (Oid == FALCON_LEVEL5k) {
            ret = wc_falcon_set_level(falconKey, 5);
            aKey.type = FALCON_LEVEL5_TYPE;
            aKey.secBits = 256;
        } else {
            return BAD_FUNC_ARG;
        }
        if (ret == 0) {
            // ret = wc_falcon_make_key(keyPtr, rng);
            MADWOLF_DEBUG0("Falcon key generation not implemented");
            return NOT_COMPILED_IN;
        }
        aKey.isPQC = 1;
        aKey.isHybrid = 0;
#endif
        break;


#ifdef HAVE_MLDSA_COMPOSITE
        case MLDSA44_RSAPSS2048k:
        case MLDSA44_RSA2048k:
        case MLDSA44_NISTP256k:
        // case MLDSA44_BPOOL256k:
        case MLDSA44_ED25519k:
        case MLDSA65_ED25519k:
        case MLDSA65_RSAPSS4096k:
        case MLDSA65_RSA4096k:
        case MLDSA65_RSAPSS3072k:
        case MLDSA65_RSA3072k:
        case MLDSA65_NISTP256k:
        case MLDSA65_BPOOL256k:
        case MLDSA87_BPOOL384k:
        case MLDSA87_NISTP384k:
        case MLDSA87_ED448k:
        // ------- Draft 2 ---------- //
        case D2_MLDSA44_RSAPSS2048k:
        case D2_MLDSA44_RSA2048k:
        case D2_MLDSA44_ED25519k:
        case D2_MLDSA44_NISTP256k:
        case D2_MLDSA44_BPOOL256k:
        case D2_MLDSA65_RSAPSS3072k:
        case D2_MLDSA65_RSA3072k:
        case D2_MLDSA65_ED25519k:
        case D2_MLDSA65_NISTP256k:
        case D2_MLDSA65_BPOOL256k:
        case D2_MLDSA87_BPOOL384k:
        case D2_MLDSA87_NISTP384k:
        case D2_MLDSA87_ED448k:
            mldsa_composite_key * mldsaCompKey = (mldsa_composite_key *)&aKey.val.mldsaCompKey;
            int composite_level = wc_mldsa_composite_key_sum_level(Oid);
            if (composite_level < 0) {
                ret = composite_level;
                MADWOLF_DEBUG("Invalid composite level %d (OID: %d)", composite_level, Oid);
                goto err;
            }
            // keyPtr = (void *)XMALLOC(sizeof(mldsa_composite_key), NULL, DYNAMIC_TYPE_MLDSA_COMPOSITE);
            // if (keyPtr == NULL)
            //     return MEMORY_E;
            wc_mldsa_composite_free(mldsaCompKey);
            ret = wc_mldsa_composite_init(mldsaCompKey);
            if (ret < 0) {
                wc_mldsa_composite_free(mldsaCompKey);
                return ret;
            }
            if (ret == 0)
                ret = wc_mldsa_composite_make_key(mldsaCompKey, composite_level, rng);

            aKey.type = wc_mldsa_composite_type(mldsaCompKey);
            aKey.isHybrid = 1;
            aKey.isPQC = 1;
            // TODO: Fix this shortcut
            aKey.secBits = 128; // Shortcut - To be replaced by the different sec levels
            break;
#endif

        case SPHINCS_FAST_LEVEL1k:
        case SPHINCS_FAST_LEVEL3k:
        case SPHINCS_FAST_LEVEL5k:
        case SPHINCS_SMALL_LEVEL1k:
        case SPHINCS_SMALL_LEVEL3k:
        case SPHINCS_SMALL_LEVEL5k:
#ifdef HAVE_SPHINCS
            MADWOLF_DEBUG("Key type %d not implemented", Oid);
            ret = NOT_COMPILED_IN;
#endif
            break;

        case DHk:
        case SM2k:
        case X25519k:
        case X448k:
        case ANONk:
            MADWOLF_DEBUG("Key type %d not implemented", Oid);
            ret = NOT_COMPILED_IN;
            break;

        default:
            ret = BAD_FUNC_ARG;
            goto err;
    }

    if (ret == 0) {
        /* Allocates the outbound memory, if needed */
        if (*key == 0) {
            *key = wc_AsymKey_new();
            if (*key == NULL) {
                ret = MEMORY_E;
                goto err;
            }
        }

        // Copy the data to the destination key
        XMEMCPY(*key, &aKey, sizeof(AsymKey));
    }

err:
    if (rngAlloc) {
        wc_FreeRng(rng);
        XFREE(rng, NULL, DYNAMIC_TYPE_RNG);
    }

    return ret;
}
#endif /* ! WOLFSSL_NO_MAKE_KEY */

int wc_AsymKey_Oid(const AsymKey * key) {

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

int wc_AsymKey_CertType(const AsymKey* key) {

    int ret = 0;
    if (!key || key->type <= 0)
        return BAD_FUNC_ARG;

    switch (key->type) {

#ifdef HAVE_DSA
        case DSA_TYPE:
#endif
#ifndef NO_RSA
        case RSA_TYPE:
#endif
#ifdef HAVE_ECC
        case ECC_TYPE:
#endif
#ifdef HAVE_ED25519
        case ED25519_TYPE:
#endif
#ifdef HAVE_ED448
        case ED448_TYPE:
#endif
#ifdef HAVE_DILITHIUM
        case ML_DSA_LEVEL2_TYPE:
        case ML_DSA_LEVEL3_TYPE:
        case ML_DSA_LEVEL5_TYPE:
#endif
#ifdef HAVE_FALCON
        case FALCON_LEVEL1_TYPE:
        case FALCON_LEVEL5_TYPE:
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
        // ------- Draft 2 ------
        case D2_MLDSA44_RSAPSS2048_SHA256_TYPE:
        case D2_MLDSA44_RSA2048_SHA256_TYPE:
        case D2_MLDSA44_NISTP256_SHA256_TYPE:
        case D2_MLDSA44_ED25519_SHA256_TYPE:
        case D2_MLDSA65_ED25519_SHA512_TYPE:
        case D2_MLDSA65_BPOOL256_SHA512_TYPE:
        case D2_MLDSA65_NISTP256_SHA512_TYPE:
        case D2_MLDSA65_RSAPSS3072_SHA512_TYPE:
        case D2_MLDSA65_RSA3072_SHA512_TYPE:
        case D2_MLDSA87_BPOOL384_SHA512_TYPE:
        case D2_MLDSA87_NISTP384_SHA512_TYPE:
        case D2_MLDSA87_ED448_SHA512_TYPE:
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
        case SPHINCS_SHAKE_256S_SIMPLE_TYPE:
#endif
        ret = key->type;
        break;

        default:
            ret = BAD_FUNC_ARG;
    }

  return ret;
}

int wc_AsymKey_size(const AsymKey* key) {

  int ret = 0;

    if (!key)
        return BAD_FUNC_ARG;

    switch (key->type) {
#ifdef HAVE_DSA
        case DSA_TYPE:
            ret = wc_DsaKeyToDer((DsaKey *)key->key.dsaKey, NULL, 0);
            break;
#endif
#ifndef NO_RSA
        case RSA_TYPE:
            ret = wc_RsaKeyToDer((RsaKey *)&key->val.rsaKey, NULL, 0);
            break;
#endif
#ifdef HAVE_ECC
        case ECC_TYPE:
            byte eccBuff[512];
            word32 eccSz = sizeof(eccBuff);
            if ((wc_ecc_export_x963((ecc_key *)&key->val.eccKey, eccBuff, &eccSz) < 0)) {
                ret = BAD_STATE_E;
            } else {
                ret = eccSz;
            }
            break;
#endif
#ifdef HAVE_ED25519
    case ED25519_TYPE:
        ret = wc_Ed25519PrivateKeyToDer((ed25519_key *)&key->val.ed25519Key, NULL, 0);
        break;
#endif
#ifdef HAVE_ED448
    case ED448_TYPE:
        ret = wc_Ed448PrivateKeyToDer((ed448_key *)&key->val.ed448Key, NULL, 0);
        break;
#endif
#ifdef HAVE_DILITHIUM
    case ML_DSA_LEVEL2_TYPE:
    case ML_DSA_LEVEL3_TYPE:
    case ML_DSA_LEVEL5_TYPE:
        ret = wc_Dilithium_PrivateKeyToDer((dilithium_key *)&key->val.dilithiumKey, NULL, 0);
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
        ret = wc_MlDsaComposite_PrivateKeyToDer(&key->val.mldsaCompKey, NULL, 0);
        break;
#endif
#ifdef HAVE_FALCON
    case FALCON_LEVEL1_TYPE:
    case FALCON_LEVEL5_TYPE:
        ret = wc_FalconPrivateKeyToDer(key->val.falconKey, NULL, 0);
        break;
#endif
#ifdef HAVE_SPHINCS
    case SPHINCS_FAST_LEVEL1_TYPE:
    case SPHINCS_FAST_LEVEL3_TYPE:
    case SPHINCS_FAST_LEVEL5_TYPE:
    case SPHINCS_SMALL_LEVEL1_TYPE:
    case SPHINCS_SMALL_LEVEL3_TYPE:
    case SPHINCS_SMALL_LEVEL5_TYPE:
        ret = wc_Sphincs_PrivateKeyToDer(key->key.sphincs, NULL, 0);
        break;
#endif

    default:
        ret = BAD_FUNC_ARG;
  }

    return ret;

}

int wc_AsymKey_pub_size(const AsymKey* key) {

    int ret = 0;

    if (!key)
        return BAD_FUNC_ARG;

    switch (key->type) {
#ifdef HAVE_DSA
        case DSA_TYPE:
            ret = wc_DsaPublicKeyDerSize((DsaKey *)&key->key.dsaKey, 0);
            break;
#endif
#ifndef NO_RSA
        case RSA_TYPE:
            ret = wc_RsaPublicKeyDerSize((RsaKey *)&key->val.rsaKey, 0);
            break;
#endif
#ifdef HAVE_ECC
        case ECC_TYPE:
            ret = wc_EccPublicKeyToDer((ecc_key *)&key->val.eccKey, NULL, 0, 0);
            break;
#endif
#ifdef HAVE_ED25519
    case ED25519_TYPE:
        ret = wc_Ed25519PublicKeyToDer((ed25519_key *)&key->val.ed25519Key, NULL, 0, 0);
        break;
#endif
#ifdef HAVE_ED448
    case ED448_TYPE:
        ret = wc_Ed448PublicKeyToDer((ed448_key *)&key->val.ed448Key, NULL, 0, 0);
        break;
#endif
#ifdef HAVE_DILITHIUM
    case ML_DSA_LEVEL2_TYPE:
    case ML_DSA_LEVEL3_TYPE:
    case ML_DSA_LEVEL5_TYPE:
        ret = wc_Dilithium_PublicKeyToDer((dilithium_key *)&key->val.dilithiumKey, NULL, 0, 0);
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
        ret = wc_MlDsaComposite_PublicKeyToDer((mldsa_composite_key *)&key->val.mldsaCompKey, NULL, 0, 0);
        break;
#endif
#ifdef HAVE_FALCON
    case FALCON_LEVEL1_TYPE:
    case FALCON_LEVEL5_TYPE:
        ret = wc_Falcon_PublicKeyToDer((falcon_key *)&key->val.falconKey, NULL, 0, 0);
        break;
#endif
#ifdef HAVE_SPHINCS
    case SPHINCS_FAST_LEVEL1_TYPE:
    case SPHINCS_FAST_LEVEL3_TYPE:
    case SPHINCS_FAST_LEVEL5_TYPE:
    case SPHINCS_SMALL_LEVEL1_TYPE:
    case SPHINCS_SMALL_LEVEL3_TYPE:
    case SPHINCS_SMALL_LEVEL5_TYPE:
        ret = wc_Sphincs_PublicKeyToDer(key->key.sphincs, NULL, 0);
        break;
#endif

    default:
        ret = BAD_FUNC_ARG;
  }

    return ret;

}

int wc_AsymKey_sig_size(const AsymKey* key) {

    int ret = 0;

    if (!key)
        return BAD_FUNC_ARG;

    switch (key->type) {
#ifdef HAVE_DSA
        case DSA_TYPE:
            ret = NOT_COMPILED_IN; // Not Supported ?
            break;
#endif
#ifndef NO_RSA
        case RSA_TYPE:
            ret = wc_RsaEncryptSize((RsaKey *)&key->val.rsaKey);
            break;
#endif
#ifdef HAVE_ECC
        case ECC_TYPE:
            ret = wc_ecc_sig_size((ecc_key *)&key->val.eccKey);
            break;
#endif
#ifdef HAVE_ED25519
    case ED25519_TYPE:
        ret = wc_ed25519_sig_size((ed25519_key *)&key->val.ed25519Key);
        break;
#endif
#ifdef HAVE_ED448
    case ED448_TYPE:
        ret = wc_ed448_sig_size((ed448_key *)&key->val.ed448Key);
        break;
#endif
#ifdef HAVE_DILITHIUM
    case ML_DSA_LEVEL2_TYPE:
    case ML_DSA_LEVEL3_TYPE:
    case ML_DSA_LEVEL5_TYPE:
        ret = wc_dilithium_sig_size((dilithium_key *)&key->val.dilithiumKey);
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
        ret = wc_mldsa_composite_sig_size((mldsa_composite_key *)&key->val.mldsaCompKey);
        break;
#endif
#ifdef HAVE_FALCON
    case FALCON_LEVEL1_TYPE:
    case FALCON_LEVEL5_TYPE:
        ret = wc_falcon_sig_size(&key->val.falconKey);
        break;
#endif
#ifdef HAVE_SPHINCS
    case SPHINCS_FAST_LEVEL1_TYPE:
    case SPHINCS_FAST_LEVEL3_TYPE:
    case SPHINCS_FAST_LEVEL5_TYPE:
    case SPHINCS_SMALL_LEVEL1_TYPE:
    case SPHINCS_SMALL_LEVEL3_TYPE:
    case SPHINCS_SMALL_LEVEL5_TYPE:
        ret = wc_sphincs_sig_size(key->key.sphincs);
        break;
#endif

    default:
        ret = BAD_FUNC_ARG;
  }

    return ret;

}

int wc_AsymKey_check(const AsymKey* key) {

  (void)key;
  return NOT_COMPILED_IN;
}

int wc_AsymKey_Public_import(AsymKey* key, int type, const byte* in, word32 inLen, int format) {

    (void)key;
    (void)type;
    (void)in;
    (void)inLen;
    (void)format;

    return NOT_COMPILED_IN;
}

int wc_AsymKey_Public_export(byte* buff, word32 buffLen, int withAlg, int format, const AsymKey* key) {
  
    (void)key;
    (void)buff;
    (void)buffLen;
    (void)withAlg;
    (void)format;

    return NOT_COMPILED_IN;
}

int wc_AsymKey_import(AsymKey* key, const byte* data, word32 dataSz, int format) {

    // Calls the extended version with no password
    return wc_AsymKey_import_ex(key, data, dataSz, format, NULL, 0);
}

int wc_AsymKey_import_ex(AsymKey* key, const byte* data, word32 dataSz, int format, const char* passwd, int devId) {

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
  if ((ret = wc_AsymKey_PrivateKeyInfo(&algorSum, der, derSz, 0)) < 0) {
    return ret;
  }

  switch (algorSum) {
#ifndef NO_RSA
    case RSAk:
    case RSAPSSk:
        RsaKey * rsaKey = (RsaKey *)&key->val.rsaKey;
        if ((ret = wc_RsaPrivateKeyDecode(der, &idx, rsaKey, derSz)) < 0) {
            return ret;
        }
        key->type = RSA_TYPE;
        break;
#endif
#ifdef HAVE_ECC
    case ECDSAk:
        ecc_key * ecKey = (ecc_key *)&key->val.eccKey;
        wc_ecc_free(ecKey);
        wc_ecc_init_ex(ecKey, NULL, devId);

        if (wc_EccPrivateKeyDecode(der, &idx, ecKey, derSz) < 0) {
            XFREE(ecKey, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
            return ASN_PARSE_E;
        }
        if (wc_ecc_get_curve_id(ecKey->idx) < 0) {
            return BAD_STATE_E;
        }
        key->type = ECC_TYPE;
        break;
#endif
#ifdef HAVE_ED25519
    case ED25519k:
        ed25519_key * edKey = (ed25519_key *)&key->val.ed25519Key;
        
        wc_ed25519_free(edKey);
        if (wc_ed25519_init(edKey) < 0) {
            return BAD_STATE_E;
        }

        if ((ret = wc_Ed25519PrivateKeyDecode(der, &idx, edKey, derSz)) < 0) {
            return ASN_PARSE_E;
        }
        edKey->pubKeySet = 1;
        edKey->privKeySet = 1;
        key->type = ED25519_TYPE;
        break;
#endif
#ifdef HAVE_ED448
    case ED448k:
        ed448_key * ed448Key = (ed448_key *)&key->val.ed448Key;

        if ((ret = wc_Ed448PrivateKeyDecode(der, &idx, ed448Key, derSz)) < 0) {
            return ASN_PARSE_E;
        }
        ed448Key->pubKeySet = 1;
        ed448Key->privKeySet = 1;
        key->type = ED448_TYPE;
        break;
#endif
#ifdef HAVE_DILITHIUM
    case ML_DSA_LEVEL5k:
    case ML_DSA_LEVEL3k:
    case ML_DSA_LEVEL2k:
        MlDsaKey * mlDsaKey = (MlDsaKey *)&key->val.dilithiumKey;

        // Initializes the key and sets the expected level
        wc_dilithium_free(mlDsaKey);
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
        break;
#endif
#ifdef HAVE_FALCON
    case FALCON_LEVEL1k:
    case FALCON_LEVEL5k:
        falcon_key * falconKey = (falcon_key *)&key->val.falconKey;
        
        wc_falcon_free(falconKey);
        wc_falcon_init(falconKey);

        if (algorSum == FALCON_LEVEL1k) {
            wc_falcon_set_level(falconKey, 1);
            key->type = FALCON_LEVEL1_TYPE;
        } else if (algorSum == FALCON_LEVEL5k) {
            wc_falcon_set_level(falconKey, 5);
            key->type = FALCON_LEVEL5_TYPE;
        }

        if ((ret = wc_FalconPrivateKeyDecode(der, idx, falconKey, derSz)) < 0) {
            return ret;
        }
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
        mldsa_composite_key * mldsaCompKey = (mldsa_composite_key *)&key->val.mldsaCompKey;

        int level = wc_mldsa_composite_key_sum_level(algorSum);
        if (level <= 0)
            return ALGO_ID_E;

        key->type = wc_mldsa_composite_level_type(level);
        if (key->type <= 0) {
            return ALGO_ID_E;
        }

        wc_mldsa_composite_free(mldsaCompKey);
        if ((ret = wc_MlDsaComposite_PrivateKeyDecode(der, &idx, mldsaCompKey, derSz, level)) < 0) {
            return ret;
        }
        
        break;
#endif

        default:
            return BAD_FUNC_ARG;
    }

    if (der) XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return 0;
}

int wc_AsymKey_export(const AsymKey * key,
                      byte          * buff,
                      word32        * buffLen) {

    // Export the key without a password
    return wc_AsymKey_export_ex(key, buff, buffLen, NULL, 0);
}

int wc_AsymKey_export_ex(const AsymKey * key,
                         byte          * buff,
                         word32        * buffLen,
                         const byte    * passwd,
                         word32          passwdSz) {

    int ret = 0;
        // return value

    // byte * derPkcsPtr = NULL;
    // word32 derPkcsSz = 0;
        // PEM key buffer and size

    byte * derPtr = NULL;
    word32 derSz = 0;
        // DER key buffer and size

    word32 keyOid = 0;
        // Key OID (enum Key_Sum)

    if (!key) {
        return BAD_FUNC_ARG;
    }

    keyOid = ret = wc_AsymKey_Oid(key);
    if (ret < 0) {
        return BAD_FUNC_ARG;
    }

    switch (keyOid) {
#ifndef NO_RSA
        case RSAk:
        case RSAPSSk:

#if defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA) || \
    defined(WOLFSSL_KCAPI_RSA) || defined(WOLFSSL_SE050)

            const RsaKey * rsaKey = &key->val.rsaKey;
                // Shortcut to the RSA key

            derSz = ret = wc_RsaKeyToDer((RsaKey *)rsaKey, NULL, sizeof(derPtr));
            if (ret < 0) {
                return BAD_FUNC_ARG;
            }
            if (buff) {
                derPtr = (byte *)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (derPtr == NULL) {
                    XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    return MEMORY_E;
                }
                ret = wc_RsaKeyToDer((RsaKey *)rsaKey, derPtr, derSz);
                if (ret < 0) {
                    XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    return ret;
                }
            }
            // derPkcsPtr = derPtr;
            // derPkcsSz = derSz;
            
            // // ----------------------
            // // Export in PKCS8 format
            // // ----------------------

            // ret = wc_CreatePKCS8Key(NULL, &derPkcsSz, derPtr, derSz, keyOid, NULL, 0);
            // if (ret != LENGTH_ONLY_E) {
            //     MADWOLF_DEBUG("Error creating PKCS8 key (%d)\n", ret);
            //     XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            //     return BAD_STATE_E;
            // }

            // derPkcsPtr = (byte *)XMALLOC(derPkcsSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            // if (derPkcsPtr == NULL) {
            //     XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            //     return MEMORY_E;
            // }

            // if (buff) {
            //     ret = wc_CreatePKCS8Key(derPkcsPtr, &derPkcsSz, derPtr, derSz, keyOid, NULL, 0);
            //     if (ret < 0) {
            //         MADWOLF_DEBUG("Error creating PKCS8 key (%d)\n", ret);
            //         XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            //         XFREE(derPkcsPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            //         return BAD_STATE_E;
            //     }
            // }

            // // Free the DER buffer
            // XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            // derPtr = NULL;
            // derSz = 0;
#else
            return -1;
#endif // WOLFSSL_KEY_GEN || OPENSSL_EXTRA || WOLFSSL_KCAPI_RSA || WOLFSSL_SE050
            break;
#endif
#ifdef HAVE_ECC
        case ECDSAk:
            const ecc_key * eccKey = &key->val.eccKey;
                // Shortcut to the ECC key

            derSz = ret = wc_ecc_size((ecc_key *)eccKey);
            if (ret <= 0) {
                return BAD_FUNC_ARG;
            }
            // // Get the size of the DER key
            // derSz = ret = wc_EccKeyDerSize((ecc_key *)eccKey, 1);
            // if (ret < 0) {
            //     return BAD_FUNC_ARG;
            // }

            if (buff) {
                // Allocate memory for the DER key
                derPtr = (byte *)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (derPtr == NULL) {
                    return MEMORY_E;
                }

                // // Export the key to DER format
                // ret = wc_EccKeyToDer((ecc_key *)eccKey, derPtr, derSz);
                // if (ret < 0) {
                //     XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                //     return BAD_STATE_E;
                // }
                ret = wc_ecc_export_private_only((ecc_key *)eccKey, derPtr, &derSz);
                if (ret < 0) {
                    XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    return ret;
                }
            }
            // derPkcsPtr = derPtr;
            // derPkcsSz = derSz;

            // // ----------------------
            // // Export in PKCS8 format
            // // ----------------------

            // byte * curveOid = NULL;
            // word32 curveOidSz = 0;
            // if ((ret = wc_ecc_get_oid(eccKey->dp->oidSum, (const byte **)&curveOid, &curveOidSz)) < 0){
            //     XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            //     return ret;
            // }

            // ret = wc_CreatePKCS8Key(NULL, (word32 *)&derPkcsSz, derPtr, derSz, ECDSAk, curveOid, curveOidSz);
            // if (ret != LENGTH_ONLY_E) {
            //     MADWOLF_DEBUG("Error creating PKCS8 key (%d)\n", ret);
            //     XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            //     return ret;
            // }

            // derPkcsPtr = (byte *)XMALLOC(derPkcsSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            // if (derPkcsPtr == NULL) {
            //     XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            //     return MEMORY_E;
            // }

            // if (buff) {
            //     ret = wc_CreatePKCS8Key(derPkcsPtr, &derPkcsSz, derPtr, derSz, keyOid, curveOid, curveOidSz);
            //     if (ret < 0) {
            //         MADWOLF_DEBUG("Error creating PKCS8 key (%d)\n", ret);
            //         XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            //         XFREE(derPkcsPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            //         return ret;
            //     }
            // }
            // XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            // derPtr = NULL;
            // derSz = 0;

            break;
#endif
#ifdef HAVE_ED25519
        case ED25519k:
            const ed25519_key * ed25519Key = &key->val.ed25519Key;
                // Shortcut to the ED25519 key

            derSz = ret = ED25519_KEY_SIZE;

            // // Get the size of the DER key
            // derPkcsSz = ret = wc_Ed25519PrivateKeyToDer((ed25519_key *)ed25519Key, NULL, 0);
            // if (ret < 0) {
            //     return BAD_FUNC_ARG;
            // }

            // // Allocate memory for the DER key
            // derPkcsPtr = (byte *)XMALLOC(derPkcsSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            // if (derPkcsPtr == NULL) {
            //     return MEMORY_E;
            // }

            if (buff) {
                derPtr = (byte *)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (derPtr == NULL) {
                    return MEMORY_E;
                }

                // // Export the key to DER format
                // ret = wc_Ed25519PrivateKeyToDer((ed25519_key *)ed25519Key, derPkcsPtr, derPkcsSz);
                // if (ret < 0) {
                //     XFREE(derPkcsPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                //     return ret;
                // }

                ret = wc_ed25519_export_private_only((ed25519_key *)ed25519Key, derPtr, &derSz);
                if (ret < 0) {
                    MADWOLF_DEBUG("Error exporting ED25519 key (%d)\n", ret);
                    XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    return ret;
                }
                MADWOLF_DEBUG("Exported ED25519 key - derSz: %d\n", derSz);
            }

            break;
#endif
#ifdef HAVE_ED448
        case ED448k:
            const ed448_key * ed448Key = &key->val.ed448Key;
                // Shortcut to the ED448 key

            // derPkcsSz = ret = wc_Ed448PrivateKeyToDer((ed448_key *)ed448Key, NULL, 0);
            // if (ret < 0) {
            //     return BAD_FUNC_ARG;
            // }
            derSz = ED448_KEY_SIZE;

            if (buff) {
                derPtr = (byte *)XMALLOC(derSz, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
                if (derPtr == NULL) {
                    return MEMORY_E;
                }
                // derPkcsSz = ret = wc_Ed448PrivateKeyToDer((ed448_key *)ed448Key, derPkcsPtr, derPkcsSz);
                // if (ret < 0) {
                //     XFREE(derPkcsPtr, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
                //     return ret;
                // }
                ret = wc_ed448_export_private_only((ed448_key *)ed448Key, derPtr, &derSz);
                if (ret < 0) {
                    XFREE(derPtr, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
                    return ret;
                }
            }
            // No Need to convert to PKCS8
            break;
#endif
#ifdef HAVE_DILITHIUM
        case ML_DSA_LEVEL5k:
        case ML_DSA_LEVEL3k:
        case ML_DSA_LEVEL2k:
            const dilithium_key * dilithiumKey = &key->val.dilithiumKey;
                // Shortcut to the Dilithium key

            derSz = DILITHIUM_SEED_SZ;

            // if (keyOid == ML_DSA_LEVEL2k) {
            //     derSz = DILITHIUM_LEVEL2_KEY_SIZE;
            // } else if (keyOid == ML_DSA_LEVEL3k) {
            //     derSz = DILITHIUM_LEVEL3_KEY_SIZE;
            // } else if (keyOid == ML_DSA_LEVEL5k) {
            //     derSz = DILITHIUM_LEVEL5_KEY_SIZE;
            // }

            // derPkcsSz = ret = wc_Dilithium_PrivateKeyToDer((dilithium_key *)dilithiumKey, NULL, 0);
            // if (ret < 0) {
            //     return BAD_FUNC_ARG;
            // }
            
            if (buff) {
                derPtr = (byte *)XMALLOC(derSz, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
                if (derPtr == NULL) {
                    return MEMORY_E;
                }
                // derPkcsSz = ret = wc_Dilithium_PrivateKeyToDer((dilithium_key *)dilithiumKey, derPkcsPtr, derPkcsSz);
                // if (ret < 0) {
                //     XFREE(derPkcsPtr, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
                //     return ret;
                // }
                ret = wc_dilithium_export_private_only((dilithium_key *)dilithiumKey, derPtr, &derSz);
                if (ret < 0) {
                    XFREE(derPtr, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
                    return ret;
                }
            }
            break;
#endif
#ifdef HAVE_FALCON
        case FALCON_LEVEL1k:
        case FALCON_LEVEL5k:
            const falcon_key * falconKey = &key->val.falconKey;
                // Shortcut to the Falcon key

            if (keyOid == FALCON_LEVEL1k) {
                derSz = 1281;
            } else if (keyOid == FALCON_LEVEL5k) {
                derSz = 2305;
            }

            // derPkcsSz = ret = wc_Falcon_PrivateKeyToDer((falcon_key *)falconKey, NULL, 0);
            // if (ret < 0) {
            //     return BAD_FUNC_ARG;
            // }
            
            if (buff) {
                if ((derPtr = (byte *)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) {
                    return MEMORY_E;
                }
                // derPkcsSz = ret = wc_Falcon_PrivateKeyToDer((falcon_key *)falconKey, derPkcsPtr, derPkcsSz);
                ret = wc_falcon_export_private_only((falcon_key *)falconKey, derPtr, &derSz);
                if (ret < 0) {
                    XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    return ret;
                }
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
            const mldsa_composite_key * mldsaCompKey = &key->val.mldsaCompKey;
                // Shortcut to the MLDSA Composite key

            // derPkcsSz = ret = wc_MlDsaComposite_PrivateKeyToDer((mldsa_composite_key *)mldsaCompKey, NULL, 0);
            // derPkcsSz = ret = wc_mldsa_composite_priv_size((mldsa_composite_key *)mldsaCompKey);
            // derPkcsSz = ret = wc_mldsa_composite_size((mldsa_composite_key *)mldsaCompKey);

            ret = wc_mldsa_composite_export_private_only((mldsa_composite_key *)mldsaCompKey, NULL, &derSz);
            if (ret < 0) {
                return ret;
            }
            if (buff) {
                derPtr = (byte *)XMALLOC(derSz, mldsaCompKey->heap, DYNAMIC_TYPE_PRIVATE_KEY);
                if (derPtr == NULL) {
                    return MEMORY_E;
                }
                // ret = wc_MlDsaComposite_PrivateKeyToDer((mldsa_composite_key *)mldsaCompKey, derPkcsPtr, derPkcsSz);
                ret = wc_mldsa_composite_export_private_only((mldsa_composite_key *)mldsaCompKey, derPtr, &derSz);
                if (ret < 0) {
                    XFREE(derPtr, mldsaCompKey->heap, DYNAMIC_TYPE_PRIVATE_KEY);
                    return ret;
                }
            }

            // No Need to convert to PKCS8
            break;
#endif
#ifdef HAVE_SPHINCS
        case SPHINCS_FAST_LEVEL1k:
        case SPHINCS_FAST_LEVEL3k:
        case SPHINCS_FAST_LEVEL5k:
        case SPHINCS_SMALL_LEVEL1k:
        case SPHINCS_SMALL_LEVEL3k:
        case SPHINCS_SMALL_LEVEL5k:
            sphincs_key * sphincsKey = key->key.sphincs;
                // Shortcut to the SPHINCS key

            derSz = ret = wc_sphincs_export_private_only(sphincsKey, NULL, 0);
            if (ret < 0) {
                return ret;
            }
            if (buff) {
                derPtr = (byte *)XMALLOC(derSz, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
                if (derPtr == NULL) {
                    return MEMORY_E;
                }
                ret = wc_sphincs_export_private_only(sphincsKey, derPtr, derSz);
                if (ret < 0) {
                    XFREE(derPtr, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
                    return ret;
                }
            }
            break;
#endif

        default:
            MADWOLF_DEBUG("Unsupported key type (%d)\n", key->type);
            return BAD_FUNC_ARG;
    }

//     // --------------------
//     // Export to PEM format
//     // --------------------

// #ifdef WOLFSSL_DER_TO_PEM

//     if (format == 1) {
//         int pem_dataSz = 0;
//         byte * pem_data = NULL;

//         if (!derPkcsPtr && derPkcsSz) {
//             derPkcsPtr = (byte *)XMALLOC(derPkcsSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
//             if (derPkcsPtr == NULL) {
//                 return MEMORY_E;
//             }
//         }

//         pem_dataSz = ret = wc_DerToPem(derPkcsPtr, derPkcsSz, NULL, 0, PKCS8_PRIVATEKEY_TYPE);
//         if (ret <= 0) {
//             XFREE(derPkcsPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
//             return ret;
//         }

//         if (buff) {

//             pem_data = (byte *)XMALLOC(pem_dataSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
//             if (pem_data == NULL) {
//                 XFREE(derPkcsPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
//                 return MEMORY_E;
//             }
//             ret = wc_DerToPem(derPkcsPtr, derPkcsSz, pem_data, pem_dataSz, PKCS8_PRIVATEKEY_TYPE);
//             if (ret <= 0) {
//                 XFREE(derPkcsPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
//                 XFREE(pem_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
//                 return ret;
//             }
//             XFREE(derPkcsPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
//             derPkcsPtr = pem_data;
//             derPkcsSz = pem_dataSz;
//         }
//     }
// #endif

    // Sets the ouput parameter

    if (buff) {
        if (*buffLen < derSz) {
            XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return BUFFER_E;
        }
        XMEMCPY(buff, derPtr, derSz);
        ret = derSz;
    }

    *buffLen = ret = derSz;
    
    if (derPtr)
        XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    (void)passwd;
    (void)passwdSz;

    return ret;
}


int wc_AsymKey_PrivateKeyInfo(word32 * oid, byte * pkcsData, word32 pkcsDataSz, int format) {
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


int wc_AsymKey_PrivateKeyDerDecode(AsymKey* key, const byte* data, word32 dataSz) {
    
    // Calls the extended version with no password
    return wc_AsymKey_PrivateKeyDerDecode_ex(key, data, dataSz, NULL, 0, 0);
}

int wc_AsymKey_PrivateKeyDerDecode_ex(AsymKey* key, const byte* data, word32 dataSz, const byte* pwd, word32 pwdSz, int devId) {

    // byte * buff = NULL;
    // word32 buffSz = 0;

    // byte * der = NULL;
    // word32 derSz = 0;

    word32 algorSum = 0;
    word32 idx = 0;
    
    int ret = 0;

    if (!key || !data || dataSz <= 0)
        return BAD_FUNC_ARG;

    (void)pwd;
    (void)pwdSz;

//   /* Convert PEM to DER. */
//   if (format == 1 || format < 0) {

//       // Allocates memory for the buffer (to avoid changing the original key data)
//       buff = (byte *)XMALLOC(dataSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
//       buffSz = dataSz;

//       // Decodes PEM into DER
//       if ((ret = wc_KeyPemToDer(data, dataSz, buff, buffSz, passwd)) < 0) {
//         XFREE(buff, NULL, DYNAMIC_TYPE_TMP_BUFFER);
//         return ret;
//       }

//       // If the format was not explicity required, allow for the DER format
//       if (format == 1 && ret <= 0) {
//         XFREE(buff, NULL, DYNAMIC_TYPE_TMP_BUFFER);
//         return ret;
//       }

//       if (ret > 0) {
//           der = buff;
//           derSz  = buffSz;
//       } else {
//           der = (byte *)data;
//       }

//   } else {
//       der = (byte *)data;
//   }

  // Gets the key information (OID or Key_Sum)
  if ((ret = wc_AsymKey_PrivateKeyInfo(&algorSum, (byte *)data, dataSz, 0)) < 0) {
    MADWOLF_DEBUG("Error getting key information (%d)\n", ret);
    FILE * f = fopen("key.der", "wb");
    fwrite(data, 1, dataSz, f);
    fclose(f);
    return ret;
  }

  switch (algorSum) {
#ifndef NO_RSA
    case RSAk:
    case RSAPSSk:
        RsaKey * rsaKey = (RsaKey *)&key->val.rsaKey;
        if ((ret = wc_RsaPrivateKeyDecode(data, &idx, rsaKey, dataSz)) < 0) {
            return ret;
        }
        key->type = RSA_TYPE;
        break;
#endif
#ifdef HAVE_ECC
    case ECDSAk:
        ecc_key * ecKey = (ecc_key *)&key->val.eccKey;
        wc_ecc_free(ecKey);
        wc_ecc_init_ex(ecKey, NULL, devId);

        // if (wc_ecc_import_private_key(data, dataSz, NULL, 0, ecKey) < 0) {
        //     return ASN_PARSE_E;
        // }

        if (wc_EccPrivateKeyDecode(data, &idx, ecKey, dataSz) < 0) {
            return ASN_PARSE_E;
        }
        if (wc_ecc_get_curve_id(ecKey->idx) < 0) {
            return BAD_STATE_E;
        }

        // Makes the public key from the private key and saves it in the key structure,
        // when using NULL as the second parameter, the public key is saved within the
        // private key structure
        if (wc_ecc_make_pub(ecKey, NULL) < 0) {
            return BAD_STATE_E;
        }
        key->type = ECC_TYPE;
        break;
#endif
#ifdef HAVE_ED25519
    case ED25519k:
        ed25519_key * edKey = (ed25519_key *)&key->val.ed25519Key;
        
        wc_ed25519_free(edKey);
        if (wc_ed25519_init(edKey) < 0) {
            return BAD_STATE_E;
        }

        // if ((ret = wc_ed25519_import_private_key(data, dataSz, NULL, 0, edKey)) < 0) {
        //     MADWOLF_DEBUG("Error importing ED25519 private key (ret: %d, Sz: %d)\n", ret, dataSz);
        //     return ASN_PARSE_E;
        // }

        if ((ret = wc_Ed25519PrivateKeyDecode(data, &idx, edKey, dataSz)) < 0) {
            return ASN_PARSE_E;
        }
        edKey->pubKeySet = 1;
        edKey->privKeySet = 1;
        key->type = ED25519_TYPE;
        break;
#endif
#ifdef HAVE_ED448
    case ED448k:
        ed448_key * ed448Key = (ed448_key *)&key->val.ed448Key;

        if ((ret = wc_Ed448PrivateKeyDecode(data, &idx, ed448Key, dataSz)) < 0) {
            return ASN_PARSE_E;
        }
        ed448Key->pubKeySet = 1;
        ed448Key->privKeySet = 1;
        key->type = ED448_TYPE;
        break;
#endif
#ifdef HAVE_DILITHIUM
    case ML_DSA_LEVEL5k:
    case ML_DSA_LEVEL3k:
    case ML_DSA_LEVEL2k:
        MlDsaKey * mlDsaKey = (MlDsaKey *)&key->val.dilithiumKey;

        // Initializes the key and sets the expected level
        wc_dilithium_free(mlDsaKey);
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
        if ((ret = wc_Dilithium_PrivateKeyDecode(data, &idx, mlDsaKey, dataSz)) < 0) {
            return ret;
        }
        break;
#endif
#ifdef HAVE_FALCON
    case FALCON_LEVEL1k:
    case FALCON_LEVEL5k:
        falcon_key * falconKey = (falcon_key *)&key->val.falconKey;
        
        wc_falcon_free(falconKey);
        wc_falcon_init(falconKey);

        if (algorSum == FALCON_LEVEL1k) {
            wc_falcon_set_level(falconKey, 1);
            key->type = FALCON_LEVEL1_TYPE;
        } else if (algorSum == FALCON_LEVEL5k) {
            wc_falcon_set_level(falconKey, 5);
            key->type = FALCON_LEVEL5_TYPE;
        }

        if ((ret = wc_FalconPrivateKeyDecode(data, idx, falconKey, dataSz)) < 0) {
            return ret;
        }
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
        mldsa_composite_key * mldsaCompKey = (mldsa_composite_key *)&key->val.mldsaCompKey;

        int level = wc_mldsa_composite_key_sum_level(algorSum);
        if (level <= 0)
            return ALGO_ID_E;

        key->type = wc_mldsa_composite_level_type(level);
        if (key->type <= 0) {
            return ALGO_ID_E;
        }

        wc_mldsa_composite_free(mldsaCompKey);
        if ((ret = wc_MlDsaComposite_PrivateKeyDecode(data, &idx, mldsaCompKey, dataSz, level)) < 0) {
            return ret;
        }
        
        break;
#endif

        default:
            return BAD_FUNC_ARG;
    }

    return 0;
}

int wc_AsymKey_PrivateKeyToDer(const AsymKey * key,
                               byte          * buff,
                               word32        * buffLen) {

    int ret = 0;
        // return value

    if (!key)
        return BAD_FUNC_ARG;

    // Export the key without a password
    ret = wc_AsymKey_PrivateKeyToDer_ex(key, buff, buffLen, NULL, 0);

    return ret;
}

int wc_AsymKey_PrivateKeyToDer_ex(const AsymKey * key,
                                  byte          * buff,
                                  word32        * buffLen,
                                  const byte    * pwd,
                                  word32          pwdSz) {

    (void)pwd;
    (void)pwdSz;

    int ret = 0;
        // return value

    byte * derPkcsPtr = NULL;
    word32 derPkcsSz = 0;
        // PEM key buffer and size

    byte * derPtr = NULL;
    word32 derSz = 0;
        // DER key buffer and size

    word32 keyOid = 0;
        // Key OID (enum Key_Sum)

    if (!key) {
        return BAD_FUNC_ARG;
    }

    keyOid = ret = wc_AsymKey_Oid(key);
    if (ret < 0) {
        return BAD_FUNC_ARG;
    }

    derSz = *buffLen;

    // ret = wc_AsymKey_export(key, NULL, &derSz);
    // if (ret < 0)
    //     return ret;
    
    // derPtr = (byte *)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    // if (derPtr == NULL) {
    //     return MEMORY_E;
    // }

    // if (buff) {
    //     ret = wc_AsymKey_export(key, derPtr, &derSz);
    //     if (ret < 0) {
    //         XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    //         return ret;
    //     }
    // }

    // if (wc_CreatePKCS8Key(NULL, &derPkcsSz, derPtr, derSz, keyOid, NULL, 0) != LENGTH_ONLY_E) {
    //     XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    //     return BAD_STATE_E;
    // }
    
    // if (buff) {
    //     derPkcsPtr = (byte *)XMALLOC(derPkcsSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    //     if (derPkcsPtr == NULL) {
    //         XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    //         return MEMORY_E;
    //     }

    //     ret = wc_CreatePKCS8Key(derPkcsPtr, &derPkcsSz, derPtr, derSz, keyOid, NULL, 0);
    //     if (ret < 0) {
    //         MADWOLF_DEBUG("Error creating PKCS8 key (%d)\n", ret);
    //         XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    //         XFREE(derPkcsPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    //         return BAD_STATE_E;
    //     }

    //     // Free the DER buffer
    //     XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    // }

    // MADWOLF_DEBUG("Exported key - inputSz: %d, derSz: %d, derPkcsSz: %d\n", *buffLen, derSz, derPkcsSz);

    // TODO: Change the coding pattern to avoid
    //       allocating the buffer when not needed
    //       (e.g. when the buffer is not provided)


    switch (keyOid) {
#ifndef NO_RSA
        case RSAk:
        case RSAPSSk:

#if defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA) || \
    defined(WOLFSSL_KCAPI_RSA) || defined(WOLFSSL_SE050)

            const RsaKey * rsaKey = &key->val.rsaKey;
                // Shortcut to the RSA key

            derSz = ret = wc_RsaKeyToDer((RsaKey *)rsaKey, NULL, sizeof(derPtr));
            if (ret < 0) {
                return BAD_FUNC_ARG;
            }
            derPtr = (byte *)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (derPtr == NULL) {
                XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                return MEMORY_E;
            }
            if (buff) {
                ret = wc_RsaKeyToDer((RsaKey *)rsaKey, derPtr, derSz);
                if (ret < 0) {
                    XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    return ret;
                }
            }
            
            // ----------------------
            // Export in PKCS8 format
            // ----------------------

            ret = wc_CreatePKCS8Key(NULL, &derPkcsSz, derPtr, derSz, keyOid, NULL, 0);
            if (ret != LENGTH_ONLY_E) {
                MADWOLF_DEBUG("Error creating PKCS8 key (%d)\n", ret);
                XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                return BAD_STATE_E;
            }
            if (buff) {
                derPkcsPtr = (byte *)XMALLOC(derPkcsSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (derPkcsPtr == NULL) {
                    XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    return MEMORY_E;
                }

                ret = wc_CreatePKCS8Key(derPkcsPtr, &derPkcsSz, derPtr, derSz, keyOid, NULL, 0);
                if (ret < 0) {
                    MADWOLF_DEBUG("Error creating PKCS8 key (%d)\n", ret);
                    XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    XFREE(derPkcsPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    return BAD_STATE_E;
                }
                // Free the DER buffer
                XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            }
#else
            return -1;
#endif // WOLFSSL_KEY_GEN || OPENSSL_EXTRA || WOLFSSL_KCAPI_RSA || WOLFSSL_SE050
            break;
#endif
#ifdef HAVE_ECC
        case ECDSAk:
            const ecc_key * eccKey = &key->val.eccKey;
                // Shortcut to the ECC key

            // Get the size of the DER key
            derSz = ret = wc_EccKeyDerSize((ecc_key *)eccKey, 1);
            if (ret < 0) {
                return BAD_FUNC_ARG;
            }

            // Allocate memory for the DER key
            derPtr = (byte *)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (derPtr == NULL) {
                return MEMORY_E;
            }

            if (buff) {
                // Export the key to DER format
                ret = wc_EccKeyToDer((ecc_key *)eccKey, derPtr, derSz);
                if (ret < 0) {
                    XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    return BAD_STATE_E;
                }
            }

            // ----------------------
            // Export in PKCS8 format
            // ----------------------

            byte * curveOid = NULL;
            word32 curveOidSz = 0;
            if ((ret = wc_ecc_get_oid(eccKey->dp->oidSum, (const byte **)&curveOid, &curveOidSz)) < 0){
                XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                return ret;
            }

            ret = wc_CreatePKCS8Key(NULL, (word32 *)&derPkcsSz, derPtr, derSz, ECDSAk, curveOid, curveOidSz);
            if (ret != LENGTH_ONLY_E) {
                MADWOLF_DEBUG("Error creating PKCS8 key (%d)\n", ret);
                XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                return ret;
            }

            if (buff) {
                derPkcsPtr = (byte *)XMALLOC(derPkcsSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (derPkcsPtr == NULL) {
                    XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    return MEMORY_E;
                }

                ret = wc_CreatePKCS8Key(derPkcsPtr, &derPkcsSz, derPtr, derSz, keyOid, curveOid, curveOidSz);
                if (ret < 0) {
                    MADWOLF_DEBUG("Error creating PKCS8 key (%d)\n", ret);
                    XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    XFREE(derPkcsPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    return ret;
                }
                XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                derPtr = NULL;
                derSz = 0;
            }
            break;
#endif
#ifdef HAVE_ED25519
        case ED25519k:
             const ed25519_key * ed25519Key = &key->val.ed25519Key;
                // Shortcut to the ED25519 key

            // Get the size of the DER key
            derPkcsSz = ret = wc_Ed25519PrivateKeyToDer((ed25519_key *)ed25519Key, NULL, 0);
            if (ret < 0) {
                return BAD_FUNC_ARG;
            }

            if (buff) {
                // Allocate memory for the DER key
                derPkcsPtr = (byte *)XMALLOC(derPkcsSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (derPkcsPtr == NULL) {
                    return MEMORY_E;
                }

                // Export the key to DER format
                ret = wc_Ed25519PrivateKeyToDer((ed25519_key *)ed25519Key, derPkcsPtr, derPkcsSz);
                if (ret < 0) {
                    XFREE(derPkcsPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    return ret;
                }
            }

            break;
#endif
#ifdef HAVE_ED448
        case ED448k:
            const ed448_key * ed448Key = &key->val.ed448Key;
                // Shortcut to the ED448 key

            derPkcsSz = ret = wc_Ed448PrivateKeyToDer((ed448_key *)ed448Key, NULL, 0);
            if (ret < 0) {
                return BAD_FUNC_ARG;
            }
            if (buff) {
                derPkcsPtr = (byte *)XMALLOC(derPkcsSz, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
                if (derPkcsPtr == NULL) {
                    return MEMORY_E;
                }

                derPkcsSz = ret = wc_Ed448PrivateKeyToDer((ed448_key *)ed448Key, derPkcsPtr, derPkcsSz);
                if (ret < 0) {
                    XFREE(derPkcsPtr, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
                    return ret;
                }
            }
            // No Need to convert to PKCS8
            break;
#endif
#ifdef HAVE_DILITHIUM
        case ML_DSA_LEVEL5k:
        case ML_DSA_LEVEL3k:
        case ML_DSA_LEVEL2k:
            const dilithium_key * dilithiumKey = &key->val.dilithiumKey;
                // Shortcut to the Dilithium key

            derPkcsSz = ret = wc_Dilithium_PrivateKeyToDer((dilithium_key *)dilithiumKey, NULL, 0);
            if (ret < 0) {
                return BAD_FUNC_ARG;
            }
            if (buff) {
                derPkcsPtr = (byte *)XMALLOC(derPkcsSz, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
                if (derPkcsPtr == NULL) {
                    return MEMORY_E;
                }
                derPkcsSz = ret = wc_Dilithium_PrivateKeyToDer((dilithium_key *)dilithiumKey, derPkcsPtr, derPkcsSz);
                if (ret < 0) {
                    XFREE(derPkcsPtr, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
                    return ret;
                }
            }
            break;
#endif
#ifdef HAVE_FALCON
        case FALCON_LEVEL1k:
        case FALCON_LEVEL5k:
            falcon_key * falconKey = (falcon_key *)&key->val.falconKey;
                // Shortcut to the Falcon key

            derPkcsSz = ret = wc_Falcon_PrivateKeyToDer(falconKey, NULL, 0);
            if (ret < 0) {
                return BAD_FUNC_ARG;
            }
            if (buff) {
                if ((derPkcsPtr = (byte *)XMALLOC(derPkcsSz, NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) {
                    return MEMORY_E;
                }
                derPkcsSz = ret = wc_Falcon_PrivateKeyToDer(falconKey, derPkcsPtr, derPkcsSz);
                if (ret < 0) {
                    XFREE(derPkcsPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    return ret;
                }
            }
            // No Need to convert to PKCS8
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
            const mldsa_composite_key * mldsaCompKey = &key->val.mldsaCompKey;
                // Shortcut to the MLDSA Composite key

            derPkcsSz = ret = wc_MlDsaComposite_PrivateKeyToDer(mldsaCompKey, NULL, 0);
            if (ret < 0) {
                return ret;
            }
            if (buff) {
                derPkcsPtr = (byte *)XMALLOC(derPkcsSz, mldsaCompKey->heap, DYNAMIC_TYPE_PRIVATE_KEY);
                if (derPkcsPtr == NULL) {
                    return MEMORY_E;
                }
                ret = wc_MlDsaComposite_PrivateKeyToDer((mldsa_composite_key *)mldsaCompKey, derPkcsPtr, derPkcsSz);
                if (ret < 0) {
                    XFREE(derPkcsPtr, mldsaCompKey->heap, DYNAMIC_TYPE_PRIVATE_KEY);
                    return ret;
                }
            }

            // No Need to convert to PKCS8
            break;
#endif
#ifdef HAVE_SPHINCS
        case SPHINCS_FAST_LEVEL1k:
        case SPHINCS_FAST_LEVEL3k:
        case SPHINCS_FAST_LEVEL5k:
        case SPHINCS_SMALL_LEVEL1k:
        case SPHINCS_SMALL_LEVEL3k:
        case SPHINCS_SMALL_LEVEL5k:
            sphincs_key * sphincsKey = key->key.sphincs;
                // Shortcut to the SPHINCS key

            derPkcsSz = ret = wc_Sphincs_PrivateKeyToDer(sphincsKey, NULL, 0);
            if (ret < 0) {
                return ret;
            }
            if (buff) {
                derPtr = (byte *)XMALLOC(derPkcsSz, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
                if (derPtr == NULL) {
                    return MEMORY_E;
                }
                ret = wc_Sphincs_PrivateKeyToDer(sphincsKey, derPtr, derPkcsSz);
                if (ret < 0) {
                    XFREE(derPtr, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
                    return ret;
                }
            }
            derPkcsPtr = derPtr;
            break;
#endif

        default:
            MADWOLF_DEBUG("Unsupported key type (%d)\n", key->type);
            return BAD_FUNC_ARG;
    }

//     // --------------------
//     // Export to PEM format
//     // --------------------

// #ifdef WOLFSSL_DER_TO_PEM

//     if (format == 1) {
//         int pem_dataSz = 0;
//         byte * pem_data = NULL;

//         pem_dataSz = ret = wc_DerToPem(derPkcsPtr, derPkcsSz, NULL, 0, PKCS8_PRIVATEKEY_TYPE);
//         if (ret <= 0) {
//             XFREE(derPkcsPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
//             return ret;
//         }

//         if (buff) {
//             pem_data = (byte *)XMALLOC(pem_dataSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
//             if (pem_data == NULL) {
//                 XFREE(derPkcsPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
//                 return MEMORY_E;
//             }
//             ret = wc_DerToPem(derPkcsPtr, derPkcsSz, pem_data, pem_dataSz, PKCS8_PRIVATEKEY_TYPE);
//             if (ret <= 0) {
//                 XFREE(derPkcsPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
//                 XFREE(pem_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
//                 return ret;
//             }
//             XFREE(derPkcsPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
//             derPkcsPtr = pem_data;
//             derPkcsSz = pem_dataSz;
//         }
//     }
// #endif

    if (buff) {
        if (*buffLen < derPkcsSz) {
            XFREE(derPkcsPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return BUFFER_E;
        }
        XMEMCPY(buff, derPkcsPtr, derPkcsSz);
        XFREE(derPkcsPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    
    *buffLen = derPkcsSz;

    return 0;
}

int wc_AsymKey_Sign(byte* sig, word32* sigLen, const byte* msg, word32 msgLen,
                    enum wc_HashType hashType, const AsymKey* key, WC_RNG* rng) {

    return wc_AsymKey_Sign_ex(sig, sigLen, msg, msgLen, hashType, NULL, 0, key, rng);
}

int wc_AsymKey_Sign_ex(byte          * out, 
                       word32        * outLen, 
                       const byte    * in, 
                       word32          inLen,
                       enum wc_HashType hashType,
                       const byte    * context,
                       byte            contextLen,
                       const AsymKey * key,
                       WC_RNG        * rng) {

    int keyType = 0;
    int ret = 0;

    word32 sigLen = 0;

    const byte * tbsData = NULL;
    word32 tbsDataSz = 0;

    byte hash[MAX_DIGEST_SIZE];
    word32 hashLen = sizeof(hash);

    if (!outLen || !in || !key || !rng) {
        return BAD_FUNC_ARG;
    }

    // Retrieves the key type
    keyType = wc_AsymKey_Oid(key);

    // If an hashType is specified, the message is hashed before signing
    if (hashType != WC_HASH_TYPE_NONE) {

        ret = wc_Hash(hashType, in, inLen, hash, hashLen);
        if (ret != 0) {
            MADWOLF_DEBUG("Error hashing the message (%d)\n", ret);
            return ret;
        }

        // Sets the hash as the data to be signed
        tbsData = hash;
        tbsDataSz = wc_HashGetDigestSize(hashType);
    } else {
        // Sets the data to be signed
        tbsData = in;
        tbsDataSz = inLen;
    }

    switch (keyType) {
#ifndef NO_RSA
        case RSAk:
        case RSAPSSk:
            sigLen = ret = wc_RsaEncryptSize((RsaKey *)&key->val.rsaKey);
            if (out) {
                if (*outLen < (word32)ret) {
                    ret = CRYPTGEN_E;
                } else {
                    sigLen = ret = wc_RsaSSL_Sign(tbsData, tbsDataSz, out, *outLen, (RsaKey *)&key->val.rsaKey, rng);
                    if (ret < 0)
                        ret = CRYPTGEN_E;
                }
            }
            if (ret >= 0) {
                *outLen = ret;
                ret = 0;
            }
            break;
#endif
#ifdef HAVE_ECC
        case ECDSAk:
            sigLen = ret = wc_ecc_sig_size((ecc_key *)&key->val.eccKey);
            if (out) {
                if (*outLen < (word32)ret) {
                    ret = BUFFER_E;
                } else {
                    ret = wc_ecc_sign_hash(tbsData, tbsDataSz, out, &sigLen, rng, (ecc_key *)&key->val.eccKey);
                    if (ret < 0)
                        ret = CRYPTGEN_E;
                }
            }
            if (ret >= 0)
                *outLen = ret;
            break;
#endif
#ifdef HAVE_ED25519
        case ED25519k:
            sigLen = ret = wc_ed25519_sig_size((ed25519_key *)&key->val.ed25519Key);
            if (out) {
                if (*outLen < (word32)ret) {
                    ret = BUFFER_E;
                } else {
                    ret = wc_ed25519_sign_msg(tbsData, tbsDataSz, out, &sigLen, (ed25519_key *)&key->val.ed25519Key);
                }
            }
            if (ret >= 0) {
                *outLen = sigLen;
                ret = 0;
            }
            break;
#endif
#ifdef HAVE_ED448
        case ED448k:
            sigLen = ret = wc_ed448_sig_size((ed448_key *)&key->val.ed448Key);
            if (out) {
                if (*outLen < (word32)ret) {
                    ret = BUFFER_E;
                } else {
                    ret = wc_ed448_sign_msg(tbsData, tbsDataSz, out, &sigLen, (ed448_key *)&key->val.ed448Key, context, contextLen);
                }
            }
            if (ret >= 0) {
                *outLen = sigLen;
                ret = 0;
            }
            break;
#endif
#ifdef HAVE_DILITHIUM
        case ML_DSA_LEVEL5k:
        case ML_DSA_LEVEL3k:
        case ML_DSA_LEVEL2k:
            sigLen = ret = wc_dilithium_sig_size((dilithium_key *)&key->val.dilithiumKey);
            if (out) {
                if (*outLen < (word32)ret) {
                    ret = BUFFER_E;
                } else {
                    ret = wc_dilithium_sign_msg(tbsData, tbsDataSz, out, &sigLen, (dilithium_key *)&key->val.dilithiumKey, rng);
                    if (ret < 0)
                        ret = CRYPTGEN_E;
                }
            }
            if (ret >= 0) {
                *outLen = sigLen;
                ret = 0;
            }
            break;
#endif
#ifdef HAVE_FALCON
        case FALCON_LEVEL1k:
        case FALCON_LEVEL5k:
            ret = wc_falcon_sig_size(&key->val.falconKey);
            if (out) {
                if (*outLen < (word32)ret) {
                    ret = BUFFER_E;
                } else {
                    ret = wc_falcon_sign_msg(tbsData, tbsDataSz, out, &sigLen, &key->val.falconKey, rng);
                    if (ret < 0)
                        ret = CRYPTGEN_E;
                }
            }
            if (ret >= 0) {
                *outLen = sigLen;
                ret = 0;
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
            sigLen = ret = wc_mldsa_composite_sig_size(&key->val.mldsaCompKey);
            if (ret < 0)
                return ret;
            if (out) {
                ret = wc_mldsa_composite_sign_msg(tbsData, tbsDataSz, out, &sigLen, (mldsa_composite_key *)&key->val.mldsaCompKey, rng);
                if (ret < 0)
                    return ret;
            }
            break;
#endif
#ifdef HAVE_SPHINCS
        case SPHINCS_FAST_LEVEL1k:
        case SPHINCS_FAST_LEVEL3k:
        case SPHINCS_FAST_LEVEL5k:
        case SPHINCS_SMALL_LEVEL1k:
        case SPHINCS_SMALL_LEVEL3k:
        case SPHINCS_SMALL_LEVEL5k:
            ret = wc_sphincs_sign_msg(tbsData, tbsDataSz, out, &sigLen, key->key.sphincs, rng);
            break;
#endif
        default:
            ret = BAD_FUNC_ARG;
            break;
    }

    return ret;
}

int wc_AsymKey_Verify(const byte* sig, word32 sigLen,
        const byte* msg, word32 msgLen, enum wc_HashType hashType, const AsymKey* key) {

    return wc_AsymKey_Verify_ex(sig, sigLen, msg, msgLen, hashType, key, NULL, 0);
}

int wc_AsymKey_Verify_ex(const byte* sig, word32 sigLen,
        const byte* in, word32 inLen, enum wc_HashType hashType, const AsymKey* key, const byte* context, byte contextLen) {

    if (!sig || !in || !key) {
        return BAD_FUNC_ARG;
    }

    int ret = 0;
    int keyType = 0;
    int verify = 0;

    const byte* tbsData = NULL;
    word32 tbsDataSz = 0;
    byte hash[MAX_DIGEST_SIZE];
    word32 hashLen = sizeof(hash);

    // Retrieves the key type
    keyType = wc_AsymKey_Oid(key);
    if (keyType < 0) {
        return BAD_FUNC_ARG;
    }

    // If a hashType is specified, the message is hashed before verification
    if (hashType != WC_HASH_TYPE_NONE) {
        
        ret = wc_Hash(hashType, in, inLen, hash, hashLen);
        if (ret != 0) {
            MADWOLF_DEBUG("Error hashing the message (%d)\n", ret);
            return ret;
        }

        // Sets the hash as the data to be verified
        tbsData = hash;
        tbsDataSz = wc_HashGetDigestSize(hashType);
    } else {
        // Sets the data to be verified
        tbsData = in;
        tbsDataSz = inLen;
    }

    switch (keyType) {
#ifndef NO_RSA
        case RSAk:
        case RSAPSSk:
            ret = wc_RsaSSL_Verify(sig, sigLen, (byte *)tbsData, tbsDataSz, (RsaKey *)&key->val.rsaKey);
            if (ret < 0) {
                return SIG_VERIFY_E;
            }
            break;
#endif
#ifdef HAVE_ECC
        case ECDSAk:
            ret = wc_ecc_verify_hash(sig, sigLen, tbsData, tbsDataSz, &verify, (ecc_key *)&key->val.eccKey);
            if (ret == 0 && verify != 1) {
                return SIG_VERIFY_E;
            }
            break;
#endif
#ifdef HAVE_ED25519
        case ED25519k:
            ret = wc_ed25519_verify_msg(sig, sigLen, tbsData, tbsDataSz, &verify, (ed25519_key *)&key->val.ed25519Key);
            if (ret == 0 && verify != 1) {
                return SIG_VERIFY_E;
            }
            break;
#endif
#ifdef HAVE_ED448
        case ED448k:
            ret = wc_ed448_verify_msg(sig, sigLen, tbsData, tbsDataSz, &verify, (ed448_key *)&key->val.ed448Key, context, contextLen);
            if (ret == 0 && verify != 1) {
                return SIG_VERIFY_E;
            }
            break;
#endif
#ifdef HAVE_DILITHIUM
        case ML_DSA_LEVEL5k:
        case ML_DSA_LEVEL3k:
        case ML_DSA_LEVEL2k:
        case DILITHIUM_LEVEL2k:
        case DILITHIUM_LEVEL3k:
        case DILITHIUM_LEVEL5k:
            ret = wc_dilithium_verify_msg(sig, sigLen, tbsData, tbsDataSz, &verify, (dilithium_key *)&key->val.dilithiumKey);
            if (ret == 0 && verify != 1) {
                return SIG_VERIFY_E;
            }
            break;
#endif
#ifdef HAVE_FALCON
        case FALCON_LEVEL1k:
        case FALCON_LEVEL5k:
            ret = wc_falcon_verify_msg(sig, sigLen, tbsData, tbsDataSz, &verify, &key->val.falconKey);
            if (ret == 0 && verify != 1)
                return SIG_VERIFY_E;
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
            ret = wc_mldsa_composite_verify_msg(sig, sigLen, tbsData, tbsDataSz, &verify, (mldsa_composite_key *)&key->val.mldsaCompKey);
            if (ret == 0 && verify != 1) {
                return SIG_VERIFY_E;
            }
            break;
#endif
#ifdef HAVE_SPHINCS
        case SPHINCS_FAST_LEVEL1k:
        case SPHINCS_FAST_LEVEL3k:
        case SPHINCS_FAST_LEVEL5k:
        case SPHINCS_SMALL_LEVEL1k:
        case SPHINCS_SMALL_LEVEL3k:
        case SPHINCS_SMALL_LEVEL5k:
            ret = wc_sphincs_verify_msg(sig, sigLen, tbsData, tbsDataSz, &verify, &key->key.sphincs);
            if (ret == 0 && verify != 1) {
                ret = SIG_VERIFY_E;
            }
            break;
#endif
        default:
            return BAD_FUNC_ARG;
            break;
    }

    return 0;

}

int wc_AsymKey_MakeReq(const byte* der, word32 derSz, wc_509Req* req, const AsymKey* key) {

    (void)key;
    (void)req;
    (void)der;
    (void)derSz;

    // wc_MakeCertReq_ex(req, der, derSz, keyType, void * key);

    return NOT_COMPILED_IN;
}

int wc_AsymKey_MakeCert(const byte * der, word32 derLen, wc_509Cert* req, const AsymKey* key, WC_RNG* rng) {

    (void)key;
    (void)req;
    (void)der;
    (void)derLen;
    (void)rng;

    // wc_MakeCert_ex(cert, der, derSz, keyType, void * key, rng);

    return NOT_COMPILED_IN;
}

int wc_X509_Req_Sign(const byte * der, word32 derLen, wc_509Req * req, enum wc_HashType htype, const AsymKey* key, WC_RNG* rng) {

    (void)der;
    (void)derLen;
    (void)req;
    (void)htype;
    (void)key;
    (void)rng;

    return NOT_COMPILED_IN;
}

int wc_X509_Req_Sign_ex(const byte * der, word32 derLen, wc_509Req * req, enum wc_HashType htype, const byte* context, byte contextLen, const AsymKey* key, WC_RNG* rng) {

    (void)der;
    (void)derLen;
    (void)req;
    (void)htype;
    (void)context;
    (void)contextLen;
    (void)key;
    (void)rng;

    return NOT_COMPILED_IN;
}

int wc_X509_Req_Verify(const byte * der, word32 derLen) {

    (void)der;
    (void)derLen;

    return NOT_COMPILED_IN;
}

int wc_X509_Req_Verify_ex(const byte * der, word32 derLen, const byte* context, byte contextLen, const AsymKey* caKey) {

    (void)der;
    (void)derLen;
    (void)context;
    (void)contextLen;
    (void)caKey;

    return NOT_COMPILED_IN;
}

int wc_X509_Cert_Sign(const byte * der, word32 derLen, wc_509Req * req, enum wc_HashType htype, const AsymKey* caKey, WC_RNG* rng) {

    (void)der;
    (void)derLen;
    (void)req;
    (void)htype;
    (void)caKey;
    (void)rng;

    return NOT_COMPILED_IN;
}

int wc_X509_Cert_Sign_ex(const byte * der, word32 derLen, wc_509Req * req, enum wc_HashType htype, const byte* context, byte contextLen, const AsymKey* key, WC_RNG* rng) {

    (void)der;
    (void)derLen;
    (void)req;
    (void)htype;
    (void)context;
    (void)contextLen;
    (void)key;
    (void)rng;

    return NOT_COMPILED_IN;
}

int wc_X509_Cert_Verify(const byte * der, word32 derLen, const AsymKey * key) {

    (void)der;
    (void)derLen;
    (void)key;

    return NOT_COMPILED_IN;
}

int wc_X509_Cert_Verify_ex(const byte * der, word32 derLen, const byte* context, byte contextLen, const AsymKey * caKey) {

    (void)der;
    (void)derLen;
    (void)context;
    (void)contextLen;
    (void)caKey;

    return NOT_COMPILED_IN;
}
