/* asymkey.c */

#include <wolfssl/wolfcrypt/asymkey.h>

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

#define MADWOLF_DEBUG  WOLFSSL_MSG_VSNPRINTF
#define MADWOLF_DEBUG0  WOLFSSL_MSG_VSNPRINTF

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
int wc_AsymKey_MakeKey(AsymKey      ** key,
                   enum Key_Sum    Oid,
                   int             param,
                   byte          * seed,
                   word32          seedSz,
                   WC_RNG        * rng) {

    int ret = 0;
    int rngAlloc = 0;

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
                param = 3072;
                aKey.secBits = 128;
            } else if (param <= 8192) {
                aKey.secBits = 192;
                param = 8192;
            } else {
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
                goto err;
            }

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

int wc_AsymKey_GetOid(const AsymKey * key) {

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

int wc_AsymKey_GetCertType(const AsymKey* key) {

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

int wc_AsymKey_GetKeyType(const AsymKey* key) {

    int ret = 0;
    if (!key || key->type <= 0)
        return BAD_FUNC_ARG;

    switch (key->type) {

#ifdef HAVE_DSA
        case DSA_TYPE:
            ret = DSA_KEY;
            break;
#endif
#ifndef NO_RSA
        case RSA_TYPE:
            ret = RSA_KEY;
            break;
#endif
#ifdef HAVE_ECC
        case ECC_TYPE:
            ret = ECC_KEY;
            break;
#endif
#ifdef HAVE_ED25519
        case ED25519_TYPE:
            ret = ED25519_KEY;
            break;
#endif
#ifdef HAVE_ED448
        case ED448_TYPE:
            ret = ED448_KEY;
            break;
#endif
#ifdef HAVE_DILITHIUM
        case ML_DSA_LEVEL2_TYPE:
            ret = ML_DSA_LEVEL2_KEY;
            break;
        case ML_DSA_LEVEL3_TYPE:
            ret = ML_DSA_LEVEL3_KEY;
            break;
        case ML_DSA_LEVEL5_TYPE:
            ret = ML_DSA_LEVEL5_KEY;
            break;
#endif
#ifdef HAVE_FALCON
        case FALCON_LEVEL1_TYPE:
            ret = FALCON_LEVEL1_KEY;
            break;

        case FALCON_LEVEL5_TYPE:
            ret = FALCON_LEVEL5_KEY;
            break;
#endif
#ifdef HAVE_MLDSA_COMPOSITE
        case MLDSA44_RSAPSS2048_TYPE:
            ret = MLDSA44_RSAPSS2048_KEY;
            break;
        case MLDSA44_RSA2048_TYPE:
            ret = MLDSA44_RSA2048_KEY;
            break;
        case MLDSA44_NISTP256_TYPE:
            ret = MLDSA44_NISTP256_KEY;
            break;
        case MLDSA44_ED25519_TYPE:
            ret = MLDSA44_ED25519_KEY;
            break;
        case MLDSA65_ED25519_TYPE:
            ret = MLDSA65_ED25519_KEY;
            break;
        case MLDSA65_RSAPSS4096_TYPE:
            ret = MLDSA65_RSAPSS4096_KEY;
            break;
        case MLDSA65_RSA4096_TYPE:
            ret = MLDSA65_RSA4096_KEY;
            break;
        case MLDSA65_RSAPSS3072_TYPE:
            ret = MLDSA65_RSAPSS3072_KEY;
            break;
        case MLDSA65_RSA3072_TYPE:
            ret = MLDSA65_RSA3072_KEY;
            break;
        case MLDSA65_NISTP256_TYPE:
            ret = MLDSA65_NISTP256_KEY;
            break;
        case MLDSA65_BPOOL256_TYPE:
            ret = MLDSA65_BPOOL256_KEY;
            break;
        case MLDSA87_BPOOL384_TYPE:
            ret = MLDSA87_BPOOL384_KEY;
            break;
        case MLDSA87_NISTP384_TYPE:
            ret = MLDSA87_NISTP384_KEY;
            break;
        case MLDSA87_ED448_TYPE:
            ret = MLDSA87_ED448_KEY;
            break;
        // ------- Draft 2 ------
        case D2_MLDSA44_RSAPSS2048_SHA256_TYPE:
            ret = D2_MLDSA44_RSAPSS2048_KEY;
            break;
        case D2_MLDSA44_RSA2048_SHA256_TYPE:
            ret = D2_MLDSA44_RSA2048_KEY;
            break;
        case D2_MLDSA44_NISTP256_SHA256_TYPE:
            ret = D2_MLDSA44_NISTP256_KEY;
            break;
        case D2_MLDSA44_ED25519_SHA256_TYPE:
            ret = D2_MLDSA44_ED25519_KEY;
            break;
        case D2_MLDSA65_ED25519_SHA512_TYPE:
            ret = D2_MLDSA65_ED25519_KEY;
            break;
        case D2_MLDSA65_BPOOL256_SHA512_TYPE:
            ret = D2_MLDSA65_BPOOL256_KEY;
            break;
        case D2_MLDSA65_NISTP256_SHA512_TYPE:
            ret = D2_MLDSA65_NISTP256_KEY;
            break;
        case D2_MLDSA65_RSAPSS3072_SHA512_TYPE:
            ret = D2_MLDSA65_RSAPSS3072_KEY;
            break;
        case D2_MLDSA65_RSA3072_SHA512_TYPE:
            ret = D2_MLDSA65_RSA3072_KEY;
            break;
        case D2_MLDSA87_BPOOL384_SHA512_TYPE:
            ret = D2_MLDSA87_BPOOL384_KEY;
            break;
        case D2_MLDSA87_NISTP384_SHA512_TYPE:
            ret = D2_MLDSA87_NISTP384_KEY;
            break;
        case D2_MLDSA87_ED448_SHA512_TYPE:
            ret = D2_MLDSA87_ED448_KEY;
            break;
#endif
#ifdef HAVE_SPHINCS
        case SPHINCS_HARAKA_128S_ROBUST_TYPE:
            ret = SPHINCS_HARAKA_128S_ROBUST_KEY;
            break;
        case SPHINCS_HARAKA_128S_SIMPLE_TYPE:
            ret = SPHINCS_HARAKA_128S_SIMPLE_KEY;
            break;
        case SPHINCS_HARAKA_192S_ROBUST_TYPE:
            ret = SPHINCS_HARAKA_192S_ROBUST_KEY;
            break;
        case SPHINCS_HARAKA_192S_SIMPLE_TYPE:
            ret = SPHINCS_HARAKA_192S_SIMPLE_KEY;
            break;
        case SPHINCS_HARAKA_256S_ROBUST_TYPE:
            ret = SPHINCS_HARAKA_256S_ROBUST_KEY;
            break;
        case SPHINCS_HARAKA_256S_SIMPLE_TYPE:
            ret = SPHINCS_HARAKA_256S_SIMPLE_KEY;
            break;
        case SPHINCS_SHAKE_128S_ROBUST_TYPE:
            ret = SPHINCS_SHAKE_128S_ROBUST_KEY;
            break;
        case SPHINCS_SHAKE_128S_SIMPLE_TYPE:
            ret = SPHINCS_SHAKE_128S_SIMPLE_KEY;
            break;
        case SPHINCS_SHAKE_192S_ROBUST_TYPE:
            ret = SPHINCS_SHAKE_192S_ROBUST_KEY;
            break;
        case SPHINCS_SHAKE_192S_SIMPLE_TYPE:
            ret = SPHINCS_SHAKE_192S_SIMPLE_KEY;
            break;
        case SPHINCS_SHAKE_256S_ROBUST_TYPE:
            ret = SPHINCS_SHAKE_256S_ROBUST_KEY;
            break;
        case SPHINCS_SHAKE_256S_SIMPLE_TYPE:
            ret = SPHINCS_SHAKE_256S_SIMPLE_KEY;
            break;
#endif

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

int wc_AsymKey_public_import(AsymKey* key, int type, const byte* in, word32 inLen, int format) {

    (void)key;
    (void)type;
    (void)in;
    (void)inLen;
    (void)format;

    return NOT_COMPILED_IN;
}

int wc_AsymKey_public_export(byte* buff, word32 buffLen, int withSPKIAlg, int format, const AsymKey* key) {
  
    (void)key;
    (void)buff;
    (void)buffLen;
    (void)withSPKIAlg;
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

    keyOid = ret = wc_AsymKey_GetOid(key);
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

            if (buff) {
                // Allocate memory for the DER key
                derPtr = (byte *)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (derPtr == NULL) {
                    return MEMORY_E;
                }

                ret = wc_ecc_export_private_only((ecc_key *)eccKey, derPtr, &derSz);
                if (ret < 0) {
                    XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    return ret;
                }
            }
            break;
#endif
#ifdef HAVE_ED25519
        case ED25519k:
            const ed25519_key * ed25519Key = &key->val.ed25519Key;
                // Shortcut to the ED25519 key

            derSz = ret = ED25519_KEY_SIZE;

            if (buff) {
                derPtr = (byte *)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (derPtr == NULL) {
                    return MEMORY_E;
                }

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

            derSz = ED448_KEY_SIZE;

            if (buff) {
                derPtr = (byte *)XMALLOC(derSz, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
                if (derPtr == NULL) {
                    return MEMORY_E;
                }

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
            
            if (buff) {
                derPtr = (byte *)XMALLOC(derSz, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
                if (derPtr == NULL) {
                    return MEMORY_E;
                }
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

            if (buff) {
                if ((derPtr = (byte *)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) {
                    return MEMORY_E;
                }
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

            ret = wc_mldsa_composite_export_private_only((mldsa_composite_key *)mldsaCompKey, NULL, &derSz);
            if (ret < 0) {
                return ret;
            }
            if (buff) {
                derPtr = (byte *)XMALLOC(derSz, mldsaCompKey->heap, DYNAMIC_TYPE_PRIVATE_KEY);
                if (derPtr == NULL) {
                    return MEMORY_E;
                }
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


int wc_AsymKey_PrivateKeyInfo(word32 * oid, byte * data, word32 dataSz, int format) {

    int ret = 0;
    word32 algorSum = 0;

    if (!data || !dataSz) {
        return BAD_FUNC_ARG;
    }

    // Creates a copy of the data
    word32 derSz = dataSz;
    byte * der = XMALLOC(dataSz, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
    if (der == NULL) {
        ret = MEMORY_E;
    }
    /* Convert PEM to DER. */
    if (format == 1 || format < 0) {

        // Decodes PEM into DER
        if ((ret = wc_KeyPemToDer(data, dataSz, der, derSz, NULL)) < 0) {
          XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
          return ret;
        }

        // If the format was not explicity required, allow for the DER format
        if (format == 1 && ret <= 0) {
          XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
          return ret;
        }

        if (ret > 0) {
            derSz = ret;
        } else {
            // Copies the data (allows for trying with DER)
            XMEMCPY(der, data, dataSz);
        }

    } else {
        // Copies the data
        XMEMCPY(der, data, dataSz);
    }
    if (ret == 0) {

#if defined(HAVE_PKCS8) || defined(HAVE_PKCS12)

      // Removes the PKCS8 header
      ret = ToTraditional_ex(der, dataSz, &algorSum);
      *oid = algorSum;
#else
    ret = NOT_COMPILED_IN;
#endif // HAVE_PKCS8 || HAVE_PKCS12

      // Frees the buffer
      if (der) XFREE(der, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
      der = NULL;
    }

    return ret;
}


int wc_AsymKey_PrivateKeyDerDecode(AsymKey* key, const byte* data, word32 dataSz) {
    
    // Calls the extended version with no password
    return wc_AsymKey_PrivateKeyDerDecode_ex(key, data, dataSz, NULL, 0, 0);
}

int wc_AsymKey_PrivateKeyDerDecode_ex(AsymKey* key, const byte* data, word32 dataSz, const byte* pwd, word32 pwdSz, int devId) {

    word32 algorSum = 0;
    word32 idx = 0;
    
    int ret = 0;

    if (!key || !data || dataSz <= 0)
        return BAD_FUNC_ARG;

    (void)pwd;
    (void)pwdSz;

    // Gets the key information (OID or Key_Sum)
    if ((ret = wc_AsymKey_PrivateKeyInfo(&algorSum, (byte *)data, dataSz, 0)) < 0) {
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
        if (wc_ecc_init_ex(ecKey, NULL, devId) < 0) {
            return BAD_STATE_E;
        }

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
        ed25519_key * ed25519Key = (ed25519_key *)&key->val.ed25519Key;
        
        wc_ed25519_free(ed25519Key);
        if (wc_ed25519_init(ed25519Key) < 0) {
            return BAD_STATE_E;
        }
        if ((ret = wc_Ed25519PrivateKeyDecode(data, &idx, ed25519Key, dataSz)) < 0) {
            return ASN_PARSE_E;
        }
        ret = wc_ed25519_make_public(ed25519Key, ed25519Key->p, sizeof(ed25519Key->p));
        if (ret < 0) {
            return ret;
        }
        ed25519Key->pubKeySet = 1;
        ed25519Key->privKeySet = 1;
        key->type = ED25519_TYPE;
        break;
#endif
#ifdef HAVE_ED448
    case ED448k:
        ed448_key * ed448Key = (ed448_key *)&key->val.ed448Key;
        wc_ed448_free(ed448Key);
        if (wc_ed448_init(ed448Key) < 0) {
            return BAD_STATE_E;
        }
        if ((ret = wc_Ed448PrivateKeyDecode(data, &idx, ed448Key, dataSz)) < 0) {
            return ASN_PARSE_E;
        }
        ret = wc_ed448_make_public(ed448Key, ed448Key->p, sizeof(ed448Key->p));
        if (ret < 0) {
            return ret;
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
            wc_dilithium_set_level(mlDsaKey, WC_ML_DSA_87);
            key->type = ML_DSA_LEVEL5_TYPE;
        } else if (algorSum == ML_DSA_LEVEL3k) {
            wc_dilithium_set_level(mlDsaKey, WC_ML_DSA_65);
            key->type = ML_DSA_LEVEL3_TYPE;
        } else if (algorSum == ML_DSA_LEVEL2k) {
            wc_dilithium_set_level(mlDsaKey, WC_ML_DSA_44);
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

int wc_AsymKey_PrivateKeyPemDecode(AsymKey* key, const byte* data, word32 dataSz) {
    
    // Calls the extended version with no password
    return wc_AsymKey_PrivateKeyPemDecode_ex(key, data, dataSz, NULL, 0, 0);
}

int wc_AsymKey_PrivateKeyPemDecode_ex(AsymKey* key, const byte* data, word32 dataSz, const byte* pwd, word32 pwdSz, int devId) {

    byte * der = NULL;
    word32 derSz = 0;
    
    int ret = 0;

    if (!key || !data || dataSz <= 0)
        return BAD_FUNC_ARG;

    // Retrieves the size for the DER buffer
    derSz = ret = wc_KeyPemToDer(data, dataSz, NULL, derSz, (char *)pwd);
    if (ret <= 0)
        return ret;

    if (data) {
        // Allocates memory for the buffer (to avoid changing the original key data)
        der = (byte *)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (der == NULL)
            return MEMORY_E;
        
        // Decodes PEM into DER
        if ((ret = wc_KeyPemToDer(data, dataSz, der, derSz, (char *)pwd)) < 0) {
            XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return ret;
        }

        // Decode the DER encoded key
        ret = wc_AsymKey_PrivateKeyDerDecode_ex(key, der, derSz, pwd, pwdSz, devId);

        // Frees allocated memory
        XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    // Returns the result of the decoding
    return ret;
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

    keyOid = ret = wc_AsymKey_GetOid(key);
    if (ret < 0) {
        return BAD_FUNC_ARG;
    }

    derSz = *buffLen;

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
            derSz = ret = wc_EccPrivateKeyToDer((ecc_key *)eccKey, NULL, derSz);
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
                derSz = ret = wc_EccPrivateKeyToDer((ecc_key *)eccKey, derPtr, derSz);
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

int wc_AsymKey_PrivateKeyToPem(const AsymKey * key,
                               byte          * out,
                               word32        * outLen) {

    // Calls the extended version with no password
    return wc_AsymKey_PrivateKeyToPem_ex(key, out, outLen, NULL, 0);
}

int wc_AsymKey_PrivateKeyToPem_ex(const AsymKey * key,
                                  byte          * out,
                                  word32        * outLen,
                                  const byte    * pwd,
                                  word32          pwdSz) {

    (void)pwd;
    (void)pwdSz;

    int ret = 0;
        // return value

    byte * derPtr = NULL;
    word32 derSz = 0;
        // DER key buffer and size

    if (!key || !outLen) {
        return BAD_FUNC_ARG;
    }

    ret = wc_AsymKey_PrivateKeyToDer_ex(key, NULL, &derSz, pwd, pwdSz);
    if (ret < 0) {
        return ret;
    }

    derPtr = (byte *)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (derPtr == NULL) {
        return MEMORY_E;
    }

    ret = wc_AsymKey_PrivateKeyToDer_ex(key, derPtr, &derSz, pwd, pwdSz);
    if (ret < 0) {
        XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    ret = wc_DerToPemEx(derPtr, derSz, NULL, 0, NULL, PKCS8_PRIVATEKEY_TYPE);
    if (ret <= 0) {
        XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    *outLen = ret;

    if (out) {
        if (*outLen < (word32)ret) {
            XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return BUFFER_E;
        }
        ret = wc_DerToPemEx(derPtr, derSz, out, *outLen, NULL, PKCS8_PRIVATEKEY_TYPE);
        if (ret <= 0) {
            XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return ret;
        }
    }

    XFREE(derPtr, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return 0;
}

int wc_AsymKey_Decode(AsymKey ** key, const byte * keyData, word32 keySz, int format) {

    AsymKey * asymKeyPtr = NULL;
    int ret = 0;

    if (!key || !keyData || keySz <= 0) {
        return BAD_FUNC_ARG;
    }

    // Allocates memory for the key
    asymKeyPtr = wc_AsymKey_new();
    if (asymKeyPtr == NULL)
        return MEMORY_E;

    ret = wc_AsymKey_PrivateKeyPemDecode(asymKeyPtr, keyData, keySz);
    if (ret < 0 && format == 1) {
        wc_AsymKey_free(asymKeyPtr);
        XFREE(asymKeyPtr, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
        return ret;
    }
    if (ret < 0) {
        // Tries to decode the DER version first
        ret = wc_AsymKey_PrivateKeyDerDecode(asymKeyPtr, keyData, keySz);
        if (ret < 0) {
            wc_AsymKey_free(asymKeyPtr);
            XFREE(asymKeyPtr, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
            return ret;
        }
    }

    // Returns the key
    *key = asymKeyPtr;

    return 0;
}

int wc_CertReq_PemToDer(byte ** out, word32 * outSz, const byte * data, word32 dataSz, byte isReq) {

    int ret = 0;
        // Return value

    byte * der = NULL;
    word32 derSz = 0;
        // DER buffer and size
    
    int type = CERT_TYPE;
        // Certificate request type

    if (!outSz) {
        return BAD_FUNC_ARG;
    }
    if (isReq) {
        type = CERTREQ_TYPE;
    }
    // We cannot get the size from wc_CertPemToDer() because it
    // requires the DER buffer to be allocated. Instead, we use
    // the same size for the DER data, since it should only be
    // smaller than the PEM.
    derSz = dataSz;
    der = (byte *)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (der == NULL) {
        return MEMORY_E;
    }
    ret = wc_CertPemToDer(data, dataSz, der, derSz, type);
    // If we cannot parse the PEM, if it was not requested,
    // we proceed with DER.
    if (ret <= 0) {
        // Let's try to parse a cert instead
        type = CERT_TYPE;
        ret = wc_CertPemToDer(data, dataSz, der, derSz, type);
        if (ret != ASN_NO_PEM_HEADER) {
            XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return ret;
        }
        if (ret < 0) {
            XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            // Error parsing the PEM
            return ret;
        }
    }
    if (ret > 0) {
        derSz = ret;
        der = (byte *)XREALLOC(der, derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (der == NULL) {
            XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return MEMORY_E;
        }
        derSz = ret = wc_CertPemToDer(data, dataSz, der, derSz, type);
        if (ret < 0) {
            XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return ret;
        }
    } else {
        derSz = dataSz;
        der = (byte *)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (der == NULL) {
            return MEMORY_E;
        }
        XMEMCPY(der, data, dataSz);
    }

    *outSz = derSz;

    if (out == NULL) {
        *outSz = derSz;
        XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    } else if (*out == NULL) {
        *out = der;
        *outSz = derSz;
    } else {
        if (*outSz < derSz) {
            XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return BUFFER_E;
        }
        XMEMCPY(*out, der, derSz);
        *outSz = derSz;
        
        XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return ret;
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
    keyType = wc_AsymKey_GetOid(key);

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
    keyType = wc_AsymKey_GetOid(key);
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

int wc_AsymKey_GetSigType(const AsymKey* key, enum wc_HashType hashType) {

    int certType = 0;
    int ret = 0;

    if (!key) {
        return BAD_FUNC_ARG;
    }

    // Retrieves the key type
    certType = wc_AsymKey_GetCertType(key);
    if (certType < 0) {
        return BAD_FUNC_ARG;
    }

    switch (certType) {

#ifndef NO_RSA
        case RSA_TYPE:
            int keyType = wc_AsymKey_GetOid(key);
            if (keyType < 0) {
                ret = BAD_FUNC_ARG;
                break;
            }

            if (keyType == RSAPSSk) {
                ret = CTC_RSASSAPSS;
                break;
            }

            if (hashType == WC_HASH_TYPE_NONE
                || hashType == WC_HASH_TYPE_SHA256) {
                ret = CTC_SHA256wRSA;
            } else if (hashType == WC_HASH_TYPE_SHA384) {
                ret = CTC_SHA384wRSA;
            } else if (hashType == WC_HASH_TYPE_SHA512) {
                ret = CTC_SHA512wRSA;
            } else if (hashType == WC_HASH_TYPE_SHA3_256) {
                ret = CTC_SHA3_256wRSA;
            } else if (hashType == WC_HASH_TYPE_SHA3_384) {
                ret = CTC_SHA3_384wRSA;
            } else if (hashType == WC_HASH_TYPE_SHA3_512) {
                ret = CTC_SHA3_512wRSA;
            } else {
                ret = BAD_FUNC_ARG;
            }
        break;
#endif // NO_RSA

#ifdef HAVE_ECC
        case ECC_TYPE:
            if (hashType == WC_HASH_TYPE_NONE
                || hashType == WC_HASH_TYPE_SHA256) {
                ret = CTC_SHA256wECDSA;
            } else if (hashType == WC_HASH_TYPE_SHA384) {
                ret = CTC_SHA384wECDSA;
            } else if (hashType == WC_HASH_TYPE_SHA512) {
                ret = CTC_SHA512wECDSA; 
            } else if (hashType == WC_HASH_TYPE_SHA3_256) {
                ret = CTC_SHA3_256wECDSA;
            } else if (hashType == WC_HASH_TYPE_SHA3_384) {
                ret = CTC_SHA3_384wECDSA;
            } else if (hashType == WC_HASH_TYPE_SHA3_512) {
                ret = CTC_SHA3_512wECDSA;
            } else {
                ret = BAD_FUNC_ARG;
            }
        break;
#endif // HAVE_ECC

#ifdef HAVE_ED25519
        case ED25519_TYPE:
            ret = CTC_ED25519;
        break;
#endif // HAVE_ED25519

#ifdef HAVE_ED448
        case ED448_TYPE:
            ret = CTC_ED448;
        break;
#endif // HAVE_ED448

#if defined(HAVE_DILITHIUM)
        case ML_DSA_LEVEL2_TYPE:
            ret = CTC_ML_DSA_LEVEL2;
            break;

        case ML_DSA_LEVEL3_TYPE:
            ret = CTC_ML_DSA_LEVEL3;
            break;

        case ML_DSA_LEVEL5_TYPE:
            ret = CTC_ML_DSA_LEVEL5;
            break;
#endif

#ifdef HAVE_FALCON
        case FALCON_LEVEL1_TYPE:
            ret = CTC_FALCON_LEVEL1;
            break;

        case FALCON_LEVEL5_TYPE:
            ret = CTC_FALCON_LEVEL5;
            break;
#endif // HAVE_FALCON

#ifdef HAVE_SPHINCS
        case SPHINCS_HARAKA_128F_ROBUST_TYPE:
            ret = CTC_SPHINCS_HARAKA_128F_ROBUST;
            break;

        case SPHINCS_HARAKA_128S_ROBUST_TYPE:
            ret = CTC_SPHINCS_HARAKA_128S_ROBUST;
            break;

        case SPHINCS_HARAKA_192F_ROBUST_TYPE:
            ret = CTC_SPHINCS_HARAKA_192F_ROBUST;
            break;

        case SPHINCS_HARAKA_192S_ROBUST_TYPE:
            ret = CTC_SPHINCS_HARAKA_192S_ROBUST;
            break;

        case SPHINCS_HARAKA_256F_ROBUST_TYPE:
            ret = CTC_SPHINCS_HARAKA_256F_ROBUST;
            break;

        case SPHINCS_HARAKA_256S_ROBUST_TYPE:
            ret = CTC_SPHINCS_HARAKA_256S_ROBUST;
            break;
#endif
// #ifdef HAVE_MLDSA_COMPOSITE
        case MLDSA44_NISTP256_TYPE:
            ret = CTC_MLDSA44_NISTP256_SHA256;
            break;
        case MLDSA44_RSA2048_TYPE:
            ret = CTC_MLDSA44_RSA2048_SHA256;
            break;
        case MLDSA44_RSAPSS2048_TYPE:
            ret = CTC_MLDSA44_RSAPSS2048_SHA256;
            break;
        // case MLDSA44_BPOOL256_TYPE:
        //     ret = CTC_MLDSA44_BPOOL256_SHA256;
        //     break;
        case MLDSA44_ED25519_TYPE:
            ret = CTC_MLDSA44_ED25519;
            break;
        case MLDSA65_NISTP256_TYPE:
            ret = CTC_MLDSA65_NISTP256_SHA384;
            break;
        case MLDSA65_RSA3072_TYPE:
            ret = CTC_MLDSA65_RSA3072_SHA384;
            break;
        case MLDSA65_RSAPSS3072_TYPE:
            ret = CTC_MLDSA65_RSAPSS3072_SHA384;
            break;
        case MLDSA65_RSA4096_TYPE:
            ret = CTC_MLDSA65_RSA4096_SHA384;
            break;
        case MLDSA65_RSAPSS4096_TYPE:
            ret = CTC_MLDSA65_RSAPSS4096_SHA384;
            break;
        case MLDSA65_BPOOL256_TYPE:
            ret = CTC_MLDSA65_BPOOL256_SHA256;
            break;
        case MLDSA65_ED25519_TYPE:
            ret = CTC_MLDSA65_ED25519_SHA384;
            break;
        case MLDSA87_BPOOL384_TYPE:
            ret = CTC_MLDSA87_BPOOL384_SHA384;
            break;
        case MLDSA87_NISTP384_TYPE:
            ret = CTC_MLDSA87_NISTP384_SHA384;
            break;
        case MLDSA87_ED448_TYPE:
            ret = CTC_MLDSA87_ED448;
            break;
        // -------- Draft 2 -------------//
        case D2_MLDSA44_RSAPSS2048_SHA256_TYPE:
            ret = D2_CTC_MLDSA44_RSAPSS2048_SHA256;
            break;
        case D2_MLDSA44_RSA2048_SHA256_TYPE:
            ret = D2_CTC_MLDSA44_RSA2048_SHA256;
            break;
        case D2_MLDSA44_NISTP256_SHA256_TYPE:
            ret = D2_CTC_MLDSA44_NISTP256_SHA256;
            break;
        case D2_MLDSA44_ED25519_SHA256_TYPE:
            ret = D2_CTC_MLDSA44_ED25519;
            break;
        case D2_MLDSA65_RSAPSS3072_SHA512_TYPE:
            ret = D2_CTC_MLDSA65_RSAPSS3072_SHA512;
            break;
        case D2_MLDSA65_RSA3072_SHA512_TYPE:
            ret = D2_CTC_MLDSA65_RSA3072_SHA512;
            break;
        case D2_MLDSA65_NISTP256_SHA512_TYPE:
            ret = D2_CTC_MLDSA65_NISTP256_SHA512;
            break;
        case D2_MLDSA65_ED25519_SHA512_TYPE:
            ret = D2_CTC_MLDSA65_ED25519_SHA512;
            break;
        case D2_MLDSA87_BPOOL384_SHA512_TYPE:
            ret = D2_CTC_MLDSA87_BPOOL384_SHA512;
            break;
        case D2_MLDSA87_NISTP384_SHA512_TYPE:
            ret = D2_CTC_MLDSA87_NISTP384_SHA512;
            break;
        case D2_MLDSA87_ED448_SHA512_TYPE:
            ret = D2_CTC_MLDSA87_ED448_SHA512;
            break;
// #endif

        default:
            ret = BAD_FUNC_ARG;
    }

    return ret;
}

int wc_AsymKey_SignReq(byte** der, word32 *derSz, const char * subjectDN, enum wc_HashType hashType, int format, const AsymKey* key /*, const AsymKey *alt_key */) {

    int ret = 0;

    Cert req;

    WC_RNG rng;

    if (!key || !der || !derSz)
        return BAD_FUNC_ARG;

    XMEMSET(&req, 0, sizeof(Cert));

    if (wc_InitCert(&req) < 0) {
        return BAD_FUNC_ARG;
    }
    req.version = 0;
    ret = wc_CertName_set(&req.subject, subjectDN);
    if (ret != 0)
        return ret;

    if (wc_InitRng(&rng) < 0) {
        return BAD_FUNC_ARG;
    }

    return wc_AsymKey_SignReq_ex(der, derSz, &req, hashType, format, key, &rng);
}

int wc_AsymKey_CertReq_SetTemplate(Cert * tbsCert, enum wc_CertTemplate template_id) {
    
    WC_RNG rng;
    int ret = 0;

    byte * derBuf = NULL;
    byte derBufAlloc = 0;

    if (!tbsCert)
        return BAD_FUNC_ARG;

    if (wc_InitRng(&rng) < 0)
        return BAD_STATE_E;

    // Default values
    tbsCert->version   = 2;
    tbsCert->daysValid = 365;

    switch (template_id) {

        // IETF Templates (RFC 5280)
        case WC_CERT_TEMPLATE_IETF_ROOT_CA:
            tbsCert->isCA = 1;
            tbsCert->selfSigned = 1;
            tbsCert->daysValid = 4347;
            tbsCert->serialSz = 20;
            tbsCert->skidSz = 20;

            tbsCert->keyUsage = WC_KU_KEY_CERT_SIGN | WC_KU_CRL_SIGN | WC_KU_DIGITAL_SIGNATURE;
            break;

        case WC_CERT_TEMPLATE_IETF_INTERMEDIATE_CA:
            tbsCert->isCA = 1;
            tbsCert->selfSigned = 0;
            tbsCert->daysValid = 2922;
            tbsCert->serialSz = 10;
            tbsCert->skidSz = 20;
            tbsCert->akidSz = 20;

            tbsCert->keyUsage = WC_KU_KEY_CERT_SIGN | WC_KU_CRL_SIGN | WC_KU_DIGITAL_SIGNATURE;
            break;

        case WC_CERT_TEMPLATE_IETF_OCSP_SERVER:
            tbsCert->isCA = 0;
            tbsCert->daysValid = 548;
            tbsCert->keyUsage = WC_KU_DIGITAL_SIGNATURE;
            tbsCert->extKeyUsage = WC_EKU_OCSP_SIGNING;
            tbsCert->serialSz = 10;
            tbsCert->skidSz = 20;
            tbsCert->akidSz = 20;
            // OCSP NoCheck extension
            tbsCert->customCertExt[0].crit = 0;
            tbsCert->customCertExt[0].oid = wc_strdup("1.3.6.1.5.5.7.48.1.5");
            tbsCert->customCertExt[0].val = NULL;
            tbsCert->customCertExt[0].valSz = 0;
            tbsCert->customCertExtCount = 1;
            break;

        case WC_CERT_TEMPLATE_IETF_CODE_SIGNING:
            tbsCert->isCA = 0;
            tbsCert->daysValid = 548;
            tbsCert->keyUsage = WC_KU_DIGITAL_SIGNATURE;
            tbsCert->extKeyUsage = WC_EKU_CODE_SIGNING;
            tbsCert->serialSz = 10;
            tbsCert->skidSz = 20;
            tbsCert->akidSz = 20;
            break;

        case WC_CERT_TEMPLATE_IETF_TIME_STAMPING:
            tbsCert->isCA = 0;
            tbsCert->daysValid = 548;
            tbsCert->keyUsage = WC_KU_DIGITAL_SIGNATURE;
            tbsCert->extKeyUsage = WC_EKU_TIME_STAMPING;
            tbsCert->serialSz = 10;
            tbsCert->skidSz = 20;
            tbsCert->akidSz = 20;
            break;

        case WC_CERT_TEMPLATE_IETF_TLS_SERVER:
            tbsCert->isCA = 0;
            tbsCert->daysValid = 548;
            tbsCert->keyUsage = WC_KU_DIGITAL_SIGNATURE;
            tbsCert->extKeyUsage = WC_EKU_SERVER_AUTH | WC_EKU_CLIENT_AUTH;
            tbsCert->serialSz = 10;
            tbsCert->skidSz = 20;
            tbsCert->akidSz = 20;
            break;

        case WC_CERT_TEMPLATE_IETF_TLS_CLIENT:
            tbsCert->isCA = 0;
            tbsCert->daysValid = 548;
            tbsCert->keyUsage = WC_KU_DIGITAL_SIGNATURE;
            tbsCert->extKeyUsage = WC_EKU_CLIENT_AUTH;
            tbsCert->serialSz = 10;
            tbsCert->skidSz = 20;
            tbsCert->akidSz = 20;
            break;

        case WC_CERT_TEMPLATE_IETF_EMAIL:
            tbsCert->isCA = 0;
            tbsCert->daysValid = 548;
            tbsCert->keyUsage = WC_KU_DIGITAL_SIGNATURE;
            tbsCert->extKeyUsage = WC_EKU_EMAIL | WC_EKU_CLIENT_AUTH;
            tbsCert->serialSz = 10;
            tbsCert->skidSz = 20;
            tbsCert->akidSz = 20;
            break;

        case WC_CERT_TEMPLATE_IETF_802_1X:
            tbsCert->isCA = 0;
            tbsCert->daysValid = 548;
            tbsCert->keyUsage = WC_KU_DIGITAL_SIGNATURE;
            tbsCert->extKeyUsage = WC_EKU_CLIENT_AUTH | WC_EKU_SERVER_AUTH;
            tbsCert->serialSz = 10;
            tbsCert->skidSz = 20;
            tbsCert->akidSz = 20;
            break;

        case WC_CERT_TEMPLATE_IETF_IPSEC:
            tbsCert->isCA = 0;
            tbsCert->daysValid = 548;
            tbsCert->keyUsage = WC_KU_DIGITAL_SIGNATURE;
            tbsCert->extKeyUsage = WC_EKU_CLIENT_AUTH | WC_EKU_SERVER_AUTH;
            tbsCert->serialSz = 10;
            tbsCert->skidSz = 20;
            tbsCert->akidSz = 20;
            break;

        // X9.68 Templates
        case WC_CERT_TEMPLATE_X9_RFC5280_ROOT_CA:
        case WC_CERT_TEMPLATE_X9_INTERMEDIATE_CA:
        case WC_CERT_TEMPLATE_X9_OCSP_SERVER:
        case WC_CERT_TEMPLATE_X9_CODE_SIGNING:
        case WC_CERT_TEMPLATE_X9_TIME_STAMPING:
        case WC_CERT_TEMPLATE_X9_TLS_SERVER:
        case WC_CERT_TEMPLATE_X9_TLS_CLIENT:
        case WC_CERT_TEMPLATE_X9_EMAIL:
        case WC_CERT_TEMPLATE_X9_802_1X:
        case WC_CERT_TEMPLATE_X9_IPSEC:

        case WC_CERT_TEMPLATE_UNKNOWN:
            default:
                ret = BAD_FUNC_ARG;
                goto err;
    }

    // Serial Number
    if (tbsCert->serialSz > 0)
        wc_RNG_GenerateBlock(&rng, tbsCert->serial, tbsCert->serialSz);

err:

    if (derBufAlloc) {
        XFREE(derBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return ret;
}

int wc_AsymKey_CertReq_SetSigtype(Cert * tbsCert, enum wc_HashType hashType, const AsymKey* caKey) {

    int ret = 0;

    if (!tbsCert || !caKey)
        return BAD_FUNC_ARG;

    ret = wc_AsymKey_GetSigType(caKey, hashType);
    if (ret < 0) 
        return ret;

    tbsCert->sigType = ret;

    return 0;
}

int wc_AsymKey_CertReq_SetSerial(Cert * tbsCert, const byte * serial, word32 serialSz) {

    int ret = 0;
    RNG rng;

    if (!tbsCert)
        ret = BAD_FUNC_ARG;

    if (ret == 0) {
        if (serialSz <= 0)
            serialSz = tbsCert->serialSz;
        if (serialSz <= 0 || serialSz > sizeof(tbsCert->serial))
            serialSz = sizeof(tbsCert->serial);
    }
    if (ret == 0) {
        if (serial) {
            XMEMCPY(tbsCert->serial, serial, serialSz);
            tbsCert->serialSz = serialSz;
        } else {
            if (wc_InitRng(&rng) < 0)
                ret = BAD_STATE_E;
            
            tbsCert->serialSz = serialSz;
            wc_RNG_GenerateBlock(&rng, tbsCert->serial, tbsCert->serialSz);
        }
    }

    return ret;
}

int wc_AsymKey_CertReq_SetSubject(Cert * tbsCert, const char * subjectStr) {
    
    int ret = 0;

    if (!tbsCert) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0 && subjectStr)
        ret = wc_CertName_set(&tbsCert->subject, subjectStr);

    return ret;
}

int wc_AsymKey_CertReq_SetIssuer(Cert * tbsCert, const char * issuerStr) {

    int ret = 0;

    if (!tbsCert) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0 && issuerStr)
        ret = wc_CertName_set(&tbsCert->issuer, issuerStr);

    return ret;
}

int wc_AsymKey_CertReq_SetIssuer_CaCert(Cert * tbsCert, const byte * der, word32 derSz) {

    int ret = 0;
    if (!tbsCert || !der || derSz <= 0) {
        printf("Error: %s: %d\n", __FILE__, __LINE__);
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ret = wc_SetIssuerBuffer(tbsCert, der, derSz);
    }

    return ret;
}

int wc_AsymKey_CertReq_GetPublicKey(AsymKey * aKey, byte *reqData, word32 reqDataSz) {

    int ret = 0;
    word32 idx = 0;

    byte *derReq = NULL;
    word32 derReqSz = 0;
        // Internal buffer for the DER data

    DecodedCert decReq;
        // Decoded Request structure

    // Convert the request data from PEM to DER, if needed
    if (!reqData || reqDataSz <= 0)
        return BAD_FUNC_ARG;

    derReqSz = reqDataSz;
    derReq = (byte *)XMALLOC(derReqSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (derReq == NULL) {
        return MEMORY_E;
    }
    derReqSz = ret = wc_CertPemToDer(reqData, reqDataSz, derReq, derReqSz, CERTREQ_TYPE);
    if (ret < 0 && ret != ASN_NO_PEM_HEADER) {
        XFREE(derReq, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }
    if (ret > 0) {
        derReq = (byte *)XREALLOC(derReq, derReqSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (derReq == NULL) {
            return MEMORY_E;
        }
        ret = wc_CertPemToDer(reqData, reqDataSz, derReq, derReqSz, CERTREQ_TYPE);
        if (ret < 0) {
            XFREE(derReq, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return ASN_PARSE_E;
        }
        derReqSz = ret;
    } else {
        XMEMCPY(derReq, reqData, reqDataSz);
        derReqSz = reqDataSz;
    }

    // Loads the CSR
    InitDecodedCert(&decReq, derReq, reqDataSz, NULL);
    ret = ParseCert(&decReq, CERTREQ_TYPE, NO_VERIFY, NULL);
    if (ret != 0)
        return ret;

    switch (decReq.keyOID) {
#ifndef NO_RSA
        case RSAPSSk:
        case RSAk:
            idx = 0;
            ret = wc_RsaPublicKeyDecode(decReq.publicKey, &idx, &aKey->val.rsaKey, decReq.pubKeySize);
            if (ret != 0) {
                MADWOLF_DEBUG("Error decoding RSA public key (%d)\n", ret);
                return ret;
            }
            aKey->type = RSA_TYPE;
            break;
#endif
#ifdef HAVE_ECC
        case ECDSAk:
            ret = wc_EccPublicKeyDecode(decReq.publicKey, &idx, &aKey->val.eccKey, decReq.pubKeySize);
            if (ret != 0)
                return ret;
            aKey->type = ECC_TYPE;
            break;
#endif
#ifdef HAVE_ED25519
        case ED25519k:
            ret = wc_ed25519_import_public(decReq.publicKey, decReq.pubKeySize, &aKey->val.ed25519Key);
            if (ret != 0)
                return ret;
            aKey->type = ED25519_TYPE;
            break;
#endif
#ifdef HAVE_ED448
        case ED448k:
            ret = wc_ed448_import_public(decReq.publicKey, decReq.pubKeySize, &aKey->val.ed448Key);
            if (ret != 0)
                return ret;
            aKey->type = ED448_TYPE;
            break;
#endif
#ifdef HAVE_DILITHIUM
        case ML_DSA_LEVEL2k:
        case ML_DSA_LEVEL3k:
        case ML_DSA_LEVEL5k:
            if (decReq.keyOID == ML_DSA_LEVEL2k) {
                aKey->type = ML_DSA_LEVEL2_TYPE;
                wc_dilithium_set_level(&aKey->val.dilithiumKey, WC_ML_DSA_44);
            } else if (decReq.keyOID == ML_DSA_LEVEL3k) {
                aKey->type = ML_DSA_LEVEL3_TYPE;
                wc_dilithium_set_level(&aKey->val.dilithiumKey, WC_ML_DSA_65);
            } else if (decReq.keyOID == ML_DSA_LEVEL5k) {
                aKey->type = ML_DSA_LEVEL5_TYPE;
                wc_dilithium_set_level(&aKey->val.dilithiumKey, WC_ML_DSA_87);
            }
            ret = wc_dilithium_import_public(decReq.publicKey, decReq.pubKeySize, &aKey->val.dilithiumKey);
            if (ret != 0)
                return ret;
            break;
#endif
#ifdef HAVE_FALCON
        case FALCON_LEVEL1k:
        case FALCON_LEVEL5k:
            if (decReq.keyOID == FALCON_LEVEL1k) {
                aKey->type = FALCON_LEVEL1_TYPE;
                wc_falcon_set_level(&aKey->val.falconKey, 1);
            } else if (decReq.keyOID == FALCON_LEVEL5k) {
                aKey->type = FALCON_LEVEL5_TYPE;
                wc_falcon_set_level(&aKey->val.falconKey, 5);
            }
            ret = wc_falcon_import_public(decReq.publicKey, decReq.pubKeySize, &aKey->val.falconKey);
            if (ret != 0)
                return ret;
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
            int level = wc_mldsa_composite_key_sum_level(decReq.keyOID);
            if (level < 0)
                return BAD_FUNC_ARG;

            ret = wc_MlDsaComposite_PublicKeyDecode(decReq.publicKey, &idx, &aKey->val.mldsaCompKey, decReq.pubKeySize, level);
            if (ret != 0)
                return ret;

            aKey->type = wc_mldsa_composite_level_type(level);
            if (aKey->type < 0)
                return BAD_FUNC_ARG;

            break;
#endif
#ifdef HAVE_SPHINCS
        case SPHINCS_FAST_LEVEL1k:
        case SPHINCS_FAST_LEVEL3k:
        case SPHINCS_FAST_LEVEL5k:
        case SPHINCS_SMALL_LEVEL1k:
        case SPHINCS_SMALL_LEVEL3k:
        case SPHINCS_SMALL_LEVEL5k:
            ret = wc_sphincs_import_public(decReq.publicKey, decReq.pubKeySize, &aKey->val.sphincsKey);
            if (ret != 0)
                return ret;

            if (decReq.keyOID == SPHINCS_FAST_LEVEL1k) {
                aKey->type = SPHINCS_FAST_LEVEL1_TYPE;
            } else if (decReq.keyOID == SPHINCS_FAST_LEVEL3k) {
                aKey->type = SPHINCS_FAST_LEVEL3_TYPE;
            } else if (decReq.keyOID == SPHINCS_FAST_LEVEL5k) {
                aKey->type = SPHINCS_FAST_LEVEL5_TYPE;
            } else if (decReq.keyOID == SPHINCS_SMALL_LEVEL1k) {
                aKey->type = SPHINCS_SMALL_LEVEL1_TYPE;
            } else if (decReq.keyOID == SPHINCS_SMALL_LEVEL3k) {
                aKey->type = SPHINCS_SMALL_LEVEL3_TYPE;
            } else if (decReq.keyOID == SPHINCS_SMALL_LEVEL5k) {
                aKey->type = SPHINCS_SMALL_LEVEL5_TYPE;
            }
            break;
#endif
        default:
            return BAD_FUNC_ARG;
            break;
    }

    return ret;
}

int wc_AsymKey_SignReq_ex(byte** der, word32 *derSz, Cert* req, enum wc_HashType hashType, int format, const AsymKey* key, WC_RNG* rng) {

    int ret = 0;
    int certType = 0;

    byte* tbsReq = NULL;
    word32 tbsReqSz = WC_CTC_MAX_ALT_SIZE;

    if (!req || !key || !rng || !der || !derSz)
        return BAD_FUNC_ARG;

    // Retrieves the key type
    certType = wc_AsymKey_GetCertType(key);
    if (certType < 0)
        return BAD_FUNC_ARG;

    req->sigType = ret = wc_AsymKey_GetSigType(key, hashType);
    if (ret < 0)
        return req->sigType;

    tbsReq = (byte *)XMALLOC(WC_CTC_MAX_ALT_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (tbsReq == NULL)
        return MEMORY_E;

    // int keyType = wc_AsymKey_GetKeyType(key);
    ret = wc_SetSubjectKeyIdFromPublicKey_ex(req, key->type, (void *)&key->val);
    if (ret != 0) {
        XFREE(tbsReq, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    ret = wc_MakeCertReq_ex(req, tbsReq, WC_CTC_MAX_ALT_SIZE, certType, (void *)&key->val);
    if (ret <= 0) {
        XFREE(tbsReq, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    tbsReqSz = ret = wc_SignCert_ex(req->bodySz, req->sigType, 
                        tbsReq, WC_CTC_MAX_ALT_SIZE, certType,
                        (void *)&key->val, rng);
    if (ret <= 0) {
        XFREE(tbsReq, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    if (format != 0) {
#ifdef WOLFSSL_DER_TO_PEM
        byte * pem_data = NULL;
        int pem_dataSz = 0;

        pem_dataSz = ret = wc_DerToPem(tbsReq, tbsReqSz, NULL, pem_dataSz, CERTREQ_TYPE);
        if (ret <= 0) {
            XFREE(tbsReq, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return ret;
        }

        if (der) {
            pem_data = (byte *)XMALLOC(pem_dataSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (pem_data == NULL) {
                XFREE(tbsReq, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                return MEMORY_E;
            }
            ret = wc_DerToPem(tbsReq, tbsReqSz, pem_data, pem_dataSz, CERTREQ_TYPE);
            if (ret <= 0) {
                XFREE(tbsReq, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                XFREE(pem_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                return ret;
            }

            XFREE(tbsReq, NULL, DYNAMIC_TYPE_TMP_BUFFER);

            tbsReq = pem_data;
            tbsReqSz = pem_dataSz;
        }
#endif
    }

    if (der && *der) {
        if (tbsReqSz > *derSz) {
            XFREE(tbsReq, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return BUFFER_E;
        }
        XMEMCPY(der, tbsReq, tbsReqSz);
        XFREE(tbsReq, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    } else if (der) {
        *der = tbsReq;
    } else {
        XFREE(tbsReq, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    *derSz = tbsReqSz;

    return ret;
}

int wc_AsymKey_SignCert(byte * out, word32 outSz, int outform, 
                        Cert* tbsCert, const AsymKey * req_pub_key,
                        enum wc_HashType hashType, const AsymKey* priv_key,
                        WC_RNG* rng) {

    return wc_AsymKey_SignCert_ex(out, outSz, outform, NULL, 0, tbsCert, req_pub_key, hashType, priv_key, NULL, rng);

}

int wc_AsymKey_SignCert_ex(byte * out, word32 outSz, int outform, 
                           byte * caCert, word32 caCertSz, Cert* tbsCert,  
                           const AsymKey * reqPubKey, enum wc_HashType hashType,
                           const AsymKey * caKey, const AsymKey * caAltKey,
                           WC_RNG* rng) {

    int ret = 0;
    int certType = 0;
    
    void * pubKeyPtr = NULL;

    byte *cert = NULL;
    word32 certSz = 0;
        // DER encoded certificate

    byte *derCa = NULL;
    word32 derCaSz = 0;
        // DER encoded certificate

    byte * pem_data = NULL;
    int pem_dataSz = 0;

    (void)caAltKey;
    (void)hashType;
    (void)outform;

    if (!caKey || !rng || 
            (out && outSz <= 0) || (caCert && caCertSz <= 0)) {
        return BAD_FUNC_ARG;
    }

    if (caCert) {
        derCaSz = caCertSz;
        derCa = (byte *)XMALLOC(derCaSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (derCa == NULL) {
            goto exit;
        }
        derCaSz = ret = wc_CertPemToDer(caCert, caCertSz, derCa, derCaSz, CERT_TYPE);
        // If we cannot parse the PEM, if it was not requested,
        // we proceed with DER.
        if (ret < 0 && ret != ASN_NO_PEM_HEADER) {
            XFREE(derCa, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return ret;
        }
        if (ret > 0) {
            derCa = (byte *)XREALLOC(derCa, derCaSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (derCa == NULL) {
                return MEMORY_E;
            }
            ret = wc_CertPemToDer(caCert, caCertSz, derCa, derCaSz, CERT_TYPE);
            if (ret < 0) {
                XFREE(derCa, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                goto exit;
            }
            derCaSz = ret;
        } else {
            XMEMCPY(derCa, caCert, caCertSz);
            derCaSz = caCertSz;
        }
    }

    // Sets the static parts of the DN
    ret = wc_AsymKey_CertReq_SetSigtype(tbsCert, hashType, caKey);
    if (ret < 0) {
        printf("Error retrieving the signature type: %d\n", ret);
        goto exit;
    }

    // Sets the key type
    if (reqPubKey) {
        certType = wc_AsymKey_GetCertType(reqPubKey);
        tbsCert->keyType = wc_AsymKey_GetKeyType(reqPubKey);
        pubKeyPtr = (void *)&reqPubKey->val;
        tbsCert->selfSigned = 0;

    } else if (caKey) {
        certType = wc_AsymKey_GetCertType(caKey);
        tbsCert->keyType = wc_AsymKey_GetKeyType(caKey);
        pubKeyPtr = (void *)&caKey->val;
        tbsCert->selfSigned = 1;
    } else {
        ret = BAD_FUNC_ARG;
        goto exit;
    }

    if (tbsCert->skidSz > 0) {
        ret = wc_SetSubjectKeyIdFromPublicKey_ex(tbsCert, certType, pubKeyPtr);
        if (ret != 0) {
            printf("Error setting the Subject Key ID: %d\n", ret);
            goto exit;
        }
    }

    int authKeyType = wc_AsymKey_GetCertType(caKey);
    if (caKey && tbsCert->akidSz > 0) {
        ret = wc_SetAuthKeyIdFromPublicKey_ex(tbsCert, 
                                              authKeyType,
                                              (void *)&caKey->val);
        if (ret != 0) {
            printf("Error setting the Authority Key ID: %d\n", ret);
            goto exit;
        }
    }

    // Generates the DER certificate (unsigned)
    certSz = ret = wc_MakeCert_ex(tbsCert, NULL, certSz, certType, pubKeyPtr, rng);
    if (ret <= 0) {
        printf("Make Cert failed: %d\n", ret);
        goto exit;
    }
    ret = wc_AsymKey_sig_size(caKey);
    if (ret < 0)
        goto exit;
    
    // Adds the missing size for the signature
    certSz += ret + MAX_SEQ_SZ * 3;

    // Allocates the needed size
    cert = (byte *)XMALLOC(certSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (cert == NULL) {
        printf("Memory Error exporting key\n");
        goto exit;
    }

    if (out) {
        // Signs the tbsCert
        ret = wc_MakeCert_ex(tbsCert, cert, certSz, certType, pubKeyPtr, rng);
        if (ret <= 0) {
            printf("Make Cert failed: %d\n", ret);
            goto exit;
        }

        // Signs the certificate
        ret = wc_InitRng(rng);
        if (ret != 0) {
            goto exit;
        }
        certType = wc_AsymKey_GetCertType(caKey);
        ret = wc_SignCert_ex(tbsCert->bodySz, tbsCert->sigType, 
                            cert, certSz, certType,
                            (void *)&caKey->val, rng);
        if (ret <= 0) {
            printf("Sign Cert failed: %d\n", ret);
            goto exit;
        }
        certSz = ret;
    }

#ifdef WOLFSSL_DER_TO_PEM

    if (outform == 1) {
        pem_dataSz = ret = wc_DerToPem(cert, certSz, NULL, pem_dataSz, CERT_TYPE);
        if (ret <= 0) {
            printf("Cannot get the size of the PEM...: %d\n", ret);
            goto exit;
        }
        if (!out)
            goto exit;
        
        pem_data = (byte *)XMALLOC(pem_dataSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (pem_data == NULL) {
            printf("Memory Error exporting key\n");
            goto exit;
        }
        ret = wc_DerToPem(cert, certSz, pem_data, pem_dataSz, CERT_TYPE);
        if (ret <= 0) {
            printf("CSR DER to PEM failed: %d\n", ret);
            goto exit;
        }
        certSz = ret;
    }

    if (out) {
        if (certSz > outSz) {
            ret = BUFFER_E;
            goto exit;
        }
        XMEMCPY(out, pem_data, certSz);
    }

    goto exit;

#endif

    ret = 0; /* success */

exit:

    if (derCa)
        XFREE(derCa, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (pem_data)
        XFREE(pem_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (cert)
        XFREE(cert, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

int wc_AsymKey_SignCertTemplate(byte * out, word32 outSz, int outform, byte * reqData, word32 reqDataSz, byte * ca, word32 caSz,
                        enum wc_CertTemplate templateId, const char * subjectOverride, enum wc_HashType hashType, const AsymKey* priv_key,
                        WC_RNG* rng) {
    
    int ret = 0;

    AsymKey pub_key;
        // Public key of the certificate request

    byte *derReq = NULL;
    word32 derReqSz = 0;
        // DER encoded certificate

    Cert myCert;
        // Certificate to be signed

    DecodedCert myReqD;
        // Decoded Request structure

    // Initializes the certificate template
    wc_InitCert(&myCert);

    if (reqData) {

        derReqSz = reqDataSz;
        derReq = (byte *)XMALLOC(derReqSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (derReq == NULL) {
            return MEMORY_E;
        }
        derReqSz = ret = wc_CertPemToDer(reqData, reqDataSz, derReq, derReqSz, CERTREQ_TYPE);
        if (ret < 0 && ret != ASN_NO_PEM_HEADER) {
            XFREE(derReq, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return ret;
        }
        if (ret > 0) {
            derReq = (byte *)XREALLOC(derReq, derReqSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (derReq == NULL) {
                return MEMORY_E;
            }
            ret = wc_CertPemToDer(reqData, reqDataSz, derReq, derReqSz, CERTREQ_TYPE);
            if (ret < 0) {
                XFREE(derReq, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                return ASN_PARSE_E;
            }
            derReqSz = ret;
        } else {
            XMEMCPY(derReq, reqData, reqDataSz);
            derReqSz = reqDataSz;
        }

        ret = wc_AsymKey_CertReq_GetPublicKey(&pub_key, derReq, derReqSz);
        if (ret != 0) {
            XFREE(derReq, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return ret;
        }

        InitDecodedCert(&myReqD, derReq, derReqSz, NULL);
        ret = ParseCert(&myReqD, CERTREQ_TYPE, NO_VERIFY, NULL);
        if (ret != 0) {
            FreeDecodedCert(&myReqD);
            XFREE(derReq, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return ret;
        }

        // Calculates the Subject KeyId with SHA1 (RFC 5280)
        myCert.skidSz = SHA_DIGEST_SIZE;
        ret = CalcHashId_ex(myReqD.publicKey, myReqD.pubKeySize,
            myCert.skid, WC_HASH_TYPE_SHA);
        FreeDecodedCert(&myReqD);
        if (ret != 0) {
            XFREE(derReq, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return ret;
        }
    }

    // Sets the initial values for the certificate
    if (templateId > 0)
        ret = wc_AsymKey_CertReq_SetTemplate(&myCert, templateId);

    // Sets the subjectDN
    if (subjectOverride)
        ret = wc_AsymKey_CertReq_SetSubject(&myCert, subjectOverride);
    else if (derReq)
        ret = wc_SetSubjectBuffer(&myCert, derReq, derReqSz);
    if (ret != 0) {
        MADWOLF_DEBUG("Error setting the subject: %d (req: %d)\n", ret, derReq != NULL);
        XFREE(derReq, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }
    
    // Generates the Certificate
    if (derReq) {
        ret = wc_AsymKey_SignCert_ex(out, outSz, outform, 
                                     ca, caSz, &myCert, &pub_key,
                                     hashType, priv_key, NULL, rng);
    } else {
        ret = wc_AsymKey_SignCert_ex(out, outSz, outform, 
                                     ca, caSz, &myCert, NULL,
                                     hashType, priv_key, NULL, rng);
    }

    // Free the public key
    wc_AsymKey_free(&pub_key);

    // If needed, free allocated memory
    if (derReq)
        XFREE(derReq, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    // All done
    return ret;
}
                        

int wc_X509_Req_Sign(byte * der, word32 derLen, Cert * req, enum wc_HashType htype, const AsymKey* key, WC_RNG* rng) {

    (void)der;
    (void)derLen;
    (void)req;
    (void)htype;
    (void)key;
    (void)rng;

    return NOT_COMPILED_IN;
}

int wc_X509_Req_Sign_ex(byte * der, word32 derLen, Cert * req, enum wc_HashType htype, const byte* context, byte contextLen, const AsymKey* key, WC_RNG* rng) {

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

int wc_X509_Cert_Sign(byte * der, word32 derLen, Cert * req, enum wc_HashType htype, const AsymKey* caKey, WC_RNG* rng) {

    (void)der;
    (void)derLen;
    (void)req;
    (void)htype;
    (void)caKey;
    (void)rng;

    return NOT_COMPILED_IN;
}

int wc_X509_Cert_Sign_ex(byte * der, word32 derLen, Cert * req, enum wc_HashType htype, const byte* context, byte contextLen, const AsymKey* key, WC_RNG* rng) {

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
