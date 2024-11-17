/* pktool.c */

#include "pktool.h"

void usage(void) {

    printf("\n");
    printf("\n    USAGE: pktool <CMD> [ options ]\n\n");
    printf("Where <CMD> is one of the following:\n");
    printf(" genpkey .............: generate a private key\n");
    printf(" genreq ..............: generate a certificate request\n");
    printf(" gencert .............: generate a certificate\n\n");
    printf("Where [ options ] are:\n");

    printf(" -in <file> .......: input file\n");
    printf(" -out <file> ......: output file\n");
    printf(" -inform <format> .: input format (DER, PEM)\n");
    printf(" -outform <format> : output format (DER, PEM)\n");
    printf(" -algor <name> ....: use the named algorithm (e.g., rsa, ec, mldsa44, mldsa65-ed25519)\n");
    printf(" -curve <name> ....: use the named curve (e.g., nistp256, nistp384, nistp521, bpool256, bpool384, bpool512)\n");
    printf(" -bits <num> ......: number of bits in the key (RSA only)\n");

    printf(" -v ...............: verbose\n");
    printf(" -d ...............: debug\n");
    printf(" -h ...............: help\n");
    printf("\n");
}

int wc_PKCS8_info(byte * p8_data, word32 p8_dataSz, word32 * oid) {

    int ret = 0;
    word32 algorSum = 0;

    if (!p8_data || !p8_dataSz) {
        printf("Invalid input (p8: %p, sz: %d\n", p8_data, p8_dataSz);
        return BAD_FUNC_ARG;
    }

    // Creates a copy of the data
    byte * buff = XMALLOC(p8_dataSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buff == NULL) {
        printf("Memory allocation error\n");
        ret = MEMORY_E;
        goto err;
    }

    // Copies the data
    XMEMCPY(buff, p8_data, p8_dataSz);

    // Removes the PKCS8 header
    if ((ret = ToTraditional_ex(buff, p8_dataSz, &algorSum)) < 0) {
        printf("[%d] Error loading key (err: %d)\n", __LINE__, ret);
    } else {
        // Saves the result in the OID
        *oid = algorSum;
    }

err:

    // Frees the buffer
    if (buff) XFREE(buff, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

int export_key_p8(void * key, int type, const char * out_file, int format) {
    int ret = 0;
    int outSz = 0;

    FILE* file = NULL;
    
    byte * keyData = NULL;
        // pointer to the key data

    byte * derPtr = NULL;
    int    derSz = 0;
        // buffer to hold the key in DER format

    byte * pem_data = NULL;
    word32 pem_dataSz = 0;
        // size of the PEM data

    byte * p8_data = NULL;
    int    p8_outSz = 0;
        // size of the PKCS8 key

    // Input checks
    if (!key || type < 0) {
        printf("Invalid key type (key: %p, type: %d)\n", key, type);
        return -1;
    }

    switch (type) {
#ifndef NO_RSA
    case RSAk:
    case RSAPSSk:
        derSz = wc_RsaKeyToDer((RsaKey *)key, NULL, sizeof(derPtr));
        if (derSz < 0) {
            printf("Error exporting key (%d)\n", derSz);
            return -1;
        }
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

        if ((ret = wc_CreatePKCS8Key(NULL, (word32 *)&p8_outSz, derPtr, derSz, type, NULL, 0)) < 0 && ret != LENGTH_ONLY_E) {
            printf("Error creating PKCS8 key (%d)\n", ret);
            return -1;
        }

        p8_data = (byte *)XMALLOC(p8_outSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (p8_data == NULL) {
            printf("Error exporting key\n");
            return -1;
        }
        if ((ret = wc_CreatePKCS8Key(p8_data, (word32 *)&p8_outSz, derPtr, derSz, type, NULL, 0)) < 0) {
            printf("Error creating PKCS8 key (%d)\n", ret);
            return -1;
        }

        if (ret < 0) {
            printf("Error exporting key\n");
            return -1;
        }

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
        if ((ret = wc_CreatePKCS8Key(p8_data, (word32 *)&p8_outSz, derPtr, derSz, type, curveOid, curveOidSz)) < 0 && ret != LENGTH_ONLY_E) {
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
        derSz = wc_Ed25519PrivateKeyToDer((ed25519_key *)key, derPtr, derSz);
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
        derSz = wc_Ed448PrivateKeyToDer((ed448_key *)key, NULL, sizeof(derPtr));
        if (derSz < 0) {
            printf("Error exporting key\n");
            return -1;
        }
        derPtr = (byte *)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (derPtr == NULL) {
            printf("Error exporting key\n");
            return -1;
        }
        derSz = wc_Ed448PrivateKeyToDer((ed448_key *)key, derPtr, derSz);
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
        derSz = wc_Dilithium_PrivateKeyToDer((MlDsaKey *)key, NULL, sizeof(derPtr));
        // derSz = wc_Dilithium_PrivateKeyToDer((MlDsaKey *)key, NULL, sizeof(derPtr));
        if (derSz < 0) {
            printf("Error exporting key\n");
            return -1;
        }
        derPtr = (byte *)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (derPtr == NULL) {
            printf("Error exporting key\n");
            return -1;
        }
        derSz = wc_Dilithium_PrivateKeyToDer((MlDsaKey *)key, derPtr, derSz);
        // derSz = wc_Dilithium_PrivateKeyToDer((MlDsaKey *)key, derPtr, derSz);
        if (derSz < 0) {
            printf("Error exporting key\n");
            return -1;
        }
        // byte dilithium_level = 0;
        // wc_dilithium_get_level((MlDsaKey *)key, &dilithium_level);
        p8_data = derPtr;
        p8_outSz = derSz;
        break;
#endif
#ifdef HAVE_FALCON
    case FALCON_LEVEL1k:
    case FALCON_LEVEL5k:
        outSz = wc_FalconKeyToDer((falcon_key *)key, NULL, sizeof(derPtr));
        if (outSz < 0) {
            printf("Error exporting key\n");
            return -1;
        }
        derPtr = (byte *)XMALLOC(outSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (derPtr == NULL) {
            printf("Error exporting key\n");
            return -1;
        }
        derSz = wc_FalconKeyToDer((falcon_key *)key, derPtr, derSz);
        if (derSz < 0) {
            printf("Error exporting key\n");
            return -1;
        }
        p8_data = derPtr;
        p8_outSz = derSz;
        break;
#endif
#ifdef HAVE_MLDSA_COMPOSITE
    case MLDSA44_RSA2048k:
    case MLDSA44_RSAPSS2048k:
    case MLDSA44_NISTP256k:
    case MLDSA44_BPOOL256k:
    case MLDSA44_ED25519k:

    case MLDSA65_ED25519k:
    case MLDSA65_RSA3072k:
    case MLDSA65_RSAPSS3072k:
    case MLDSA65_NISTP256k:
    case MLDSA65_BPOOL256k:

    case MLDSA87_BPOOL384k:
    case MLDSA87_NISTP384k:
    case MLDSA87_ED448k:
        derSz = wc_MlDsaComposite_PrivateKeyToDer((mldsa_composite_key *)key, NULL, 0);
        if (derSz < 0) {
            printf("Error exporting key\n");
            return -1;
        }
        derPtr = (byte *)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (derPtr == NULL) {
            printf("Error exporting key\n");
            return -1;
        }
        derSz = wc_MlDsaComposite_PrivateKeyToDer((mldsa_composite_key *)key, derPtr, derSz);
        if (derSz < 0) {
            printf("Error exporting key\n");
            return -1;
        }
        p8_data = derPtr;
        p8_outSz = derSz;
        break;
#endif
        default:
            return BAD_FUNC_ARG;
    }

    keyData = p8_data;
    outSz = p8_outSz;

    // --------------------
    // Export to PEM format
    // --------------------

    if (format == 1) {
        ret = wc_DerToPem(p8_data, p8_outSz, NULL, 0, PKCS8_PRIVATEKEY_TYPE);
        if (ret <= 0) {
            printf("Key DER to PEM failed: %d\n", ret);
            return -1;
        }
        pem_dataSz = ret;
        pem_data = (byte *)XMALLOC(pem_dataSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (pem_data == NULL) {
            printf("Error exporting key\n");
            return -1;
        }
        ret = wc_DerToPem(p8_data, p8_outSz, pem_data, pem_dataSz, PKCS8_PRIVATEKEY_TYPE);
        if (ret <= 0) {
            printf("Key DER to PEM failed: %d\n", ret);
            return -1;
        }
        outSz = ret;
        keyData = pem_data;

        if (outSz <= 0) {
           printf("Error exporting key\n");
           return -1;
        }
    }

    // -------------
    // Write to file
    // -------------

    if (out_file) {
        file = fopen(out_file, "wb");
        if (file) {
            ret = (int)fwrite(keyData, 1, outSz, file);
            fclose(file);
        }
    } else {
        int fd = fileno(stdout);
        ret = write(fd, keyData, outSz);
    }

    return 0;
}

int load_key_p8(void ** key, int type, const char * key_file, int format) {

    int ret = 0;
    int keySz = 0;

    FILE * file = NULL;
    byte * keyData = NULL;
    byte * derPtr = NULL;
    // int    derSz = 0;
    byte * buff = NULL;
    int buff_sz = 0;

    word32 algorSum = 0;

    // Input checks
    if (!key) {
        printf("[%d] Missing Key Pointer, aborting.\n", __LINE__);
        return -1;
    }

    file = fopen(key_file, "rb");
    if (file == NULL) {
        printf("[%d] Error opening file\n", __LINE__);
        return -1;
    }

    fseek(file, 0, SEEK_END);
    keySz = ftell(file);

    keyData = (byte *)XMALLOC(keySz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (keyData == NULL) {
        printf("[%d] Error allocating memory for the key\n", __LINE__);
        fclose(file);
        return -1;
    }

    fseek(file, 0, SEEK_SET);
    ret = (int)fread(keyData, 1, keySz, file);
    fclose(file);

    if (ret != keySz) {
        printf("[%d] Error reading key\n", __LINE__);
        return -1;
    }

    /* Convert PEM to DER. */
    if (format == 1 || format < 0) {

        // Allocates memory for the buffer (to avoid changing the original key data)
        buff = (byte *)XMALLOC(keySz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        buff_sz = keySz;

        // Decodes PEM into DER
        ret = wc_KeyPemToDer(keyData, keySz, buff, buff_sz, NULL);

        // If the format was not explicity required, allow for the DER format
        if (format == 1 && ret <= 0) {
            printf("[%d] Error loading key (err: %d)\n", __LINE__, ret);
            return ret;
        }

        if (ret > 0) {
            derPtr = buff;
            keySz  = buff_sz;

            XFREE(keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        } else {
            derPtr = keyData;
        }

    } else {
        derPtr = keyData;
    }

    word32 idx = 0;
    char * privKey = NULL;
    word32 privKeySz = 0;

    char * pubKey = NULL;
    word32 pubKeySz = 0;

    // Retrieves the PKCS8 information
    if ((ret = wc_PKCS8_info(derPtr, keySz, &algorSum)) < 0) {
        printf("[%d] Error loading key (sz: %d, sum: %d, err: %d)\n", __LINE__, keySz, algorSum, ret);
        return -1;
    }

    switch (algorSum) {
#ifndef NO_RSA
    case RSAk:
    case RSAPSSk:
        RsaKey * rsaKey = (RsaKey *)XMALLOC(sizeof(RsaKey), NULL, DYNAMIC_TYPE_PRIVATE_KEY);
        ret = wc_RsaPrivateKeyDecode(derPtr, &idx, rsaKey, keySz);
        if (ret != 0) {
            XFREE(rsaKey, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
            printf("[%d] Error loading key\n", __LINE__);
            return -1;
        }
        *key = rsaKey;
        break;
#endif
#ifdef HAVE_ECC
    case ECDSAk:

        ecc_key * ecKey = (ecc_key *)XMALLOC(sizeof(ecc_key), NULL, DYNAMIC_TYPE_PRIVATE_KEY);
        XMEMSET(ecKey, 0, sizeof(ecc_key));

        if (wc_EccPrivateKeyDecode(derPtr, &idx, ecKey, keySz) < 0) {
            printf("[%d] Error loading key\n", __LINE__);
            return -1;
        }
        // Checks the ECDSA curve (P-256)
        if (wc_ecc_get_curve_id(ecKey->idx) < 0) {
            printf("Cannot retrieve the curve Id, aborting (%d)", ecKey->idx);
            return BAD_STATE_E;
        }

        printf("Curve ID: %d\n", ecKey->idx);

        // ret = wc_ecc_import_private_key(derPtr, keySz, (ecc_key *)ecKey, );
        // if (ret != 0) {
        //     printf("[%d] Error loading key\n", __LINE__);
        //     return -1;
        // }
        break;
#endif
#ifdef HAVE_ED25519
    case ED25519k:
        ed25519_key * edKey = (ed25519_key *)XMALLOC(sizeof(ed25519_key), NULL, DYNAMIC_TYPE_PRIVATE_KEY);
        XMEMSET(edKey, 0, sizeof(ed25519_key));

        if ((ret = wc_Ed25519PrivateKeyDecode(derPtr, &idx, edKey, keySz)) < 0) {
            printf("[%d] Error loading key\n", __LINE__);
            return -1;
        }
        break;
#endif
#ifdef HAVE_ED448
    case ED448k:
        ed448_key * ed448Key = (ed448_key *)XMALLOC(sizeof(ed448_key), NULL, DYNAMIC_TYPE_PRIVATE_KEY);
        XMEMSET(ed448Key, 0, sizeof(ed448_key));

        if ((ret = wc_Ed448PrivateKeyDecode(derPtr, &idx, ed448Key, keySz)) < 0) {
            printf("[%d] Error loading key\n", __LINE__);
            return -1;
        }
        break;
#endif
#ifdef HAVE_DILITHIUM
    case ML_DSA_LEVEL5k:
    case ML_DSA_LEVEL3k:
    case ML_DSA_LEVEL2k:
        MlDsaKey * mlDsaKey = (MlDsaKey *)XMALLOC(sizeof(MlDsaKey), NULL, DYNAMIC_TYPE_PRIVATE_KEY);
        XMEMSET(mlDsaKey, 0, sizeof(MlDsaKey));

        // Initializes the key and sets the expected level
        wc_dilithium_init(mlDsaKey);
        if (algorSum == ML_DSA_LEVEL5k) {
            wc_dilithium_set_level(mlDsaKey, 5);
        } else if (algorSum == ML_DSA_LEVEL3k) {
            wc_dilithium_set_level(mlDsaKey, 3);
        } else if (algorSum == ML_DSA_LEVEL2k) {
            wc_dilithium_set_level(mlDsaKey, 2);
        }

        // Decodes the key
        if ((ret = wc_Dilithium_PrivateKeyDecode(derPtr, &idx, mlDsaKey, keySz)) < 0) {
            return ret;
        }
        break;
#endif
// #ifdef HAVE_FALCON
//     case FALCON_LEVEL1k:
//     case FALCON_LEVEL5k:
//         falcon_key * falconKey = (falcon_key *)XMALLOC(sizeof(falcon_key), NULL, DYNAMIC_TYPE_PRIVATE_KEY);
//         XMEMSET(falconKey, 0, sizeof(falcon_key *));
//         if ((ret = wc_FalconPrivateKeyDecode(derPtr, idx, falconKey, keySz)) < 0) {
//             printf("[%d] Error loading key\n", __LINE__);
//             return -1;
//         }
//         break;
// #endif
#ifdef HAVE_MLDSA_COMPOSITE
    case MLDSA44_RSA2048k:
    case MLDSA44_RSAPSS2048k:
    case MLDSA44_NISTP256k:
    case MLDSA44_BPOOL256k:
    case MLDSA44_ED25519k:

    case MLDSA65_ED25519k:
    case MLDSA65_RSA3072k:
    case MLDSA65_RSAPSS3072k:
    case MLDSA65_NISTP256k:
    case MLDSA65_BPOOL256k:

    case MLDSA87_BPOOL384k:
    case MLDSA87_NISTP384k:
    case MLDSA87_ED448k:
        int comp_type = 0;
        mldsa_composite_key * mldsaCompKey = NULL;

        // Gets the composite type
        if (wc_mldsa_composite_keytype_to_type(algorSum, (enum mldsa_composite_type *)&comp_type) < 0) {
            return ALGO_ID_E;
        }

        // Allocates the memory for the key        
        mldsaCompKey = (mldsa_composite_key *)XMALLOC(sizeof(mldsa_composite_key), NULL, DYNAMIC_TYPE_PRIVATE_KEY);
        if (mldsaCompKey == NULL) {
            printf("[%d] Error loading key\n", __LINE__);
            return MEMORY_E;
        }
        XMEMSET(mldsaCompKey, 0, sizeof(mldsa_composite_key));

        // Decodes the key
        if ((ret = wc_mldsa_composite_import_private(derPtr, keySz, mldsaCompKey, comp_type)) < 0) {
            return ret;
        }
        // if ((ret = wc_MlDsaComposite_PrivateKeyDecode(derPtr, &idx, mldsaCompKey, keySz, comp_type)) < 0) {
        //     return ret;
        // }
        break;
#endif
        default:
            return BAD_FUNC_ARG;
    }

    if (derPtr) XFREE(derPtr, NULL, DYNAMIC_TYPE_PRIVATE_KEY);

    (void)idx;
    (void)privKey;
    (void)privKeySz;
    (void)pubKey;
    (void)pubKeySz;
    (void)type;

    return 0;
}

// static int gen_csr(const char* arg1)
// {
//     int ret;
//     int type;
// #ifdef HAVE_ECC
//     ecc_key ecKey;
// #endif
// #ifndef NO_RSA
//     RsaKey rsaKey;
// #endif
// #ifdef HAVE_ED25519
//     ed25519_key edKey;
// #endif
//     void* keyPtr = NULL;
//     WC_RNG rng;
//     Cert req;
//     byte der[LARGE_TEMP_SZ];
//     int  derSz;
// #ifdef WOLFSSL_DER_TO_PEM
//     byte pem[LARGE_TEMP_SZ];
//     int  pemSz;
//     FILE* file = NULL;
//     char outFile[255];
// #endif

//     XMEMSET(der, 0, LARGE_TEMP_SZ);
// #ifdef WOLFSSL_DER_TO_PEM
//     XMEMSET(pem, 0, LARGE_TEMP_SZ);
// #endif

//     if (XSTRNCMP(arg1, "rsa", 3) == 0)
//         type = RSA_TYPE;
//     else if (XSTRNCMP(arg1, "ecc", 3) == 0)
//         type = ECC_TYPE;
//     else if (XSTRNCMP(arg1, "ed25519", 7) == 0)
//         type = ED25519_TYPE;
//     else
//         return NOT_COMPILED_IN;

    
//     ret = wc_InitRng(&rng);
//     if (ret != 0) {
//         printf("RNG initialization failed: %d\n", ret);
//         return ret;
//     }

// #ifdef HAVE_ECC
//     if (type == ECC_TYPE) {
//         keyPtr = &ecKey;
//         ret = wc_ecc_init(&ecKey);
//     }
// #endif
// #ifndef NO_RSA
//     if (type == RSA_TYPE) {
//         keyPtr = &rsaKey;
//         ret = wc_InitRsaKey(&rsaKey, NULL);
//     }
// #endif
// #ifdef HAVE_ED25519
//     if (type == ED25519_TYPE) {
//         keyPtr = &edKey;
//         ret = wc_ed25519_init(&edKey);
//     }
// #endif
//     if (ret != 0) {
//         printf("Key initialization failed: %d\n", ret);
//         goto exit;
//     }

// #ifdef HAVE_ECC
//     if (type == ECC_TYPE)
//         ret = wc_ecc_make_key_ex(&rng, 32, &ecKey, ECC_SECP256R1);
// #endif
// #ifndef NO_RSA
//     if (type == RSA_TYPE)
//         ret = wc_MakeRsaKey(&rsaKey, 2048, WC_RSA_EXPONENT, &rng);
// #endif
// #ifdef HAVE_ED25519
//     if (type == ED25519_TYPE)
//         ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &edKey);
// #endif
//     if (ret != 0) {
//         printf("Key generation failed: %d\n", ret);
//         goto exit;
//     }

// #ifdef HAVE_ECC
//     if (type == ECC_TYPE)
//         ret = wc_EccKeyToDer(&ecKey, der, sizeof(der));
// #endif
// #ifndef NO_RSA
//     if (type == RSA_TYPE)
//         ret = wc_RsaKeyToDer(&rsaKey, der, sizeof(der));
// #endif
// #ifdef HAVE_ED25519
//     if (type == ED25519_TYPE)
//         ret = wc_Ed25519KeyToDer(&edKey, der, sizeof(der));
// #endif
//     if (ret <= 0) {
//         printf("Key To DER failed: %d\n", ret);
//         goto exit;
//     }
//     derSz = ret;

// #ifdef WOLFSSL_DER_TO_PEM
//     memset(pem, 0, sizeof(pem));
// #ifdef HAVE_ECC
//     if (type == ECC_TYPE)
//         ret = wc_DerToPem(der, derSz, pem, sizeof(pem), ECC_PRIVATEKEY_TYPE);
// #endif
// #ifndef NO_RSA
//     if (type == RSA_TYPE)
//         ret = wc_DerToPem(der, derSz, pem, sizeof(pem), PRIVATEKEY_TYPE);
// #endif
// #ifdef HAVE_ED25519
//     if (type == ED25519_TYPE)
//         ret = wc_DerToPem(der, derSz, pem, sizeof(pem), ED25519_TYPE);
// #endif
//     if (ret <= 0) {
//         printf("Key DER to PEM failed: %d\n", ret);
//         goto exit;
//     }
//     pemSz = ret;
//     printf("%s (%d)\n", pem, pemSz);

//     snprintf(outFile, sizeof(outFile), "%s-key.pem", arg1);
//     printf("Saved Key PEM to \"%s\"\n", outFile);
//     file = fopen(outFile, "wb");
//     if (file) {
//         ret = (int)fwrite(pem, 1, pemSz, file);
//         fclose(file);
//     }
// #endif /* WOLFSSL_DER_TO_PEM */

//     ret = wc_InitCert(&req);
//     if (ret != 0) {
//         printf("Init Cert failed: %d\n", ret);
//         goto exit;
//     }
//     strncpy(req.subject.country, "US", CTC_NAME_SIZE);
//     strncpy(req.subject.state, "OR", CTC_NAME_SIZE);
//     strncpy(req.subject.locality, "Portland", CTC_NAME_SIZE);
//     strncpy(req.subject.org, "wolfSSL", CTC_NAME_SIZE);
//     strncpy(req.subject.unit, "Development", CTC_NAME_SIZE);
//     strncpy(req.subject.commonName, "www.wolfssl.com", CTC_NAME_SIZE);
//     strncpy(req.subject.email, "info@wolfssl.com", CTC_NAME_SIZE);
//     req.version = 0;
//     ret = wc_MakeCertReq_ex(&req, der, sizeof(der), type, keyPtr);
//     if (ret <= 0) {
//         printf("Make Cert Req failed: %d\n", ret);
//         goto exit;
//     }
//     derSz = ret;

// #ifdef HAVE_ECC
//     if (type == ECC_TYPE)
//         req.sigType = CTC_SHA256wECDSA;
// #endif
// #ifndef NO_RSA
//     if (type == RSA_TYPE)
//         req.sigType = CTC_SHA256wRSA;
// #endif
// #ifdef HAVE_ED25519
//     if (type == ED25519_TYPE)
//         req.sigType = CTC_ED25519;
// #endif
//     ret = wc_SignCert_ex(req.bodySz, req.sigType, der, sizeof(der), type,
//         keyPtr, &rng);
//     if (ret <= 0) {
//         printf("Sign Cert failed: %d\n", ret);
//         goto exit;
//     }
//     derSz = ret;

// #ifdef WOLFSSL_DER_TO_PEM
//     memset(pem, 0, sizeof(pem));
//     ret = wc_DerToPem(der, derSz, pem, sizeof(pem), CERTREQ_TYPE);
//     if (ret <= 0) {
//         printf("CSR DER to PEM failed: %d\n", ret);
//         goto exit;
//     }
//     pemSz = ret;
//     printf("%s (%d)\n", pem, pemSz);

//     snprintf(outFile, sizeof(outFile), "%s-csr.pem", arg1);
//     printf("Saved CSR PEM to \"%s\"\n", outFile);
//     file = fopen(outFile, "wb");
//     if (file) {
//         ret = (int)fwrite(pem, 1, pemSz, file);
//         fclose(file);
//     }
// #endif

//     ret = 0; /* success */
    
// exit:
// #ifdef HAVE_ECC
//     if (type == ECC_TYPE)
//         wc_ecc_free(&ecKey);
// #endif
// #ifndef NO_RSA
//     if (type == RSA_TYPE)
//         wc_FreeRsaKey(&rsaKey);
// #endif
// #ifdef HAVE_ED25519
//     if (type == ED25519_TYPE)
//         wc_ed25519_free(&edKey);
// #endif
//     wc_FreeRng(&rng);

//     return ret;
// }

int gen_keypair(void ** key, int type, int param, const char * out_file) {

    int ret;
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

#ifdef HAVE_MLDSA_COMPOSITE
    byte der[MLDSA_COMPOSITE_MAX_PRV_KEY_SIZE];
#else
    byte der[10192]; /* 10k */
#endif
        // buffer to hold the key in DER format

    if (type < 0) {
        printf("Invalid key type (type: %d, out: %p)\n", type, out_file);
        return -1;
    } else if (!key) {
        printf("Missing function parameter (key)\n");
        return -2;
    }

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("RNG initialization failed: %d\n", ret);
        return ret;
    }

    switch (type) {
#ifdef HAVE_DSA
    case DSAk:
        keyPtr = &dsaKey;
        ret = wc_InitDsaKey(&dsaKey, NULL);
        break;
#endif
#ifndef NO_RSA
    case RSAPSSk:
    case RSAk:
        keyPtr = &rsaKey;
        ret = wc_InitRsaKey(&rsaKey, NULL);
        if (ret == 0)
            ret = wc_MakeRsaKey(&rsaKey, 2048, WC_RSA_EXPONENT, &rng);
        if (ret == 0)
            outSz = wc_RsaKeyToDer(&rsaKey, der, sizeof(der));
        if (outSz < 0)
            ret = outSz;
        break;
#endif
#ifdef HAVE_ECC
    case ECDSAk:
        keyPtr = &ecKey;
        ret = wc_ecc_init(&ecKey);
        int keySz = 32;
        if (param <= 0)
            param = ECC_SECP256R1;
        if (ret == 0) {
            if ((keySz = wc_ecc_get_curve_size_from_id(param)) < 0)
                ret = keySz;
            if (ret == 0)
                ret = wc_ecc_make_key_ex(&rng, keySz, keyPtr, param);
            if (ret == 0)
                outSz = wc_EccKeyToDer(&ecKey, der, sizeof(der));
            if (outSz < 0)
                ret = outSz;
        }
        break;
#endif
#ifdef HAVE_ED25519
    case ED25519k:
        keyPtr = &ed25519Key;
        ret = wc_ed25519_init(&ed25519Key);
        if (ret == 0)
            ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, keyPtr);
        if (ret == 0)
            outSz = wc_Ed25519KeyToDer(&ed25519Key, der, sizeof(der));
        if (outSz < 0)
            ret = outSz;
        break;
#endif
#ifdef HAVE_ED448
    case ED448k:
        keyPtr = &ed448Key;
        ret = wc_ed448_init(&ed448Key);
        if (ret == 0)
            ret = wc_ed448_make_key(&rng, ED448_KEY_SIZE, keyPtr);
        if (ret == 0)
            outSz = wc_Ed448KeyToDer(&ed448Key, der, sizeof(der));
        if (outSz < 0)
            ret = outSz;
        break;
#endif
#ifdef HAVE_DILITHIUM
    case ML_DSA_LEVEL2k:
    case ML_DSA_LEVEL3k:
    case ML_DSA_LEVEL5k:
        keyPtr = &mldsaKey;
        ret = wc_dilithium_init(&mldsaKey);
        if (ret == 0) {
            if (type == ML_DSA_LEVEL2k)
                ret = wc_dilithium_set_level(&mldsaKey, WC_ML_DSA_44);
            else if (type == ML_DSA_LEVEL3k)
                ret = wc_dilithium_set_level(&mldsaKey, WC_ML_DSA_65);
            else if (type == ML_DSA_LEVEL5k)
                ret = wc_dilithium_set_level(&mldsaKey, WC_ML_DSA_87);
            else
                ret = -1;
        }
        if (ret == 0)
            ret = wc_dilithium_make_key(&mldsaKey, &rng);
        if (ret == 0)
            outSz = wc_Dilithium_PrivateKeyToDer(&mldsaKey, der, sizeof(der));
        if (outSz < 0)
            ret = outSz;
        break;
#endif

#ifdef HAVE_MLDSA_COMPOSITE
    case MLDSA44_RSA2048k:
    case MLDSA44_RSAPSS2048k:
    case MLDSA44_NISTP256k:
    case MLDSA44_BPOOL256k:
    case MLDSA44_ED25519k:
    case MLDSA65_ED25519k:
    case MLDSA65_RSA3072k:
    case MLDSA65_RSAPSS3072k:
    case MLDSA65_NISTP256k:
    case MLDSA65_BPOOL256k:
    case MLDSA87_BPOOL384k:
    case MLDSA87_NISTP384k:
    case MLDSA87_ED448k:
        keyPtr = &mldsa_compositeKey;
        int key_type = 0;
        
        ret = wc_mldsa_composite_init(&mldsa_compositeKey);
        if ((ret = wc_mldsa_composite_keytype_to_type(type, (enum mldsa_composite_type *)&key_type)) < 0)
            return ret;
        if (ret == 0)
            ret = wc_mldsa_composite_make_key(&mldsa_compositeKey, key_type, &rng);
        if (ret == 0)
            outSz = wc_MlDsaComposite_PrivateKeyToDer(&mldsa_compositeKey, der, sizeof(der));
        if (outSz < 0)
            ret = outSz;
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

int main(int argc, char** argv) {

#if !defined(WOLFSSL_CERT_REQ) || !defined(WOLFSSL_CERT_GEN) || !defined(WOLFSSL_KEY_GEN)
    printf("Please compile wolfSSL with --enable-certreq --enable-certgen --enable-certext --enable-keygen\n");
    return 0;
#else
    enum Key_Sum keySum = ML_DSA_LEVEL2k;
    int verbose = 0;
    int debug = 0;
    
    char * out_file = NULL;
    char * in_file = NULL;

    int i = 1;
    
    int param = ECC_SECP256R1;
    int cmd = 0; /* 0 = pkey, 1 = req, 2 = cert */

    int in_format = -1; /* -1 = ANY, 0 = DER, 1 = PEM */
    int out_format = 1; /* 0 = DER, 1 = PEM */

    void * keyPtr = NULL; /* pointer to the key */
    void * altKeyPtr = NULL; /* pointer to the alt Key */

    char * key_file = NULL; /* key file */
    char * csr_file = NULL; /* csr file */
    char * cert_file = NULL; /* cert file */
    char * altkey_file = NULL; /* alt key file */
    char * ca_file = NULL; /* ca file */

    // Gets the CMD
    if (argc < 2) {
        usage();
        return 1;
    }

    if (!XSTRNCMP(argv[i], "genpkey", 4)) {
        cmd = 0;
    } else if (!XSTRNCMP(argv[i], "genreq", 3)) {
        cmd = 1;
    } else if (!XSTRNCMP(argv[i], "gencert", 4)) {
        cmd = 2;
    } else {
        usage();
        return 1;
    }

    i++;

    // Gets the parameters
    while (i < argc) {
        if (!XSTRNCMP(argv[i], "-v", 2)) {
            verbose = 1;
        } else if (!XSTRNCMP(argv[i], "-d", 2)) {
            debug = 1;
        } else if (!XSTRNCMP(argv[i], "-inform", 7)) {
            i++;
            if (!XSTRNCMP(argv[i], "DER", 3) || 
                !XSTRNCMP(argv[i], "der", 3)) {
                in_format = 0;
            } else if (!XSTRNCMP(argv[i], "PEM", 3) ||
                       !XSTRNCMP(argv[i], "pem", 3)) {
                in_format = 1;
           } else {
                printf("Invalid input format (%d)\n\n", in_format);
                usage();
                return 1;
            }
        } else if (XSTRNCMP(argv[i], "-outform", 8) == 0) {
            i++;
            if (!XSTRNCMP(argv[i], "DER", 3) || 
                !XSTRNCMP(argv[i], "der", 3)) {
                out_format = 0;
            } else if (!XSTRNCMP(argv[i], "PEM", 3) ||
                       !XSTRNCMP(argv[i], "pem", 3)) {
                out_format = 1;
            } else {
                printf("Invalid output format (%d)\n\n", out_format);
                usage();
                return 1;
            }
        } else if (XSTRNCMP(argv[i], "-h", 2) == 0) {
            usage();
            return 1;
        } else if ((XSTRNCMP(argv[i], "-algorithm", 10) == 0) ||
                   (XSTRNCMP(argv[i], "-algor", 6) == 0)) {
            i++;
            keySum = wc_KeySum_get(argv[i]);
            if ( keySum < 0) {
                printf("Invalid algorithm type\n");
                return 1;
            }
        } else if (XSTRNCMP(argv[i], "-curve", 6) == 0) {
            i++;
                   if (!XSTRNCMP(argv[i], "nistp256", 8) ||
                       !XSTRNCMP(argv[i], "NISTP256", 8)) {
                param = ECC_SECP256R1;
            } else if (!XSTRNCMP(argv[i], "nistp384", 8) ||
                       !XSTRNCMP(argv[i], "NISTP384", 8)) {
                param = ECC_SECP384R1;
            } else if (!XSTRNCMP(argv[i], "nistp521", 8) ||
                       !XSTRNCMP(argv[i], "NISTP521", 8)) {
                param = ECC_SECP521R1;
            } else if (!XSTRNCMP(argv[i], "bpool256", 8) ||
                       !XSTRNCMP(argv[i], "BPOOL256", 8)) {
                param = ECC_BRAINPOOLP256R1;
            } else if (XSTRNCMP(argv[i], "bpool384", 8) ||
                       !XSTRNCMP(argv[i], "BPOOL384", 8)) {
                param = ECC_BRAINPOOLP384R1;
            } else if (XSTRNCMP(argv[i], "bpool512", 8) ||
                       !XSTRNCMP(argv[i], "BPOOL512", 8)) {
                param = ECC_BRAINPOOLP512R1;
            } else {
                printf("Invalid curve type\n");
                return 1;
            }
        } else if (XSTRNCMP(argv[i], "-bits", 5) == 0) {
            i++;
            if ((param = atoi(argv[i])) <= 0) {
                printf("Invalid key size\n");
                return 1;
            }
            if (param < 2048) {
                printf("Invalid key size (min: 2048)\n");
                return 1;
            }

            if (param > 16384) {
                printf("Invalid key size (max: 16384)\n");
                return 1;
            }

        } else if (XSTRNCMP(argv[i], "-key", 4) == 0) {
            i++;
            if (i >= argc) {
                printf("Missing keypair filename\n\n");
                usage();
                return 1;
            }
            key_file = argv[i];
        } else if (XSTRNCMP(argv[i], "-altkey", 7) == 0) {
            i++;
            if (i >= argc) {
                printf("Missing alt keypair filename\n\n");
                usage();
                return 1;
            }
            altkey_file = argv[i];
        } else if (XSTRNCMP(argv[i], "-req", 4) == 0) {
            i++;
            if (i >= argc) {
                printf("Missing request filename\n\n");
                usage();
                return 1;
            }
            csr_file = argv[i];
        } else if (XSTRNCMP(argv[i], "-cer", 4) == 0) {
            i++;
            if (i >= argc) {
                printf("Missing certificate filename\n\n");
                usage();
                return 1;
            }
            cert_file = argv[i];
            wolfSSL_X509_load_certificate_file(cert_file, WOLFSSL_FILETYPE_PEM);
            
        } else if (XSTRNCMP(argv[i], "-ca", 3) == 0) {
            i++;
            if (i >= argc) {
                printf("Missing CA filename\n\n");
                usage();
                return 1;
            }
            ca_file = argv[i];
        } else if (XSTRNCMP(argv[i], "-in", 3) == 0) {
            i++;
            if (i >= argc) {
                printf("Missing input file\n\n");
                usage();
                return 1;
            }
            in_file = argv[i];
        } else if (XSTRNCMP(argv[i], "-out", 4) == 0) {
            i++;
            if (i >= argc) {
                printf("Missing output filename\n\n");
                usage();
                return 1;
            }
            out_file = argv[i];
        } else {
            printf("\n     ERROR: option \"%s\" was not recognized.\n\n", argv[i]);
            break;
        }
        i++;
    }

    switch (cmd) {
        // PKEY
        case 0: {
            if (gen_keypair(&keyPtr, keySum, param, out_file) < 0) {
                printf("Error generating keypair\n");
                return 1;
            }
            if (export_key_p8(keyPtr, keySum, out_file, out_format) < 0) {
                printf("Error exporting keypair\n");
                return 1;
            }
        } break;

        // Gen CSR
        case 1: {
            if (in_file == NULL && key_file == NULL) {
                printf("Missing keypair or request filename\n");
                return 1;
            } else if (key_file == NULL) {
                key_file = in_file;
            }
            if (load_key_p8(&keyPtr, keySum, key_file, in_format) < 0) {
                printf("Error loading keypair\n");
                return 1;
            }
            if (altkey_file) {
                if (load_key_p8(&altKeyPtr, keySum, altkey_file, in_format) < 0) {
                    printf("Error loading alt keypair\n");
                    return 1;
                }
            }
            return -1;
        } break;

        // Gen CERT
        case 2: {
            return -1;
        } break;

        default:
            return -1;
    }

    (void)debug;
    (void)verbose;
    (void)in_format;
    (void)ca_file;
    (void)csr_file;
    (void)argv;
    (void)argc;

#endif
}