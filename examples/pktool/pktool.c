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

int export_key_p8(AsymKey * key, const char * out_file, int format) {
    int ret = 0;

    FILE* file = NULL;
    
    word32 buffSz = 0;
    byte * buff = NULL;
        // buffer to hold the exported key

    (void)format;

    ret = wc_AsymKey_PrivateKeyToDer(key, NULL, &buffSz);
    if (ret < 0) {
        printf("Error exporting key %d\n", ret);
        return ret;
    }

    buff = (byte *)XMALLOC(buffSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buff == NULL) {
        printf("Error allocating memory for the key\n");
        return -1;
    }

    ret = wc_AsymKey_PrivateKeyToDer(key, buff, &buffSz);
    if (ret < 0) {
        printf("Error exporting key %d\n", ret);
        return ret;
    }

    // -------------
    // Write to file
    // -------------

    if (out_file) {
        file = fopen(out_file, "wb");
        if (file) {
            ret = (int)fwrite(buff, 1, buffSz, file);
            fclose(file);
        }
    } else {
        int fd = fileno(stdout);
        ret = write(fd, buff, buffSz);
    }

    return 0;
}

int load_key_p8(AsymKey ** key, int type, const char * key_file, int format) {

    int ret = 0;
    int keySz = 0;

    byte * keyData = NULL;

    word32 idx = 0;
    char * privKey = NULL;
    word32 privKeySz = 0;

    char * pubKey = NULL;
    word32 pubKeySz = 0;

    AsymKey * asymKeyPtr = NULL;

    (void)format;
    
    // Input checks
    if (!key) {
        printf("[%d] Missing Key Pointer, aborting.\n", __LINE__);
        return -1;
    }

    if (load_file(&keyData, &keySz, key_file) < 0) {
        printf("Cannot open the key file (%s)\n", key_file);
        fflush(stdout);
        return -1;
    }

    printf("******** Loaded File: %s, %d ******** \n", key_file, keySz);

    // word32 algorSum = 0;
    // ret = wc_AsymKey_info(&algorSum, keyData, keySz, format);
    // if (ret < 0) {
    //     printf("[%d] Error Retrieving AsymKey Information (sz: %d, sum: %d, err: %d)\n", __LINE__, keySz, algorSum, ret);
    //     return -1;
    // }

    // Allocates memory for the key
    asymKeyPtr = wc_AsymKey_new();
    if (asymKeyPtr == NULL) {
        printf("[%d] Error allocating memory for the key\n", __LINE__);
        XFREE(keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return -1;
    }

    // ret = wc_AsymKey_import(asymKeyPtr, keyData, keySz, format);
    ret = wc_AsymKey_PrivateKeyDerDecode(asymKeyPtr, keyData, keySz);
    if (ret != 0) {
        printf("[%d] Error parsing the key data (err: %d)\n", __LINE__, ret);
        wc_AsymKey_free(asymKeyPtr);
        XFREE(asymKeyPtr, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
        XFREE(keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    if (keyData) XFREE(keyData, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
    *key = asymKeyPtr;

    (void)idx;
    (void)privKey;
    (void)privKeySz;
    (void)pubKey;
    (void)pubKeySz;
    (void)type;

    return 0;
}

int load_file(byte ** data, int *len, const char * filename) {

    int ret = 0;
    int alloc = 0;
    size_t fileSz = 0;
    FILE * file = NULL;

    if (!filename || len == NULL) {
        return -1;
    }

    file = fopen(filename, "rb");
    if (file == NULL) {
        return -1;
    }

    fseek(file, 0, SEEK_END);
    fileSz = ftell(file);
    if (fileSz <= 0) {
        return -1;
    }

    if (data && *data == NULL) {
        // allocates the buffer, if needed
        if ((*data = (byte *)XMALLOC(fileSz, NULL, DYNAMIC_TYPE_TMP_BUFFER)) == NULL) {
            printf("ERROR: Memory allocation\n");
            fclose(file);
            return -1;
        }
        if (*data == NULL) {
            XFREE(*data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            fclose(file);
            return -1;
        }
        alloc = 1;
    }

    // If data was provided, let's check the size
    if (data && *data && !alloc) {
        // Checks the input size
        if (*len < (int)fileSz) {
            return -1;
        }
    }
    *len = fileSz;

    if (data && *data) {
        // Reads the file and closes it
        fseek(file, 0, SEEK_SET);
        if (fread(*data, 1, fileSz, file) != fileSz) {
            if (alloc) XFREE(*data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            *len = -1;
            return -1;
        }
    }
    fclose(file);

    return ret;
}

int gen_csr(const AsymKey * keyPair, const AsymKey * altkey, const char * out_filename, int out_format)
{
    int ret = NOT_COMPILED_IN;
#ifdef WOLFSSL_CERT_REQ
    int certType = MLDSA44_NISTP256_TYPE; // MLDSA87_ED448_TYPE
    // void* keyPtr = NULL;
    WC_RNG rng;
    Cert req;
    byte der[12240];
    int  derSz = 12240;
#ifdef WOLFSSL_DER_TO_PEM
    // byte pem[12240];
    // int  pemSz = 12240;
    FILE* file = NULL;
    // char outFile[255];
#endif

    XMEMSET(der, 0, 12240);
#ifdef WOLFSSL_DER_TO_PEM
    // XMEMSET(pem, 0, 12240);
#endif

    enum Key_Sum keySum;

    if (!keyPair) {
        printf("Invalid key\n");
        return BAD_FUNC_ARG;
    }

    printf("AsymKey PubSz: %d, Size: %d\n", wc_AsymKey_pub_size(keyPair), wc_AsymKey_size(keyPair));

    wc_InitRng(&rng);
    ret = wc_AsymKey_Sign_ex(NULL, (word32 *)&derSz, (const byte *)"1234567890", 10, WC_HASH_TYPE_SHA256, NULL, 0, keyPair, &rng);
    printf("AsymKey Sign: derSz = %d, ret = %d\n", derSz, ret);
    ret = wc_AsymKey_Sign_ex(der, (word32 *)&derSz, (const byte *)"1234567890", 10, WC_HASH_TYPE_SHA256, NULL, 0, keyPair, &rng);
    if (ret != 0) {
        printf("Error signing data: %d, derSz = %d\n", ret, derSz);
        return ret;
    }

    ret = wc_AsymKey_Verify_ex(der, derSz, (const byte *)"1234567890", 10, WC_HASH_TYPE_SHA256, keyPair, NULL, 0);
    if (ret != 0) {
        printf("Error verifying data: %d\n", ret);
        return ret;
    }

    derSz = 12240;

    printf("**** Initializing CertReq ****\n");
    
    ret = wc_InitCert(&req);
    if (ret != 0) {
        printf("Init Cert failed: %d\n", ret);
        goto exit;
    }

    // Extracts the type of key
    keySum = wc_AsymKey_Oid(keyPair);
    certType = wc_AsymKey_CertType(keyPair);

    const char * algName = (char *)wc_KeySum_name(keySum);
    if (algName == NULL) {
        printf("Cannot Retreieve Alg Name for key type: %d\n", keySum);
        algName = "Unknown";
    }

    // strncpy(req.subject.country, "US", CTC_NAME_SIZE);
    // // strncpy(req.subject.state, "OR", CTC_NAME_SIZE);
    // // strncpy(req.subject.locality, "Portland", CTC_NAME_SIZE);
    // strncpy(req.subject.org, "wolfSSL", CTC_NAME_SIZE);
    // strncpy(req.subject.unit, "Test", CTC_NAME_SIZE);
    // strncpy(req.subject.commonName, algName, CTC_NAME_SIZE);
    // strncpy(req.subject.email, "info@wolfssl.com", CTC_NAME_SIZE);

    // Sets Request Version
    req.version = 0;

    if (wc_CertName_set(&req.subject, "C=US, O=wolfSSL, OU=Test, CN=Test") < 0) {
        printf("Error parsing subject\n");
        goto exit;
    }

    ret = wc_MakeCertReq_ex(&req, der, sizeof(der), certType, (void *)&keyPair->val);
    if (ret <= 0) {
        printf("Make Cert Req failed: %d\n", ret);
        goto exit;
    }
    derSz = ret;

#ifdef HAVE_ECC
    if (certType == ECC_TYPE)
        req.sigType = CTC_SHA256wECDSA;
#endif
#ifndef NO_RSA
    if (certType == RSA_TYPE)
        req.sigType = CTC_SHA256wRSA;
#endif
#ifdef HAVE_ED25519
    if (certType == ED25519_TYPE)
        req.sigType = CTC_ED25519;
#endif
#ifdef HAVE_ED448
    if (certType == ED448_TYPE)
        req.sigType = CTC_ED448;
#endif
#ifdef HAVE_DILITHIUM
    if (certType == ML_DSA_LEVEL2_TYPE)
        req.sigType = CTC_ML_DSA_LEVEL2;
    if (certType == ML_DSA_LEVEL3_TYPE)
        req.sigType = CTC_ML_DSA_LEVEL3;
    if (certType == ML_DSA_LEVEL5_TYPE)
        req.sigType = CTC_ML_DSA_LEVEL5;
#endif
#ifdef HAVE_FALCON
    if (certType == FALCON_LEVEL1_TYPE)
        req.sigType = CTC_FALCON_LEVEL1;
    if (certType == FALCON_LEVEL5_TYPE)
        req.sigType = CTC_FALCON_LEVEL5;
#endif
#ifdef HAVE_SPHINCS
    if (certType == SPHINCS_HARAKA_128F_ROBUST_TYPE)
        req.sigType = CTC_SPHINCS_HARAKA_128F_ROBUST;
    if (certType == SPHINCS_HARAKA_128S_ROBUST_TYPE)
        req.sigType = CTC_SPHINCS_HARAKA_128S_ROBUST;
    if (certType == SPHINCS_HARAKA_192F_ROBUST_TYPE)
        req.sigType = CTC_SPHINCS_HARAKA_192F_ROBUST;
    if (certType == SPHINCS_HARAKA_192S_ROBUST_TYPE)
        req.sigType = CTC_SPHINCS_HARAKA_192S_ROBUST;
    if (certType == SPHINCS_HARAKA_256F_ROBUST_TYPE)
        req.sigType = CTC_SPHINCS_HARAKA_256F_ROBUST;
    if (certType == SPHINCS_HARAKA_256S_ROBUST_TYPE)
        req.sigType = CTC_SPHINCS_HARAKA_256S_ROBUST;
#endif
#ifdef HAVE_MLDSA_COMPOSITE
    if (certType == MLDSA44_NISTP256_TYPE)
        req.sigType = CTC_MLDSA44_NISTP256_SHA256;
    if (certType == MLDSA44_RSA2048_TYPE)
        req.sigType = CTC_MLDSA44_RSA2048_SHA256;
    if (certType == MLDSA44_RSAPSS2048_TYPE)
        req.sigType = CTC_MLDSA44_RSAPSS2048_SHA256;
    // if (type == MLDSA44_BPOOL256_TYPE)
    //     req.sigType = CTC_MLDSA44_BPOOL256_SHA256;
    if (certType == MLDSA44_ED25519_TYPE)
        req.sigType = CTC_MLDSA44_ED25519;
    if (certType == MLDSA65_NISTP256_TYPE)
        req.sigType = CTC_MLDSA65_NISTP256_SHA384;
    if (certType == MLDSA65_RSA3072_TYPE)
        req.sigType = CTC_MLDSA65_RSA3072_SHA384;
    if (certType == MLDSA65_RSAPSS3072_TYPE)    
        req.sigType = CTC_MLDSA65_RSAPSS3072_SHA384;
    if (certType == MLDSA65_RSA4096_TYPE)
        req.sigType = CTC_MLDSA65_RSA4096_SHA384;
    if (certType == MLDSA65_RSAPSS4096_TYPE)    
        req.sigType = CTC_MLDSA65_RSAPSS4096_SHA384;
    if (certType == MLDSA65_BPOOL256_TYPE)
        req.sigType = CTC_MLDSA65_BPOOL256_SHA256;
    if (certType == MLDSA65_ED25519_TYPE)
        req.sigType = CTC_MLDSA65_ED25519_SHA384;
    if (certType == MLDSA87_NISTP384_TYPE)
        req.sigType = CTC_MLDSA87_NISTP384_SHA384;
    if (certType == MLDSA87_BPOOL384_TYPE)
        req.sigType = CTC_MLDSA87_BPOOL384_SHA384;
    if (certType == MLDSA87_ED448_TYPE)
        req.sigType = CTC_MLDSA87_ED448;
    // -------- Draft 2 -------------//
    if (certType == D2_MLDSA44_RSAPSS2048_SHA256_TYPE)
        req.sigType = D2_CTC_MLDSA44_RSAPSS2048_SHA256;
    if (certType == D2_MLDSA44_RSA2048_SHA256_TYPE)
        req.sigType = D2_CTC_MLDSA44_RSA2048_SHA256;
    if (certType == D2_MLDSA44_NISTP256_SHA256_TYPE)
        req.sigType = D2_CTC_MLDSA44_NISTP256_SHA256;
    if (certType == D2_MLDSA44_ED25519_SHA256_TYPE)
        req.sigType = D2_CTC_MLDSA44_ED25519;
    if (certType == D2_MLDSA65_RSAPSS3072_SHA512_TYPE)
        req.sigType = D2_CTC_MLDSA65_RSAPSS3072_SHA512;
    if (certType == D2_MLDSA65_RSA3072_SHA512_TYPE)
        req.sigType = D2_CTC_MLDSA65_RSA3072_SHA512;
    if (certType == D2_MLDSA65_NISTP256_SHA512_TYPE)
        req.sigType = D2_CTC_MLDSA65_NISTP256_SHA512;
    if (certType == D2_MLDSA65_ED25519_SHA512_TYPE)
        req.sigType = D2_CTC_MLDSA65_ED25519_SHA512;
    if (certType == D2_MLDSA87_BPOOL384_SHA512_TYPE)
        req.sigType = D2_CTC_MLDSA87_BPOOL384_SHA512;
    if (certType == D2_MLDSA87_NISTP384_SHA512_TYPE)
        req.sigType = D2_CTC_MLDSA87_NISTP384_SHA512;
    if (certType == D2_MLDSA87_ED448_SHA512_TYPE)
        req.sigType = D2_CTC_MLDSA87_ED448_SHA512;
#endif
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("RNG initialization failed: %d\n", ret);
        goto exit;
    }
    ret = wc_SignCert_ex(req.bodySz, req.sigType, 
                         der, sizeof(der), certType,
                         (void *)&keyPair->val, &rng);
    if (ret <= 0) {
        printf("Sign Cert failed: %d\n", ret);
        goto exit;
    }
    derSz = ret;

#ifdef WOLFSSL_DER_TO_PEM
    byte * pem_data = NULL;
    int pem_dataSz = 0;

    ret = wc_DerToPem(der, derSz, NULL, pem_dataSz, CERTREQ_TYPE);
    if (ret <= 0) {
        printf("Cannot get the size of the PEM...: %d\n", ret);
        goto exit;
    }
    pem_dataSz = ret;
    pem_data = (byte *)XMALLOC(pem_dataSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (pem_data == NULL) {
        printf("Memory Error exporting key\n");
        goto exit;
    }
    ret = wc_DerToPem(der, derSz, pem_data, pem_dataSz, CERTREQ_TYPE);
    if (ret <= 0) {
        printf("CSR DER to PEM failed: %d\n", ret);
        goto exit;
    }
    if (out_filename) {
        file = fopen(out_filename, "wb");
        if (file) {
            ret = (int)fwrite(pem_data, 1, pem_dataSz, file);
            fclose(file);
        }
    } else {
        int fd = fileno(stdout);
        ret = write(fd, pem_data, pem_dataSz);
    }
#endif

    ret = 0; /* success */
    
exit:
    wc_FreeRng(&rng);

#endif /* WOLFSSL_CERT_REQ */

    (void)altkey;
    (void)out_format;
    (void)out_filename;
    (void)keyPair;
    (void)ret;

    return ret;
}

int gen_cert(const AsymKey * keyPair, const AsymKey * altkey, const char * out_filename, int out_format)
{
    int ret = NOT_COMPILED_IN;
#ifdef WOLFSSL_CERT_REQ
    int certType = MLDSA44_NISTP256_TYPE; // MLDSA87_ED448_TYPE
    // void* keyPtr = NULL;
    WC_RNG rng;
    byte der[12240];
    int  derSz = 12240;
#ifdef WOLFSSL_DER_TO_PEM
    // byte pem[12240];
    // int  pemSz = 12240;
    FILE* file = NULL;
    // char outFile[255];
#endif

    XMEMSET(der, 0, 12240);
#ifdef WOLFSSL_DER_TO_PEM
    // XMEMSET(pem, 0, 12240);
#endif

    Cert aCert;
    enum Key_Sum keySum;

    if (!keyPair) {
        printf("Invalid key\n");
        return BAD_FUNC_ARG;
    }
    
    ret = wc_InitCert(&aCert);
    if (ret != 0) {
        printf("Init Cert failed: %d\n", ret);
        goto exit;
    }

    // Extracts the type of key
    keySum = wc_AsymKey_Oid(keyPair);
    certType = wc_AsymKey_CertType(keyPair);

    const char * algName = (char *)wc_KeySum_name(keySum);
    if (algName == NULL) {
        printf("Cannot Retreieve Alg Name for key type: %d\n", keySum);
        algName = "Unknown";
    }

    printf("CertType: %d, keySum: %d, algName: %s\n", certType, keySum, algName);

    strncpy(aCert.subject.country, "US", CTC_NAME_SIZE);
    // strncpy(req.subject.state, "OR", CTC_NAME_SIZE);
    // strncpy(req.subject.locality, "Portland", CTC_NAME_SIZE);
    strncpy(aCert.subject.org, "wolfSSL", CTC_NAME_SIZE);
    strncpy(aCert.subject.unit, "Test", CTC_NAME_SIZE);
    strncpy(aCert.subject.commonName, algName, CTC_NAME_SIZE);
    strncpy(aCert.subject.email, "info@wolfssl.com", CTC_NAME_SIZE);
    aCert.version = 0;

    byte serial[20] = { 
        0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };

    // XMEMCPY(aCert.serial, serial, sizeof(serial));
    // aCert.serialSz = sizeof(serial);
    aCert.serialSz = sizeof(serial);

    /* Days before certificate expires */
    aCert.daysValid = 365;

    XMEMCPY(aCert.serial, serial, sizeof(serial));
    aCert.serialSz = sizeof(serial);

    // Forcing the type
    // certType = MLDSA44_RSAPSS2048_TYPE;
    ret = wc_MakeCert_ex(&aCert, der, sizeof(der), certType, (void *)&keyPair->val, &rng);
    if (ret <= 0) {
        printf("Make Cert failed: %d\n", ret);
        goto exit;
    }
    derSz = ret;

#ifdef HAVE_ECC
    if (certType == ECC_TYPE)
        aCert.sigType = CTC_SHA256wECDSA;
#endif
#ifndef NO_RSA
    if (certType == RSA_TYPE)
        aCert.sigType = CTC_SHA256wRSA;
#endif
#ifdef HAVE_ED25519
    if (certType == ED25519_TYPE)
        aCert.sigType = CTC_ED25519;
#endif
#ifdef HAVE_ED448
    if (certType == ED448_TYPE)
        aCert.sigType = CTC_ED448;
#endif
#ifdef HAVE_DILITHIUM
    if (certType == ML_DSA_LEVEL2_TYPE)
        aCert.sigType = CTC_DILITHIUM_LEVEL2;
    if (certType == ML_DSA_LEVEL3_TYPE)
        aCert.sigType = CTC_DILITHIUM_LEVEL3;
    if (certType == ML_DSA_LEVEL5_TYPE)
        aCert.sigType = CTC_DILITHIUM_LEVEL5;
#endif
#ifdef HAVE_FALCON
    if (certType == FALCON_LEVEL1_TYPE)
        aCert.sigType = CTC_FALCON_LEVEL1;
    if (certType == FALCON_LEVEL5_TYPE)
        aCert.sigType = CTC_FALCON_LEVEL5;
#endif
#ifdef HAVE_SPHINCS
    if (certType == SPHINCS_HARAKA_128F_ROBUST_TYPE)
        aCert.sigType = CTC_SPHINCS_HARAKA_128F_ROBUST;
    if (certType == SPHINCS_HARAKA_128S_ROBUST_TYPE)
        aCert.sigType = CTC_SPHINCS_HARAKA_128S_ROBUST;
    if (certType == SPHINCS_HARAKA_192F_ROBUST_TYPE)
        aCert.sigType = CTC_SPHINCS_HARAKA_192F_ROBUST;
    if (certType == SPHINCS_HARAKA_192S_ROBUST_TYPE)
        aCert.sigType = CTC_SPHINCS_HARAKA_192S_ROBUST;
    if (certType == SPHINCS_HARAKA_256F_ROBUST_TYPE)
        aCert.sigType = CTC_SPHINCS_HARAKA_256F_ROBUST;
    if (certType == SPHINCS_HARAKA_256S_ROBUST_TYPE)
        aCert.sigType = CTC_SPHINCS_HARAKA_256S_ROBUST;
#endif
#ifdef HAVE_MLDSA_COMPOSITE
    if (certType == MLDSA44_NISTP256_TYPE)
        aCert.sigType = CTC_MLDSA44_NISTP256_SHA256;
    if (certType == MLDSA44_RSA2048_TYPE)
        aCert.sigType = CTC_MLDSA44_RSA2048_SHA256;
    if (certType == MLDSA44_RSAPSS2048_TYPE)
        aCert.sigType = CTC_MLDSA44_RSAPSS2048_SHA256;
    // if (type == MLDSA44_BPOOL256_TYPE)
    //     aCert.sigType = CTC_MLDSA44_BPOOL256_SHA256;
    if (certType == MLDSA44_ED25519_TYPE)
        aCert.sigType = CTC_MLDSA44_ED25519;
    if (certType == MLDSA65_NISTP256_TYPE)
        aCert.sigType = CTC_MLDSA65_NISTP256_SHA384;
    if (certType == MLDSA65_RSA3072_TYPE)
        aCert.sigType = CTC_MLDSA65_RSA3072_SHA384;
    if (certType == MLDSA65_RSAPSS3072_TYPE)    
        aCert.sigType = CTC_MLDSA65_RSAPSS3072_SHA384;
    if (certType == MLDSA65_RSA4096_TYPE)
        aCert.sigType = CTC_MLDSA65_RSA4096_SHA384;
    if (certType == MLDSA65_RSAPSS4096_TYPE)    
        aCert.sigType = CTC_MLDSA65_RSAPSS4096_SHA384;
    if (certType == MLDSA65_BPOOL256_TYPE)
        aCert.sigType = CTC_MLDSA65_BPOOL256_SHA256;
    if (certType == MLDSA65_ED25519_TYPE)
        aCert.sigType = CTC_MLDSA65_ED25519_SHA384;
    if (certType == MLDSA87_NISTP384_TYPE)
        aCert.sigType = CTC_MLDSA87_NISTP384_SHA384;
    if (certType == MLDSA87_BPOOL384_TYPE)
        aCert.sigType = CTC_MLDSA87_BPOOL384_SHA384;
    if (certType == MLDSA87_ED448_TYPE)
        aCert.sigType = CTC_MLDSA87_ED448;
    // -------- Draft 2 -------------//
    if (certType == D2_MLDSA44_RSAPSS2048_SHA256_TYPE)
        aCert.sigType = D2_CTC_MLDSA44_RSAPSS2048_SHA256;
    if (certType == D2_MLDSA44_RSA2048_SHA256_TYPE)
        aCert.sigType = D2_CTC_MLDSA44_RSA2048_SHA256;
    if (certType == D2_MLDSA44_NISTP256_SHA256_TYPE)
        aCert.sigType = D2_CTC_MLDSA44_NISTP256_SHA256;
    if (certType == D2_MLDSA44_ED25519_SHA256_TYPE)
        aCert.sigType = D2_CTC_MLDSA44_ED25519;
    if (certType == D2_MLDSA65_RSAPSS3072_SHA512_TYPE)
        aCert.sigType = D2_CTC_MLDSA65_RSAPSS3072_SHA512;
    if (certType == D2_MLDSA65_RSA3072_SHA512_TYPE)
        aCert.sigType = D2_CTC_MLDSA65_RSA3072_SHA512;
    if (certType == D2_MLDSA65_NISTP256_SHA512_TYPE)
        aCert.sigType = D2_CTC_MLDSA65_NISTP256_SHA512;
    if (certType == D2_MLDSA65_ED25519_SHA512_TYPE)
        aCert.sigType = D2_CTC_MLDSA65_ED25519_SHA512;
    if (certType == D2_MLDSA87_BPOOL384_SHA512_TYPE)
        aCert.sigType = D2_CTC_MLDSA87_BPOOL384_SHA512;
    if (certType == D2_MLDSA87_NISTP384_SHA512_TYPE)
        aCert.sigType = D2_CTC_MLDSA87_NISTP384_SHA512;
    if (certType == D2_MLDSA87_ED448_SHA512_TYPE)
        aCert.sigType = D2_CTC_MLDSA87_ED448_SHA512;
#endif
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("RNG initialization failed: %d\n", ret);
        goto exit;
    }
    ret = wc_SignCert_ex(aCert.bodySz, aCert.sigType, 
                         der, sizeof(der), certType,
                         (void *)&keyPair->val, &rng);
    if (ret <= 0) {
        printf("Sign Cert failed: %d\n", ret);
        goto exit;
    }
    derSz = ret;

#ifdef WOLFSSL_DER_TO_PEM
    byte * pem_data = NULL;
    int pem_dataSz = 0;

    ret = wc_DerToPem(der, derSz, NULL, pem_dataSz, CERT_TYPE);
    if (ret <= 0) {
        printf("Cannot get the size of the PEM...: %d\n", ret);
        goto exit;
    }
    pem_dataSz = ret;
    pem_data = (byte *)XMALLOC(pem_dataSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (pem_data == NULL) {
        printf("Memory Error exporting key\n");
        goto exit;
    }
    ret = wc_DerToPem(der, derSz, pem_data, pem_dataSz, CERT_TYPE);
    if (ret <= 0) {
        printf("CSR DER to PEM failed: %d\n", ret);
        goto exit;
    }
    if (out_filename) {
        file = fopen(out_filename, "wb");
        if (file) {
            ret = (int)fwrite(pem_data, 1, pem_dataSz, file);
            fclose(file);
        }
    } else {
        int fd = fileno(stdout);
        ret = write(fd, pem_data, pem_dataSz);
    }
#endif

    ret = 0; /* success */
    
exit:
    wc_FreeRng(&rng);

#endif /* WOLFSSL_CERT_REQ */

    (void)altkey;
    (void)out_format;
    (void)out_filename;
    (void)keyPair;
    (void)ret;

    return ret;
}

#ifdef WOLFSSL_KEY_GEN

int gen_keypair(AsymKey ** key, int keySum, int param) {

    int ret;
    WC_RNG rng;

    wc_InitRng(&rng);
    if ((ret = wc_AsymKey_gen(key, keySum, param, NULL, 0, &rng)) < 0) {
        printf("Error generating key (%d)\n", ret);
        return -1;
    }

    wc_FreeRng(&rng);

    return 0;
}
#endif // WOLFSSL_KEY_GEN


int main(int argc, char** argv) {

#if !defined(WOLFSSL_CERT_REQ) || !defined(WOLFSSL_CERT_GEN) || !defined(WOLFSSL_KEY_GEN) || !defined(WOLFSSL_CERT_EXT) 
    printf("Please compile wolfSSL with --enable-certreq --enable-certgen\n"
           "  --enable-keygen --enable-certext\n");
    return 0;
#else
    enum Key_Sum keySum = ML_DSA_LEVEL2k;
    int verbose = 0;
    int debug = 0;
    
    char * out_file = NULL;
    char * in_file = NULL;

    int i = 1;
    
    int param = 0;
    int cmd = 0; /* 0 = pkey, 1 = req, 2 = cert */

    int in_format = -1; /* -1 = ANY, 0 = DER, 1 = PEM */
    int out_format = 1; /* 0 = DER, 1 = PEM */

    AsymKey * keyPtr = NULL; /* pointer to the key */
    AsymKey * altKeyPtr = NULL; /* pointer to the alt Key */

    char * key_file = NULL; /* key file */
    char * csr_file = NULL; /* csr file */
    char * cert_file = NULL; /* cert file */
    char * altkey_file = NULL; /* alt key file */
    char * ca_file = NULL; /* ca file */

    int error = 0; /* error flag */

    // Gets the CMD
    if (argc < 2) {
        usage();
        return 1;
    }

    if (!XSTRNCMP(argv[i], "genpkey", 7)) {
        cmd = 0;
    } else if (!XSTRNCMP(argv[i], "genreq", 6)) {
        cmd = 1;
    } else if (!XSTRNCMP(argv[i], "gencert", 7)) {
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
                       !XSTRNCMP(argv[i], "NISTP256", 8) ||
                       !XSTRNCMP(argv[i], "prime256v1", 10) ||
                       !XSTRNCMP(argv[i], "PRIME256V1", 10) ||
                       !XSTRNCMP(argv[i], "secp256r1", 9) ||
                       !XSTRNCMP(argv[i], "SECP256R1", 9) ||
                       !XSTRNCMP(argv[i], "p256", 4) ||
                       !XSTRNCMP(argv[i], "P256", 4)) {
                param = ECC_SECP256R1;
            } else if (!XSTRNCMP(argv[i], "nistp384", 8) ||
                       !XSTRNCMP(argv[i], "NISTP384", 8) ||
                       !XSTRNCMP(argv[i], "secp384r1", 9) ||
                       !XSTRNCMP(argv[i], "SECP384R1", 9) ||
                       !XSTRNCMP(argv[i], "P384", 4) ||
                       !XSTRNCMP(argv[i], "p384", 4)) {
                param = ECC_SECP384R1;
            } else if (!XSTRNCMP(argv[i], "nistp521", 8) ||
                       !XSTRNCMP(argv[i], "NISTP521", 8) ||
                       !XSTRNCMP(argv[i], "secp521r1", 9) ||
                       !XSTRNCMP(argv[i], "SECP521R1", 9) ||
                       !XSTRNCMP(argv[i], "P521", 4) ||
                       !XSTRNCMP(argv[i], "p521", 4)) {
                param = ECC_SECP521R1;
            } else if (!XSTRNCMP(argv[i], "bpool256", 8) ||
                       !XSTRNCMP(argv[i], "BPOOL256", 8) ||
                       !XSTRNCMP(argv[i], "brainpool256", 11) ||
                       !XSTRNCMP(argv[i], "BRAINPOOL256", 11) ||
                       !XSTRNCMP(argv[i], "bp256", 5) ||
                       !XSTRNCMP(argv[i], "BP256", 5)) {
                param = ECC_BRAINPOOLP256R1;
            } else if (!XSTRNCMP(argv[i], "bpool384", 8) ||
                       !XSTRNCMP(argv[i], "BPOOL384", 8) ||
                       !XSTRNCMP(argv[i], "brainpool384", 11) ||
                       !XSTRNCMP(argv[i], "BRAINPOOL384", 11) ||
                       !XSTRNCMP(argv[i], "bp384", 5) ||
                       !XSTRNCMP(argv[i], "BP384", 5)) {
                param = ECC_BRAINPOOLP384R1;
            } else if (!XSTRNCMP(argv[i], "bpool512", 8) ||
                       !XSTRNCMP(argv[i], "BPOOL512", 8) ||
                       !XSTRNCMP(argv[i], "brainpool512", 11) ||
                       !XSTRNCMP(argv[i], "BRAINPOOL512", 11) ||
                       !XSTRNCMP(argv[i], "bp512", 5) ||
                       !XSTRNCMP(argv[i], "BP512", 5)) {
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
            error = 1;
            break;
        }
        i++;
    }

    // Abort if we do not understand any option(s)
    if (error) exit(error);

    switch (cmd) {
        // PKEY
        case 0: {
#ifdef WOLFSSL_KEY_GEN
            if (gen_keypair(&keyPtr, keySum, param) < 0) {
                printf("Error generating keypair\n");
                return 1;
            }
            if (export_key_p8(keyPtr, out_file, out_format) < 0) {
                printf("export_key_p8() < 0 : Error exporting keypair\n");
                return 1;
            }
#else
            printf("Key generation not supported\n");
            return 1;
#endif
        } break;

        // Gen CSR
        case 1: {
            printf("Generating CSR\n");
            if (in_file == NULL && key_file == NULL) {
                printf("Missing keypair or request filename\n");
                return 1;
            } else if (key_file == NULL) {
                key_file = in_file;
            }
            if (load_key_p8(&keyPtr, keySum, key_file, in_format) < 0) {
                printf("Error loading keypair\n");
                return -1;
            }
            if (altkey_file) {
                if (load_key_p8(&altKeyPtr, keySum, altkey_file, in_format) < 0) {
                    printf("Error loading alt keypair\n");
                    return -1;
                }
            }
            if (gen_csr(keyPtr, altKeyPtr, out_file, out_format) < 0) {
                return -1;
            }
            return 0;
        } break;

        // Gen CERT
        case 2: {
            printf("Generating CERT\n");
            if (in_file == NULL && key_file == NULL) {
                printf("Missing keypair or request filename\n");
                return 1;
            } else if (key_file == NULL) {
                key_file = in_file;
            }
            if (load_key_p8(&keyPtr, keySum, key_file, in_format) < 0) {
                printf("Error loading keypair\n");
                return -1;
            }

            if (altkey_file) {
                if (load_key_p8(&altKeyPtr, keySum, altkey_file, in_format) < 0) {
                    printf("Error loading alt keypair\n");
                    return -1;
                }
            }
            if (gen_cert(keyPtr, altKeyPtr, out_file, out_format) < 0) {
                printf("Error generating certificate\n");
                return -1;
            }
            return 0;
        } break;

        default:
            return -1;
    }

    (void)debug;
    (void)verbose;
    (void)in_format;
    (void)ca_file;
    (void)csr_file;
#endif
    (void)argv;
    (void)argc;

    return 0;
}