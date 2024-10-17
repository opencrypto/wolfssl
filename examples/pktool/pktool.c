/* csr_example.c */

#include "pktool.h"

#define LARGE_TEMP_SZ 4096

static void usage(void)
{
    printf("Invalid input supplied try one of the below examples\n");
    printf("Examples:\n\n");
    printf("./csr_example rsa\n");
    printf("./csr_example ecc\n");
    printf("./csr_example ed25519\n");
}

static int gen_csr(const char* arg1)
{
    int ret;
    int type;
#ifdef HAVE_ECC
    ecc_key ecKey;
#endif
#ifndef NO_RSA
    RsaKey rsaKey;
#endif
#ifdef HAVE_ED25519
    ed25519_key edKey;
#endif
    void* keyPtr = NULL;
    WC_RNG rng;
    Cert req;
    byte der[LARGE_TEMP_SZ];
    int  derSz;
#ifdef WOLFSSL_DER_TO_PEM
    byte pem[LARGE_TEMP_SZ];
    int  pemSz;
    FILE* file = NULL;
    char outFile[255];
#endif

    XMEMSET(der, 0, LARGE_TEMP_SZ);
#ifdef WOLFSSL_DER_TO_PEM
    XMEMSET(pem, 0, LARGE_TEMP_SZ);
#endif

    if (XSTRNCMP(arg1, "rsa", 3) == 0)
        type = RSA_TYPE;
    else if (XSTRNCMP(arg1, "ecc", 3) == 0)
        type = ECC_TYPE;
    else if (XSTRNCMP(arg1, "ed25519", 7) == 0)
        type = ED25519_TYPE;
    else
        return NOT_COMPILED_IN;

    
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("RNG initialization failed: %d\n", ret);
        return ret;
    }

#ifdef HAVE_ECC
    if (type == ECC_TYPE) {
        keyPtr = &ecKey;
        ret = wc_ecc_init(&ecKey);
    }
#endif
#ifndef NO_RSA
    if (type == RSA_TYPE) {
        keyPtr = &rsaKey;
        ret = wc_InitRsaKey(&rsaKey, NULL);
    }
#endif
#ifdef HAVE_ED25519
    if (type == ED25519_TYPE) {
        keyPtr = &edKey;
        ret = wc_ed25519_init(&edKey);
    }
#endif
    if (ret != 0) {
        printf("Key initialization failed: %d\n", ret);
        goto exit;
    }

#ifdef HAVE_ECC
    if (type == ECC_TYPE)
        ret = wc_ecc_make_key_ex(&rng, 32, &ecKey, ECC_SECP256R1);
#endif
#ifndef NO_RSA
    if (type == RSA_TYPE)
        ret = wc_MakeRsaKey(&rsaKey, 2048, WC_RSA_EXPONENT, &rng);
#endif
#ifdef HAVE_ED25519
    if (type == ED25519_TYPE)
        ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &edKey);
#endif
    if (ret != 0) {
        printf("Key generation failed: %d\n", ret);
        goto exit;
    }

#ifdef HAVE_ECC
    if (type == ECC_TYPE)
        ret = wc_EccKeyToDer(&ecKey, der, sizeof(der));
#endif
#ifndef NO_RSA
    if (type == RSA_TYPE)
        ret = wc_RsaKeyToDer(&rsaKey, der, sizeof(der));
#endif
#ifdef HAVE_ED25519
    if (type == ED25519_TYPE)
        ret = wc_Ed25519KeyToDer(&edKey, der, sizeof(der));
#endif
    if (ret <= 0) {
        printf("Key To DER failed: %d\n", ret);
        goto exit;
    }
    derSz = ret;

#ifdef WOLFSSL_DER_TO_PEM
    memset(pem, 0, sizeof(pem));
#ifdef HAVE_ECC
    if (type == ECC_TYPE)
        ret = wc_DerToPem(der, derSz, pem, sizeof(pem), ECC_PRIVATEKEY_TYPE);
#endif
#ifndef NO_RSA
    if (type == RSA_TYPE)
        ret = wc_DerToPem(der, derSz, pem, sizeof(pem), PRIVATEKEY_TYPE);
#endif
#ifdef HAVE_ED25519
    if (type == ED25519_TYPE)
        ret = wc_DerToPem(der, derSz, pem, sizeof(pem), ED25519_TYPE);
#endif
    if (ret <= 0) {
        printf("Key DER to PEM failed: %d\n", ret);
        goto exit;
    }
    pemSz = ret;
    printf("%s (%d)\n", pem, pemSz);

    snprintf(outFile, sizeof(outFile), "%s-key.pem", arg1);
    printf("Saved Key PEM to \"%s\"\n", outFile);
    file = fopen(outFile, "wb");
    if (file) {
        ret = (int)fwrite(pem, 1, pemSz, file);
        fclose(file);
    }
#endif /* WOLFSSL_DER_TO_PEM */

    ret = wc_InitCert(&req);
    if (ret != 0) {
        printf("Init Cert failed: %d\n", ret);
        goto exit;
    }
    strncpy(req.subject.country, "US", CTC_NAME_SIZE);
    strncpy(req.subject.state, "OR", CTC_NAME_SIZE);
    strncpy(req.subject.locality, "Portland", CTC_NAME_SIZE);
    strncpy(req.subject.org, "wolfSSL", CTC_NAME_SIZE);
    strncpy(req.subject.unit, "Development", CTC_NAME_SIZE);
    strncpy(req.subject.commonName, "www.wolfssl.com", CTC_NAME_SIZE);
    strncpy(req.subject.email, "info@wolfssl.com", CTC_NAME_SIZE);
    req.version = 0;
    ret = wc_MakeCertReq_ex(&req, der, sizeof(der), type, keyPtr);
    if (ret <= 0) {
        printf("Make Cert Req failed: %d\n", ret);
        goto exit;
    }
    derSz = ret;

#ifdef HAVE_ECC
    if (type == ECC_TYPE)
        req.sigType = CTC_SHA256wECDSA;
#endif
#ifndef NO_RSA
    if (type == RSA_TYPE)
        req.sigType = CTC_SHA256wRSA;
#endif
#ifdef HAVE_ED25519
    if (type == ED25519_TYPE)
        req.sigType = CTC_ED25519;
#endif
    ret = wc_SignCert_ex(req.bodySz, req.sigType, der, sizeof(der), type,
        keyPtr, &rng);
    if (ret <= 0) {
        printf("Sign Cert failed: %d\n", ret);
        goto exit;
    }
    derSz = ret;

#ifdef WOLFSSL_DER_TO_PEM
    memset(pem, 0, sizeof(pem));
    ret = wc_DerToPem(der, derSz, pem, sizeof(pem), CERTREQ_TYPE);
    if (ret <= 0) {
        printf("CSR DER to PEM failed: %d\n", ret);
        goto exit;
    }
    pemSz = ret;
    printf("%s (%d)\n", pem, pemSz);

    snprintf(outFile, sizeof(outFile), "%s-csr.pem", arg1);
    printf("Saved CSR PEM to \"%s\"\n", outFile);
    file = fopen(outFile, "wb");
    if (file) {
        ret = (int)fwrite(pem, 1, pemSz, file);
        fclose(file);
    }
#endif

    ret = 0; /* success */
    
exit:
#ifdef HAVE_ECC
    if (type == ECC_TYPE)
        wc_ecc_free(&ecKey);
#endif
#ifndef NO_RSA
    if (type == RSA_TYPE)
        wc_FreeRsaKey(&rsaKey);
#endif
#ifdef HAVE_ED25519
    if (type == ED25519_TYPE)
        wc_ed25519_free(&edKey);
#endif
    wc_FreeRng(&rng);

    return ret;
}

int main(int argc, char** argv)
{
#if !defined(WOLFSSL_CERT_REQ) || !defined(WOLFSSL_CERT_GEN) || !defined(WOLFSSL_KEY_GEN)
    printf("Please compile wolfSSL with --enable-certreq --enable-certgen --enable-certext --enable-keygen\n");
    return 0;
#else
    enum Key_Sum keySum = RSAk;
    int verbose = 0;
    int debug = 0;
    int i = 1;

    while (i < argc) {
        if (XSTRNCMP(argv[i], "-v", 2) == 0) {
            verbose = 1;
        } else if (XSTRNCMP(argv[i], "-d", 2) == 0) {
            debug = 1;
        } else if (XSTRNCMP(argv[i], "-h", 2) == 0) {
            usage();
            return 1;
        } else if (XSTRNCMP(argv[i++], "-algor", 6) == 0) {
            keySum = wc_KeySum_get(argv[i]);
            if ( keySum < 0) {
                printf("Invalid algorithm type\n");
                return 1;
            }
            printf("Algorithm type: %d (%s)\n", keySum, wc_KeySum_name(keySum));
        }
        i++;
    }

    if (argc != 2) {
        if (verbose) usage();
        return 1;
    }

    (void)debug;

    return gen_csr(argv[1]);
#endif
}