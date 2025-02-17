/* pktool.c */

#include "pktool.h"

void usage(void) {

    printf("\n");
    printf("\n    USAGE: pktool <CMD> [ options ]\n\n");
    printf("Where <CMD> is one of the following:\n");
    printf(" genkey ..............: Generates a keypair (PKCS#8 format)\n");
    printf(" genreq ..............: Generate a certificate request (PKCS#10 format)\n");
    printf(" signcert ............: Generate an X.509 Certificate\n");
    printf(" templates ...........: Lists available templates and id values\n\n");
    
    printf("Where [ options ] are:\n");
    printf(" -in <file> .......: input file\n");
    printf(" -out <file> ......: output file\n");
    printf(" -inform <format> .: input format (DER, PEM)\n");
    printf(" -outform <format> : output format (DER, PEM)\n");
    printf(" -template_id <id> : certificate template to use (0-20)\n");
    printf(" -subject <DN> ... : certificate subject (e.g., 'O=wolfSSL, OU=Test, CN=John Doe')\n");
    printf(" -algor <name> ....: use the named algorithm (e.g., rsa, ec, mldsa44, mldsa65-ed25519)\n");
    printf(" -curve <name> ....: use the named curve (e.g., nistp256, nistp384, nistp521, bpool256, bpool384, bpool512)\n");
    printf(" -bits <num> ......: number of bits in the key (RSA only)\n");
    printf(" -key <file> ......: signing private key filename\n");
    printf(" -altkey <file> ...: filename for the secondary signing private key\n");
    printf(" -cacert <file> ...: CA certificate filename\n");
    printf(" -h ...............: help\n\n");
}

void templates(void) {

    printf("Where IETF template_id(s) are:\n");
    printf(" 1 ................: WC_CERT_TEMPLATE_IETF_ROOT_CA\n");
    printf(" 2 ................: WC_CERT_TEMPLATE_IETF_INTERMEDIATE_CA\n");
    printf(" 3 ................: WC_CERT_TEMPLATE_IETF_OCSP_SERVER\n");
    printf(" 4 ................: WC_CERT_TEMPLATE_IETF_CODE_SIGNING\n");
    printf(" 5 ................: WC_CERT_TEMPLATE_IETF_TIME_STAMPING\n");
    printf(" 6 ................: WC_CERT_TEMPLATE_IETF_TLS_SERVER\n");
    printf(" 7 ................: WC_CERT_TEMPLATE_IETF_TLS_CLIENT\n");
    printf(" 8 ................: WC_CERT_TEMPLATE_IETF_EMAIL\n");
    printf(" 9 ................: WC_CERT_TEMPLATE_IETF_802_1X\n");
    printf("10 ................: WC_CERT_TEMPLATE_IETF_IPSEC\n\n");

    printf("Where ASC X9 template_id(s) are:\n");
    printf("11 ................: WC_CERT_TEMPLATE_X9_RFC5280_ROOT_CA\n");
    printf("12 ................: WC_CERT_TEMPLATE_X9_INTERMEDIATE_CA\n");
    printf("13 ................: WC_CERT_TEMPLATE_X9_OCSP_SERVER\n");
    printf("14 ................: WC_CERT_TEMPLATE_X9_CODE_SIGNING\n");
    printf("15 ................: WC_CERT_TEMPLATE_X9_TIME_STAMPING\n");
    printf("16 ................: WC_CERT_TEMPLATE_X9_TLS_SERVER\n");
    printf("17 ................: WC_CERT_TEMPLATE_X9_TLS_CLIENT\n");
    printf("18 ................: WC_CERT_TEMPLATE_X9_EMAIL\n");
    printf("19 ................: WC_CERT_TEMPLATE_X9_802_1X\n");
    printf("20 ................: WC_CERT_TEMPLATE_X9_IPSEC\n");
    printf("\n");
}

int export_key_p8(AsymKey * key, const char * out_file, int format) {
    int ret = 0;

    FILE* file = NULL;
    
    word32 buffSz = 0;
    byte * buff = NULL;
        // buffer to hold the exported key

    if (format == 1) {

        ret = wc_AsymKey_PrivateKeyToPem(key, NULL, &buffSz);
        if (ret < 0) {
            printf("Error exporting key %d\n", ret);
            return ret;
        }

        buff = (byte *)XMALLOC(buffSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (buff == NULL) {
            printf("Error allocating memory for the key\n");
            return -1;
        }

        ret = wc_AsymKey_PrivateKeyToPem(key, buff, &buffSz);
        if (ret < 0) {
            printf("Error exporting key %d\n", ret);
            return ret;
        }

    } else {

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
        ret = (int)write(fd, buff, buffSz);
    }

    return 0;
}

int load_key_p8(AsymKey ** key, const char * key_file, int format) {

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

    ret = wc_AsymKey_Decode(&asymKeyPtr, keyData, keySz, -1);
    if (ret != 0) {
        printf("Error decoding the request: %d\n", ret);
        return ret;
    }
        
    // Free the key data
    if (keyData) XFREE(keyData, NULL, DYNAMIC_TYPE_PRIVATE_KEY);

    // Returns the key
    *key = asymKeyPtr;

    (void)idx;
    (void)privKey;
    (void)privKeySz;
    (void)pubKey;
    (void)pubKeySz;

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
    *len = (int)fileSz;

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

int gen_csr(const AsymKey * keyPair, const AsymKey * altkey,
            const char * out_filename, int out_format, const char * subject_dn)
{
    int ret = NOT_COMPILED_IN;

#ifdef WOLFSSL_CERT_REQ

    WC_RNG rng;
    Cert aReq;

    byte* out = NULL;
    word32 outSz = 0;

    if (!keyPair) {
        printf("Invalid key\n");
        return BAD_FUNC_ARG;
    }

    wc_InitCert(&aReq);
    ret = wc_AsymKey_CertReq_SetTemplate(&aReq, WC_CERT_TEMPLATE_IETF_ROOT_CA);
    if (ret != 0) {
        printf("Init Cert failed: %d\n", ret);
        return ret;
    }

    // Sets the Static parts of the DN
    if (wc_AsymKey_CertReq_SetSubject(&aReq, subject_dn) < 0) {
        printf("Error setting the subject\n");
        return -1;
    }

    wc_InitRng(&rng);
    ret = wc_AsymKey_SignReq_ex(&out, &outSz, &aReq, WC_HASH_TYPE_SHA512, 1, keyPair, &rng);
    if (ret < 0) {
        printf("Error Generating the Request: ret = %d, derSz = %d\n", ret, outSz);
        return ret;
    }
    outSz = ret;

    if (out_filename) {
        FILE * aFile = fopen(out_filename, "wb");
        if (!aFile) {
            printf("Error opening file for writing: %s\n", out_filename);
            return -1;
        }
        fwrite(out, outSz, 1, aFile);
        fclose(aFile);
    } else {
        int fd = fileno(stdout);
        write(fd, out, outSz);
    }

    wc_FreeRng(&rng);

#endif /* WOLFSSL_CERT_REQ */

    (void)altkey;
    (void)out_format;
    (void)out_filename;
    (void)keyPair;
    (void)ret;

    return 0;
}

int sign_cert(const char * req_file, const char * outCertFilename, int outCertFormat, 
              const char * caCertFilename, int caCertFormat, const char * subject_dn, int templateId,
              const AsymKey * caKeyPair, const AsymKey * caAltKeyPair)
{
    int ret = NOT_COMPILED_IN;

#ifdef WOLFSSL_CERT_REQ
    WC_RNG rng;
    byte * data = NULL;
    int  dataSz = 0;
    FILE* file = NULL;

    byte *pem = NULL;
    word32 pemSz = 0;

    byte * derReq = NULL;
    word32 derReqSz = 0;
        // PEM temp buffer

    byte *req = NULL;
        // DER encoded request

    byte *ca = NULL;
    word32 caSz = 0;
        // DER encoded request and CA certificate

    byte *cert = NULL;
    word32 certSz = 0;
        // DER encoded certificate

    Cert aCert;
        // Certificate Template

    AsymKey reqPubKey = { 0x0 };
        // Public key from the request

    if (!caKeyPair) {
        printf("Invalid key\n");
        return BAD_FUNC_ARG;
    }

    // Loads the request
    if (req_file) {
        if (load_file(&data, (int *)&dataSz, req_file) < 0) {
            printf("Cannot open the request file (%s)\n", req_file);
            return -1;
        }

        ret = wc_CertReq_PemToDer(&derReq, &derReqSz, data, dataSz, 1);
        if (ret < 0) {
            printf("Error converting the request to DER: %d\n", ret);
            return ret;
        }
    }

    // Loads the CA certificate
    if (caCertFilename) {
        if (load_file(&pem, (int *)&pemSz, caCertFilename) < 0) {
            printf("Cannot open the CA certificate file (%s)\n", caCertFilename);
            goto exit;
        }
        ret = wc_CertReq_PemToDer(&ca, &caSz, pem, pemSz, 0);
        if (ret < 0) {
            printf("2 Error converting the request to DER: %d\n", ret);
            return ret;
        }
    }

    // Initializes the random number generator
    wc_InitRng(&rng);

    // Initializes the certificate structure
    wc_InitCert(&aCert);

    ret = wc_AsymKey_CertReq_SetTemplate(&aCert, templateId);
    if (ret < 0) {
        printf("Error setting the template (id: %d): ret = %d\n", templateId, ret);
        return ret;
    }

    ret = wc_AsymKey_CertReq_SetSerial(&aCert, NULL, 15);
    if (ret < 0) {
        printf("Error setting the serial number: %d\n", ret);
        return ret;
    }

    if (subject_dn) {
        ret = wc_AsymKey_CertReq_SetSubject(&aCert, subject_dn);
        if (ret < 0) {
            printf("Error setting the subject: %d\n", ret);
            return ret;
        }
    }
    
    if (data) {
        ret = wc_AsymKey_CertReq_GetPublicKey(&reqPubKey, data, dataSz);
        if (ret < 0) {
            printf("Error getting the public key: %d\n", ret);
            return ret;
        }
    }

    if (ca) {
        ret = wc_AsymKey_CertReq_SetIssuer_CaCert(&aCert, ca, caSz);
        aCert.selfSigned = 0;
    } else if (subject_dn) {
        ret = wc_AsymKey_CertReq_SetIssuer(&aCert, subject_dn);
        aCert.selfSigned = 1;
    } else {
        ret = wc_AsymKey_CertReq_SetIssuer(&aCert, "O=wolfSSL");
        aCert.selfSigned = 1;
    }
    if (ret < 0) {
        return ret;
    }

    AsymKey * pubKeyPnt = &reqPubKey;

    if (aCert.selfSigned == 1)
        pubKeyPnt = (AsymKey *)caKeyPair;

    ret = wc_AsymKey_SignCert_ex(NULL, 0, 1, ca, caSz, &aCert, pubKeyPnt, 0, caKeyPair, NULL, &rng);
    if (ret < 0) {
        printf("Error generating the certificate: %d\n", ret);
        return ret;
    }
    
    certSz = ret = wc_AsymKey_SignCert_ex(NULL, 0, 1, ca, caSz, &aCert, pubKeyPnt, 0, caKeyPair, NULL, &rng);
    if (ret < 0) {
        printf("Error generating the certificate: %d\n", ret);
        return ret;
    }

    cert = (byte *)XMALLOC(certSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (cert == NULL) {
        printf("Memory Error exporting key\n");
        return -1;
    }

    ret = wc_AsymKey_SignCert_ex(cert, certSz, 1, ca, caSz, &aCert, pubKeyPnt, 0, caKeyPair, NULL, &rng);
    if (ret < 0) {
        printf("Error generating the certificate: %d\n", ret);
        return ret;
    }

    if (outCertFilename) {
        file = fopen(outCertFilename, "wb");
        if (file) {
            ret = (int)fwrite(cert, 1, certSz, file);
            fclose(file);
        }
    } else {
        int fd = fileno(stdout);
        ret = (int)write(fd, cert, certSz);
    }

    ret = 0; /* success */
    
exit:

    if (req) XFREE(req, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (pem) XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    wc_FreeRng(&rng);

#endif /* WOLFSSL_CERT_REQ */

    (void)req_file;
    (void)caAltKeyPair;
    (void)outCertFormat;
    (void)outCertFilename;
    (void)caCertFilename;
    (void)caCertFormat;
    (void)caKeyPair;
    (void)ca;
    (void)caSz;
    (void)ret;

    return ret;
}

#ifdef WOLFSSL_KEY_GEN

int gen_keypair(AsymKey ** key, int keySum, int param) {

    int ret;
    WC_RNG rng;

    wc_InitRng(&rng);
    if ((ret = wc_AsymKey_MakeKey(key, keySum, param, NULL, 0, &rng)) < 0) {
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
    
    char * out_file = NULL;
    char * in_file = NULL;

    int i = 1;
    int ret = 0;
    
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
    char * subject_dn = NULL; /* subject distinguished name */

    int templateId = 0; /* template number */
    int error = 0; /* error flag */

    (void)cert_file;

    // Gets the CMD
    if (argc < 2) {
        usage();
        return 1;
    }

    if (!XSTRNCMP(argv[i], "genpkey", 7)) {
        cmd = 0;
    } else if (!XSTRNCMP(argv[i], "genreq", 6)) {
        cmd = 1;
    } else if (!XSTRNCMP(argv[i], "signcert", 8)) {
        cmd = 2;
    } else if (!XSTRNCMP(argv[i], "templates", 8)) {
        templates();
        return 1;
    } else {
        usage();
        return 1;
    }

    i++;

    // Gets the parameters
    while (i < argc) {
        if (!XSTRNCMP(argv[i], "-inform", 7)) {
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
            ret = wc_KeySum_get(argv[i]);
            if (ret < 0) {
                printf("\n    ERROR: Cannot parse the Algorithm Identifier (%s)\n\n", argv[i]);
                error = 1;
                break;
            }
            keySum = ret;

        } else if (XSTRNCMP(argv[i], "-subject", 8) == 0) {
            i++;
            if (i >= argc) {
                printf("Missing Subject Distinguished Name\n\n");
                usage();
                return 1;
            }
            subject_dn = argv[i];

        } else if (XSTRNCMP(argv[i], "-template_id", 12) == 0) {
            i++;
            if ((templateId = atoi(argv[i])) <= 0) {
                printf("Invalid template id\n");
                return 1;
            }
            if (templateId > WC_CERT_TEMPLATE_MAX) {
                printf("Invalid template id (accepted: 1-%d)\n", WC_CERT_TEMPLATE_MAX);
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
        // } else if (XSTRNCMP(argv[i], "-cer", 4) == 0) {
        //     i++;
        //     if (i >= argc) {
        //         printf("Missing certificate filename\n\n");
        //         usage();
        //         return 1;
        //     }
        //     cert_file = argv[i];
        } else if (XSTRNCMP(argv[i], "-cacert", 7) == 0) {
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
#ifdef WOLFSSL_CERT_REQ
            if (in_file == NULL && key_file == NULL) {
                printf("Missing keypair or request filename\n");
                return 1;
            } else if (key_file == NULL) {
                key_file = in_file;
            }
            if (load_key_p8(&keyPtr, key_file, -1) < 0) {
                printf("Error loading keypair\n");
                return -1;
            }
            if (altkey_file) {
                if (load_key_p8(&altKeyPtr, altkey_file, -1) < 0) {
                    printf("Error loading alt keypair\n");
                    return -1;
                }
            }
            if (gen_csr(keyPtr, altKeyPtr, out_file, out_format, subject_dn) < 0) {
                return -1;
            }
            return 0;
#else
            printf("CSR generation not supported\n");
            return 1;
#endif
        } break;

        // Sign CERT
        case 2: {
#if defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_REQ)
            if (in_file == NULL && key_file == NULL) {
                printf("Missing keypair or request filename\n");
                return 1;
            }
            if (load_key_p8(&keyPtr, key_file, -1) < 0) {
                printf("Error loading keypair\n");
                return -1;
            }

            if (altkey_file) {
                if (load_key_p8(&altKeyPtr, altkey_file, -1) < 0) {
                    printf("Error loading alt keypair\n");
                    return -1;
                }
            }

            if (sign_cert(csr_file, out_file, out_format, ca_file, in_format, 
                          subject_dn, templateId, keyPtr, altKeyPtr) < 0) {
                printf("Error generating certificate\n");
                return -1;
            }
            return 0;
#else
            printf("Certificate signing not supported\n");
            return 1;
#endif
        } break;

        default:
            return -1;
    }

    (void)in_format;
    (void)ca_file;
    (void)csr_file;

#endif
    (void)argv;
    (void)argc;

    return 0;
}