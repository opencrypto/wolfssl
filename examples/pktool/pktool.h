/* wc_pktool.h */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/asn.h>

#include <wolfssl/wolfcrypt/dsa.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/falcon.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/ed448.h>

#include <wolfssl/wolfcrypt/mldsa_composite.h>
#include <wolfssl/wolfcrypt/asymkey.h>

#include <wolfssl/wolfcrypt/types.h>

#include <wolfssl/ssl.h>

// ===================
// Function Prototypes
// ===================

void usage(void);

void templates(void);

int export_key_p8(AsymKey * key, const char * out_file, int format);

int load_file(byte ** data, int *len, const char * filename);

int load_key_p8(AsymKey ** key, const char * key_file, int format);

int gen_keypair(AsymKey ** key, int type, int param);

int gen_csr(const AsymKey * key, const AsymKey * altkey, 
            const char * out_filename, int out_format, const char * subject_dn,
            enum wc_HashType hashType);

int sign_cert(const char * req_file, const char * outCertFilename, int outCertFormat, 
              const char * caCertFilename, int caCertFormat, const char * subject_dn, int templateId,
              enum wc_HashType hashType, const AsymKey * caKeyPair, const AsymKey * caAltKeyPair);

