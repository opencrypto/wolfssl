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

#include <wolfssl/ssl.h>

// ===================
// Function Prototypes
// ===================

void usage(void);

int wc_PKCS8_info(byte * p8_data, word32 p8_dataSz, word32 * oid);

int export_key_p8(void * key, int type, const char * out_file, int format);

int load_key_p8(void ** key, int type, const char * key_file, int format);

int gen_keypair(void ** key, int type, int param, const char * out_file);

int gen_csr(const void * key, const void * altkey, const char * out_filename, int out_format);