//iesys_cryptogcry_hash_start

#include <stdarg.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include <setjmp.h>
//#include <cmocka.h>

#include "tss2_esys.h"
#include "esys_crypto.h"

#define LOGMODULE tests
#include "util/log.h"

#include <limits.h>
#include <tis_builtin.h>

#include <gcrypt.h>

typedef struct _IESYS_CRYPTO_CONTEXT
{
    enum
    {
        IESYS_CRYPTOGCRY_TYPE_HASH = 1,
        IESYS_CRYPTOGCRY_TYPE_HMAC,
    } type; /**< The type of context to hold; hash or hmac */
    union {
        struct
        {
            gcry_md_hd_t gcry_context;
            int gcry_hash_alg;
            size_t hash_len;
        } hash; /**< the state variables for a hash context */
        struct
        {
            gcry_mac_hd_t gcry_context;
            int gcry_hmac_alg;
            size_t hmac_len;
        } hmac; /**< the state variables for an hmac context */
    };
} IESYS_CRYPTOGCRY_CONTEXT;


void tis_iesys_crypto_hash_start() {
    IESYS_CRYPTO_CONTEXT_BLOB* context = NULL;
    context = tis_unsigned_long_interval(0, ULONG_MAX);
    TPM2_ALG_ID algId = tis_interval_split(0x4, 0xC); //TPM2_ALG_SHA384; //tis_nodet()
    iesys_crypto_hash_start(&context, algId);
}

void tis_iesys_crypto_hash_finish() {
    uint8_t buffer[10] = {0};
    size_t size = 0;
    IESYS_CRYPTOGCRY_CONTEXT *context = NULL;
// /* either of the following two is ok */
//     context = (IESYS_CRYPTOGCRY_CONTEXT *)malloc(sizeof(IESYS_CRYPTOGCRY_CONTEXT)); //tis_alloc(0x100); //tis_unsigned_long_interval(0, ULONG_MAX);
//     context->hash.gcry_context = tis_unsigned_long_interval(0, ULONG_MAX);
//     context->hash.gcry_hash_alg = tis_interval_split(0x4, 0xC);
//     context->hash.hash_len = tis_interval(0, INT_MAX);
//     context->type = tis_interval_split(IESYS_CRYPTOGCRY_TYPE_HASH, IESYS_CRYPTOGCRY_TYPE_HMAC);

//     // context = tis_alloc(sizeof(IESYS_CRYPTOGCRY_CONTEXT));
//     // tis_make_unknown(context, sizeof(IESYS_CRYPTOGCRY_CONTEXT));
// /**/

    TPM2_ALG_ID algId = tis_interval_split(0x4, 0xC);
    tis_make_unknown(buffer, sizeof(buffer));
    size = tis_unsigned_int_interval(0, UINT32_MAX);

    iesys_crypto_hash_start(&context, algId);
    iesys_crypto_hash_finish(&context, buffer, &size);
}

void tis_iesys_crypto_hash_update() {
    IESYS_CRYPTO_CONTEXT_BLOB *context = NULL;
    uint8_t buffer[10] = {0};
    context = tis_alloc(0x100); //tis_unsigned_long_interval(0, ULONG_MAX); 
    tis_make_unknown(buffer, sizeof(buffer));
    iesys_cryptogcry_hash_update(&context, buffer, sizeof(buffer));
}

void tis_iesys_crypto_hash_update2b() {
    IESYS_CRYPTOGCRY_CONTEXT *context = NULL;
    TPM2B tpm2b;
    context = malloc(sizeof(IESYS_CRYPTOGCRY_CONTEXT));
    // for (int i = 0; i < sizeof(IESYS_CRYPTOGCRY_CONTEXT); ++i) {
    //     *((char*)context + i) = tis_unsigned_char_interval(0, 0xff);
    // }
    context->hash.gcry_context = tis_unsigned_long_interval(0, ULONG_MAX);
    context->hash.gcry_hash_alg = tis_interval_split(0x4, 0xC);
    context->hash.hash_len = tis_interval(0, INT_MAX);
    context->type = tis_interval_split(IESYS_CRYPTOGCRY_TYPE_HASH, IESYS_CRYPTOGCRY_TYPE_HMAC);

    tis_make_unknown(&tpm2b, sizeof(tpm2b));
    iesys_crypto_hash_update2b(&context, &tpm2b);
}

void tis_iesys_crypto_hmac_start() {
    IESYS_CRYPTOGCRY_CONTEXT *context = NULL;
    context = malloc(sizeof(IESYS_CRYPTOGCRY_CONTEXT));
    // for (int i = 0; i < sizeof(IESYS_CRYPTOGCRY_CONTEXT); ++i) {
    //     *((char *)context + i) = tis_unsigned_char_interval(0, 0xff);
    // }
    context->hash.gcry_context = tis_unsigned_long_interval(0, ULONG_MAX);
    context->hash.gcry_hash_alg = tis_interval_split(0x4, 0xC);
    context->hash.hash_len = tis_interval(0, INT_MAX);
    context->type = tis_interval_split(IESYS_CRYPTOGCRY_TYPE_HASH, IESYS_CRYPTOGCRY_TYPE_HMAC);

    uint8_t buffer[10] = {0};
    for(int i=0; i<sizeof(buffer); ++i) {
        buffer[i] = tis_unsigned_char_interval(0, 0xff);
    }

    int algId = tis_interval_split(0x4, 0xC);

    iesys_crypto_hmac_start(&context, algId, &buffer[0], sizeof(buffer));
}

int main(int argc, char **argv) {
    //tis_iesys_crypto_hash_start();
    tis_iesys_crypto_hash_finish();
    //tis_iesys_crypto_hash_update();
    return 0;
}

