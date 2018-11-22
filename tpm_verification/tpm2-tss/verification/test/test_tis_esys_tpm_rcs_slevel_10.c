/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG All
 * rights reserved.
 ******************************************************************************/

#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <setjmp.h>
//#include <cmocka.h>

#include "tss2_esys.h"

#include "tss2-esys/esys_iutil.h"
#define LOGMODULE tests
#include "util/aux_util.h"
#include "util/log.h"

#include <limits.h>
#include <tis_builtin.h>
/**
 * This unit test looks into a set of Esys_<cmd>() functions and tests the
 * resubmission behaviour. The ESAPI is expected to resubmit a command for a
 * certain number of times if the TPM return RC_YIELDED. After this number of
 * times, the ESAPI shall not try it any further but return the TPM's error.
 * For all these resubmissions the command must be the same as before.
 * This shall be extended to cover all functions at some point.
 */

#define TCTI_TPMERROR_MAGIC 0x5441455252000000ULL /* 'TAERR\0' */
#define TCTI_TPMERROR_VERSION 0x1

/*
 * Esys handles for dummy session and key objects, and initialization values for
 * other objects, which can be used in ESAPI test calls
 */
#define DUMMY_TR_HANDLE_POLICY_SESSION ESYS_TR_MIN_OBJECT
#define DUMMY_TR_HANDLE_KEY ESYS_TR_MIN_OBJECT + 1
#define DUMMY_TR_HANDLE_NV_INDEX ESYS_TR_MIN_OBJECT + 2
#define DUMMY_TR_HANDLE_HIERARCHY_OWNER ESYS_TR_MIN_OBJECT + 3
#define DUMMY_TR_HANDLE_HIERARCHY_PLATFORM ESYS_TR_MIN_OBJECT + 4
#define DUMMY_TR_HANDLE_PRIVACY_ADMIN ESYS_TR_MIN_OBJECT + 5
#define DUMMY_TR_HANDLE_HMAC_SESSION ESYS_TR_MIN_OBJECT + 6
#define DUMMY_TR_HANDLE_LOCKOUT ESYS_TR_MIN_OBJECT + 7
#define DUMMY_IN_PUBLIC_DATA                                                                                        \
    {                                                                                                               \
        .size = 0,                                                                                                  \
        .publicArea = {                                                                                             \
            .type = TPM2_ALG_ECC,                                                                                   \
            .nameAlg = TPM2_ALG_SHA256,                                                                             \
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_SIGN_ENCRYPT |     \
                                 TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN), \
            .authPolicy =                                                                                           \
                {                                                                                                   \
                    .size = 0,                                                                                      \
                },                                                                                                  \
            .parameters.eccDetail = {.symmetric =                                                                   \
                                         {                                                                          \
                                             .algorithm = TPM2_ALG_NULL,                                            \
                                             .keyBits.aes = 128,                                                    \
                                             .mode.aes = TPM2_ALG_ECB,                                              \
                                         },                                                                         \
                                     .scheme =                                                                      \
                                         {                                                                          \
                                             .scheme = TPM2_ALG_ECDSA,                                              \
                                             .details = {.ecdsa = {.hashAlg = TPM2_ALG_SHA256}},                    \
                                         },                                                                         \
                                     .curveID = TPM2_ECC_NIST_P256,                                                 \
                                     .kdf = {.scheme = TPM2_ALG_NULL, .details = {}}},                              \
            .unique.ecc =                                                                                           \
                {                                                                                                   \
                    .x = {.size = 0, .buffer = {}},                                                                 \
                    .y = {.size = 0, .buffer = {}},                                                                 \
                },                                                                                                  \
        },                                                                                                          \
    }

#define DUMMY_TPMT_PUBLIC_PARAMS                                        \
    {                                                                   \
        .type = TPM2_ALG_ECC, .parameters.eccDetail = {                 \
            .symmetric =                                                \
                {                                                       \
                    .algorithm = TPM2_ALG_NULL,                         \
                    .keyBits.aes = 128,                                 \
                    .mode.aes = TPM2_ALG_ECB,                           \
                },                                                      \
            .scheme =                                                   \
                {                                                       \
                    .scheme = TPM2_ALG_ECDSA,                           \
                    .details = {.ecdsa = {.hashAlg = TPM2_ALG_SHA256}}, \
                },                                                      \
            .curveID = TPM2_ECC_NIST_P256,                              \
            .kdf = {.scheme = TPM2_ALG_NULL, .details = {}}             \
        }                                                               \
    }

#define DUMMY_2B_DATA(NAME)       \
    {                             \
        .size = 20, NAME = { 1,   \
                             2,   \
                             3,   \
                             4,   \
                             5,   \
                             6,   \
                             7,   \
                             8,   \
                             9,   \
                             10,  \
                             11,  \
                             12,  \
                             13,  \
                             14,  \
                             15,  \
                             16,  \
                             17,  \
                             18,  \
                             19,  \
                             20 } \
    }

#define DUMMY_2B_DATA16(NAME)     \
    {                             \
        .size = 16, NAME = { 1,   \
                             2,   \
                             3,   \
                             4,   \
                             5,   \
                             6,   \
                             7,   \
                             8,   \
                             9,   \
                             10,  \
                             11,  \
                             12,  \
                             13,  \
                             14,  \
                             15,  \
                             16 } \
    }

#define DUMMY_2B_DATA0 \
    { .size = 0, .buffer = {}, }

#define DUMMY_SYMMETRIC                                                                    \
    {                                                                                      \
        .algorithm = TPM2_ALG_AES, .keyBits = {.aes = 128}, .mode = {.aes = TPM2_ALG_CFB } \
    }

#define DUMMY_TPMT_TK_AUTH                                                      \
    {                                                                           \
        .tag = TPM2_ST_AUTH_SIGNED, .hierarchy = TPM2_RH_OWNER, .digest = { 0 } \
    }

#define DUMMY_TPMT_TK_CREATION                                               \
    {                                                                        \
        .tag = TPM2_ST_CREATION, .hierarchy = TPM2_RH_OWNER, .digest = { 0 } \
    }

#define DUMMY_TPMT_TK_VERIFIED                                               \
    {                                                                        \
        .tag = TPM2_ST_VERIFIED, .hierarchy = TPM2_RH_OWNER, .digest = { 0 } \
    }

#define DUMMY_TPMT_TK_HASHCHECK                                               \
    {                                                                         \
        .tag = TPM2_ST_HASHCHECK, .hierarchy = TPM2_RH_OWNER, .digest = { 0 } \
    }

#define DUMMY_RSA_DECRYPT \
    { .scheme = TPM2_ALG_NULL }

#define DUMMY_TPMT_SIGNATURE {.sigAlg = TPM2_ALG_RSAPSS, .signature = {.rsapss = {.hash = TPM2_ALG_SHA1, .sig = {0}}}};

typedef struct {
    uint64_t magic;
    uint32_t version;
    TSS2_TCTI_TRANSMIT_FCN transmit;
    TSS2_TCTI_RECEIVE_FCN receive;
    TSS2_RC (*finalize)
    (TSS2_TCTI_CONTEXT *tctiContext);
    TSS2_RC (*cancel)
    (TSS2_TCTI_CONTEXT *tctiContext);
    TSS2_RC (*getPollHandles)
    (TSS2_TCTI_CONTEXT *tctiContext, TSS2_TCTI_POLL_HANDLE *handles, size_t *num_handles);
    TSS2_RC (*setLocality)
    (TSS2_TCTI_CONTEXT *tctiContext, uint8_t locality);
} TSS2_TCTI_CONTEXT_TPMERROR;

static TSS2_RC tcti_tpmerror_transmit(TSS2_TCTI_CONTEXT *tctiContext, size_t size, const uint8_t *buffer) {
    (void)(tctiContext);
    (void)(size);
    (void)(buffer);

    return TSS2_RC_SUCCESS;
}

const uint8_t response[] = {
    0x80, 0x01,             /* TPM_ST_NO_SESSION */
    0x00, 0x00, 0x00, 0x0A, /* Response Size 10 */
    0x00, 0x00, 0x0F, 0xFF  /* TPM_RC_TODO */
};

static TSS2_RC tcti_tpmerror_receive(TSS2_TCTI_CONTEXT *tctiContext, size_t *response_size, uint8_t *response_buffer,
                                     int32_t timeout) {
    (void)(tctiContext);
    (void)timeout;

    *response_size = sizeof(response);
    if (response_buffer != NULL) memcpy(response_buffer, &response[0], sizeof(response));

    return TSS2_RC_SUCCESS;
}

static void tcti_tpmerror_finalize(TSS2_TCTI_CONTEXT *tctiContext) { (void)(tctiContext); }

static TSS2_RC tcti_tpmerror_initialize(TSS2_TCTI_CONTEXT *tctiContext, size_t *contextSize) {
    TSS2_TCTI_CONTEXT_TPMERROR *tcti_tpmerror = (TSS2_TCTI_CONTEXT_TPMERROR *)tctiContext;

    if (tctiContext == NULL && contextSize == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    } else if (tctiContext == NULL) {
        *contextSize = sizeof(*tcti_tpmerror);
        return TSS2_RC_SUCCESS;
    }

    /* Init TCTI context */
    memset(tcti_tpmerror, 0, sizeof(*tcti_tpmerror));
    TSS2_TCTI_MAGIC(tctiContext) = TCTI_TPMERROR_MAGIC;
    TSS2_TCTI_VERSION(tctiContext) = TCTI_TPMERROR_VERSION;
    TSS2_TCTI_TRANSMIT(tctiContext) = tcti_tpmerror_transmit;
    TSS2_TCTI_RECEIVE(tctiContext) = tcti_tpmerror_receive;
    TSS2_TCTI_FINALIZE(tctiContext) = tcti_tpmerror_finalize;
    TSS2_TCTI_CANCEL(tctiContext) = NULL;
    TSS2_TCTI_GET_POLL_HANDLES(tctiContext) = NULL;
    TSS2_TCTI_SET_LOCALITY(tctiContext) = NULL;

    return TSS2_RC_SUCCESS;
}


int tis_test_setup(void **state) {
    TSS2_RC r;
    ESYS_CONTEXT *ectx;
    size_t size = sizeof(TSS2_TCTI_CONTEXT_TPMERROR);
    TSS2_TCTI_CONTEXT *tcti = malloc(size);
    ESYS_TR objectHandle;
    RSRC_NODE_T *objectHandleNode = NULL;

    r = tcti_tpmerror_initialize(tcti, &size);
    if (r) return (int)r;
    r = Esys_Initialize(&ectx, tcti, NULL);
    if (r) return (int)r;

    /* Create dummy object to enable usage of SAPI prepare functions in the tests */
    objectHandle = DUMMY_TR_HANDLE_POLICY_SESSION;
    r = esys_CreateResourceObject(ectx, objectHandle, &objectHandleNode);
    if (r) return (int)r;
    objectHandleNode->rsrc.rsrcType = IESYSC_SESSION_RSRC;
    objectHandleNode->rsrc.handle = TPM2_POLICY_SESSION_FIRST;

    objectHandle = DUMMY_TR_HANDLE_HMAC_SESSION;
    r = esys_CreateResourceObject(ectx, objectHandle, &objectHandleNode);
    if (r) return (int)r;
    objectHandleNode->rsrc.rsrcType = IESYSC_SESSION_RSRC;
    objectHandleNode->rsrc.handle = TPM2_HMAC_SESSION_FIRST;

    objectHandle = DUMMY_TR_HANDLE_KEY;
    r = esys_CreateResourceObject(ectx, objectHandle, &objectHandleNode);
    if (r) return (int)r;
    objectHandleNode->rsrc.rsrcType = IESYSC_KEY_RSRC;
    objectHandleNode->rsrc.handle = TPM2_TRANSIENT_FIRST;

    objectHandle = DUMMY_TR_HANDLE_HIERARCHY_OWNER;
    r = esys_CreateResourceObject(ectx, objectHandle, &objectHandleNode);
    if (r) return (int)r;
    objectHandleNode->rsrc.rsrcType = IESYSC_WITHOUT_MISC_RSRC;
    objectHandleNode->rsrc.handle = TPM2_RH_OWNER;

    objectHandle = DUMMY_TR_HANDLE_HIERARCHY_PLATFORM;
    r = esys_CreateResourceObject(ectx, objectHandle, &objectHandleNode);
    if (r) return (int)r;
    objectHandleNode->rsrc.rsrcType = IESYSC_WITHOUT_MISC_RSRC;
    objectHandleNode->rsrc.handle = TPM2_RH_PLATFORM;

    objectHandle = DUMMY_TR_HANDLE_LOCKOUT;
    r = esys_CreateResourceObject(ectx, objectHandle, &objectHandleNode);
    if (r) return (int)r;
    objectHandleNode->rsrc.rsrcType = IESYSC_WITHOUT_MISC_RSRC;
    objectHandleNode->rsrc.handle = TPM2_RH_LOCKOUT;

    objectHandle = DUMMY_TR_HANDLE_NV_INDEX;
    r = esys_CreateResourceObject(ectx, objectHandle, &objectHandleNode);
    if (r) return (int)r;
    objectHandleNode->rsrc.rsrcType = IESYSC_WITHOUT_MISC_RSRC;
    objectHandleNode->rsrc.handle = TPM2_NV_INDEX_FIRST;

    objectHandle = DUMMY_TR_HANDLE_PRIVACY_ADMIN;
    r = esys_CreateResourceObject(ectx, objectHandle, &objectHandleNode);
    if (r) return (int)r;
    objectHandleNode->rsrc.rsrcType = IESYSC_WITHOUT_MISC_RSRC;
    objectHandleNode->rsrc.handle = TPM2_RH_ENDORSEMENT;

    *state = (void *)ectx;
    return 0;
}

void tis_test_shutdown() {}

void tis_test_Startup(void **state) {
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *)*state;
    Esys_GetTcti(esys_context, &tcti);

    TPM2_SU startupType = TPM2_SU_CLEAR;
    Esys_Startup(esys_context, startupType);
}

/*
    struct ESYS_CONTEXT {
        enum _ESYS_STATE state ;
        TSS2_SYS_CONTEXT *sys ;
        ESYS_TR esys_handle_cnt ;
        RSRC_NODE_T *rsrc_list ;
        int32_t timeout ;
        ESYS_TR session_type[3] ;
        RSRC_NODE_T *session_tab[3] ;
        int encryptNonceIdx ;
        TPM2B_NONCE *encryptNonce ;
        int authsCount ;
        int submissionCount ;
        TPM2B_DATA salt ;
        IESYS_CMD_IN_PARAM in ;
        ESYS_TR esys_handle ;
        TSS2_TCTI_CONTEXT *tcti_app_param ;
        void *dlhandle ;
        };
    */
// typedef struct RSRC_NODE_T
// {
//     ESYS_TR esys_handle;      /**< The ESYS_TR handle used by the application
//                                  to reference this entry. */
//     TPM2B_AUTH auth;          /**< The authValue for this resource object. */
//     IESYS_RESOURCE rsrc;      /**< The meta data for this resource object. */
//     struct RSRC_NODE_T *next; /**< The next object in the linked list. */
// } RSRC_NODE_T;
// typedef struct {
//     UINT16 size;
//     BYTE buffer[sizeof(TPMU_HA)];
// }
// TPM2B_DIGEST;  // TPM2B_AUTH
// typedef struct
// {
//     TPM2_HANDLE handle;            /**< Handle used by TPM */
//     TPM2B_NAME name;               /**< TPM name of the object */
//     IESYSC_RESOURCE_TYPE rsrcType; /**< Selector for resource type */
//     IESYS_RSRC_UNION misc;         /**< Resource specific information */
// } IESYS_RESOURCE;

void helper_init_esys_context(ESYS_CONTEXT *esys_context) {
    esys_context->timeout = tis_interval(0, INT32_MAX);
    esys_context->state = tis_interval_split(_ESYS_STATE_INIT, _ESYS_STATE_INTERNALERROR);
    for (int i = 0; i < 3; ++i) {
        esys_context->session_tab[i] = malloc(sizeof(RSRC_NODE_T));
        esys_context->session_tab[i]->esys_handle = tis_unsigned_int_interval(0, UINT32_MAX);
        esys_context->session_tab[i]->auth.size = tis_unsigned_short_interval(0, UINT16_MAX);
        esys_context->session_tab[i]->rsrc.handle = tis_unsigned_int_interval(0, UINT32_MAX);
        
        for (int j = 0; j < sizeof(TPMU_HA); ++j) {
            esys_context->session_tab[i]->auth.buffer[j] = tis_unsigned_char_interval(0, UCHAR_MAX);
        }
        esys_context->session_tab[i]->rsrc.misc.rsrc_session.sessionType = tis_int_interval(0, INT_MAX);
        for (int j = 0; j < 2 * sizeof(TPMU_HA); ++j) {
            esys_context->session_tab[i]->rsrc.misc.rsrc_session.sessionValue[j] =
                tis_unsigned_char_interval(0, UCHAR_MAX);
        }
        esys_context->session_tab[i]->rsrc.misc.rsrc_session.sessionAttributes =
            tis_interval_split(0x20, 0x40);  // tis_unsigned_char_interval(0, UCHAR_MAX);
        esys_context->session_tab[i]->rsrc.misc.rsrc_session.authHash = tis_unsigned_short_interval(0, UINT16_MAX);
        esys_context->session_tab[i]->rsrc.misc.rsrc_session.type_policy_session = tis_int_interval(NO_POLICY_AUTH, POLICY_PASSWORD);

        esys_context->session_tab[i]->rsrc.misc.rsrc_session.nonceTPM.size = tis_unsigned_short_interval(0, UINT16_MAX);
        for (int j = 0; j < 2 * sizeof(TPMU_HA); ++j) {
            esys_context->session_tab[i]->rsrc.misc.rsrc_session.nonceTPM.buffer[j] =
                tis_unsigned_char_interval(0, UCHAR_MAX);
        }
    }
}

void tis_test_SelfTest(void **state) {
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *)*state;
    Esys_GetTcti(esys_context, &tcti);
    // do not malloc a new one, use the initialized one above and just modify(or initialized) with a tis_xxx one.
    helper_init_esys_context(esys_context);
    Esys_SelfTest(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, 0);
}

void tis_test_IncrementalSelfTest(void **state) {
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *)*state;
    Esys_GetTcti(esys_context, &tcti);

    TPML_ALG toTest = {0};
    TPML_ALG *toDoList = {0};
    Esys_IncrementalSelfTest(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &toTest, &toDoList);
}

void tis_test_GetTestResult(void **state) {
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    TPM2B_MAX_BUFFER *outData;
    TPM2_RC testResult;
    Esys_GetTestResult(esys_context,
                           ESYS_TR_NONE,
                           ESYS_TR_NONE, ESYS_TR_NONE, &outData, &testResult);
}

void tis_test_StartAuthSession(void **state)
{
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    ESYS_TR tpmKey_handle = ESYS_TR_NONE;
    ESYS_TR bind_handle = ESYS_TR_NONE;
    TPM2B_NONCE nonceCaller = DUMMY_2B_DATA(.buffer);
    TPM2_SE sessionType = TPM2_SE_HMAC;
    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_AES,
        .keyBits = {.aes = 128},
        .mode = {.aes = TPM2_ALG_CFB}
    };
    TPMI_ALG_HASH authHash = TPM2_ALG_SHA1;
    ESYS_TR sessionHandle_handle;

    Esys_StartAuthSession(esys_context,
                              tpmKey_handle,
                              bind_handle,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE,
                              &nonceCaller,
                              sessionType,
                              &symmetric,
                              authHash, &sessionHandle_handle);
}

void tis_test_PolicyRestart(void **state)
{
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    r = Esys_PolicyRestart(esys_context,
                           DUMMY_TR_HANDLE_POLICY_SESSION,
                           ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE);

}

void tis_test_Create(void **state)
{
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);
    TPM2B_SENSITIVE_CREATE inSensitive = { 0 };
    //TPM2B_PUBLIC inPublic = DUMMY_IN_PUBLIC_DATA;
////// init inPulbic
    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                .size = 0,
            },
        },
    };
    // union defination
    TPMS_ECC_PARMS eccDetail = {.symmetric = {
                                    .algorithm = TPM2_ALG_NULL,
                                    .keyBits.aes = 128,
                                    .mode.aes = TPM2_ALG_ECB,
                                },
                                .scheme = {
                                    .scheme = TPM2_ALG_ECDSA,
                                    //.details = {.ecdsa = {.hashAlg = TPM2_ALG_SHA256}},
                                },
                                .curveID = TPM2_ECC_NIST_P256,
                                .kdf = {.scheme = TPM2_ALG_NULL},
                                };
    // union defination
    TPMU_ASYM_SCHEME details = {.ecdsa = {.hashAlg = TPM2_ALG_SHA256}};
    eccDetail.scheme.details = details;

    inPublic.publicArea.parameters.eccDetail = eccDetail;

    TPMS_ECC_POINT ecc = {
        .x = {.size = 0, .buffer = {}},
        .y = {.size = 0, .buffer = {}},
    };
    inPublic.publicArea.unique.ecc = ecc; 
//////

    TPM2B_DATA outsideInfo = DUMMY_2B_DATA0;
    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };
    TPM2B_PRIVATE *outPrivate;
    TPM2B_PUBLIC *outPublic;
    TPM2B_CREATION_DATA *creationData;
    TPM2B_DIGEST *creationHash;
    TPMT_TK_CREATION *creationTicket;

    Esys_Create(esys_context,
                    DUMMY_TR_HANDLE_KEY,
                    ESYS_TR_PASSWORD,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    &inSensitive,
                    &inPublic,
                    &outsideInfo,
                    &creationPCR,
                    &outPrivate,
                    &outPublic, &creationData, &creationHash, &creationTicket);
}

void tis_test_Load(void **state) {
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    TPM2B_PRIVATE inPrivate = DUMMY_2B_DATA(.buffer);
    //TPM2B_PUBLIC inPublic = DUMMY_IN_PUBLIC_DATA;
    ////// init inPulbic
    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                .size = 0,
            },
        },
    };
    // union defination
    TPMS_ECC_PARMS eccDetail = {
        .symmetric = {
            .algorithm = TPM2_ALG_NULL,
            .keyBits.aes = 128,
            .mode.aes = TPM2_ALG_ECB,
        },
        .scheme = {
            .scheme = TPM2_ALG_ECDSA,
            //.details = {.ecdsa = {.hashAlg = TPM2_ALG_SHA256}},
        },
        .curveID = TPM2_ECC_NIST_P256,
        .kdf = {.scheme = TPM2_ALG_NULL},
    };
    // union defination
    TPMU_ASYM_SCHEME details = {.ecdsa = {.hashAlg = TPM2_ALG_SHA256}};
    eccDetail.scheme.details = details;

    inPublic.publicArea.parameters.eccDetail = eccDetail;

    TPMS_ECC_POINT ecc = {
        .x = {.size = 0, .buffer = {}},
        .y = {.size = 0, .buffer = {}},
    };
    inPublic.publicArea.unique.ecc = ecc;
    //////

    ESYS_TR objectHandle_handle;
    Esys_Load(esys_context,
                  DUMMY_TR_HANDLE_KEY,
                  ESYS_TR_PASSWORD,
                  ESYS_TR_NONE,
                  ESYS_TR_NONE, &inPrivate, &inPublic, &objectHandle_handle);
}

void tis_test_LoadExternal(void **state) {
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    //TPM2B_PUBLIC inPublic = DUMMY_IN_PUBLIC_DATA;
    ////// init inPulbic
    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                .size = 0,
            },
        },
    };
    // union defination
    TPMS_ECC_PARMS eccDetail = {
        .symmetric = {
            .algorithm = TPM2_ALG_NULL,
            .keyBits.aes = 128,
            .mode.aes = TPM2_ALG_ECB,
        },
        .scheme = {
            .scheme = TPM2_ALG_ECDSA,
            //.details = {.ecdsa = {.hashAlg = TPM2_ALG_SHA256}},
        },
        .curveID = TPM2_ECC_NIST_P256,
        .kdf = {.scheme = TPM2_ALG_NULL},
    };
    // union defination
    TPMU_ASYM_SCHEME details = {.ecdsa = {.hashAlg = TPM2_ALG_SHA256}};
    eccDetail.scheme.details = details;

    inPublic.publicArea.parameters.eccDetail = eccDetail;

    TPMS_ECC_POINT ecc = {
        .x = {.size = 0, .buffer = {}},
        .y = {.size = 0, .buffer = {}},
    };
    inPublic.publicArea.unique.ecc = ecc;
    //////
    ESYS_TR objectHandle_handle;
    Esys_LoadExternal(esys_context,
                          ESYS_TR_NONE,
                          ESYS_TR_NONE,
                          ESYS_TR_NONE,
                          NULL, &inPublic, TPM2_RH_OWNER, &objectHandle_handle);
}

void tis_test_ReadPublic(void **state) {
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    ESYS_TR objectHandle_handle = DUMMY_TR_HANDLE_KEY;
    TPM2B_PUBLIC *outPublic;
    TPM2B_NAME *name;
    TPM2B_NAME *qualifiedName;
    Esys_ReadPublic(esys_context,
                        objectHandle_handle,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE, &outPublic, &name, &qualifiedName);
}

void tis_test_ActivateCredential(void **state) {
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    ESYS_TR activateHandle_handle = DUMMY_TR_HANDLE_KEY;
    ESYS_TR keyHandle_handle = DUMMY_TR_HANDLE_KEY;
    TPM2B_ID_OBJECT credentialBlob = DUMMY_2B_DATA(.credential);
    TPM2B_ENCRYPTED_SECRET secret = DUMMY_2B_DATA(.secret);;
    TPM2B_DIGEST *certInfo;
    Esys_ActivateCredential(esys_context,
                                activateHandle_handle,
                                keyHandle_handle,
                                ESYS_TR_PASSWORD,
                                ESYS_TR_PASSWORD,
                                ESYS_TR_NONE,
                                &credentialBlob, &secret, &certInfo);
}

void tis_test_MakeCredential(void **state)
{
    //TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    ESYS_TR handle_handle = ESYS_TR_NONE;
    TPM2B_DIGEST credential = DUMMY_2B_DATA(.buffer);
    TPM2B_NAME objectName = DUMMY_2B_DATA(.name);;
    TPM2B_ID_OBJECT *credentialBlob;
    TPM2B_ENCRYPTED_SECRET *secret;
    Esys_MakeCredential(esys_context,
                            handle_handle,
                            ESYS_TR_NONE,
                            ESYS_TR_NONE,
                            ESYS_TR_NONE,
                            &credential, &objectName, &credentialBlob, &secret);
}

void tis_test_Unseal(void **state) {
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    ESYS_TR itemHandle_handle = DUMMY_TR_HANDLE_KEY;
    TPM2B_SENSITIVE_DATA *outData;
    Esys_Unseal(esys_context,
                    itemHandle_handle,
                    ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &outData);
}

void tis_test_ObjectChangeAuth(void **state) {
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    ESYS_TR objectHandle_handle = DUMMY_TR_HANDLE_KEY;
    ESYS_TR parentHandle_handle = DUMMY_TR_HANDLE_KEY;
    TPM2B_AUTH newAuth = DUMMY_2B_DATA(.buffer);
    TPM2B_PRIVATE *outPrivate;
    Esys_ObjectChangeAuth(esys_context,
                              objectHandle_handle,
                              parentHandle_handle,
                              ESYS_TR_PASSWORD,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE, &newAuth, &outPrivate);
}

void tis_test_Duplicate(void **state) {
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    ESYS_TR objectHandle_handle = DUMMY_TR_HANDLE_KEY;
    ESYS_TR newParentHandle_handle = DUMMY_TR_HANDLE_KEY;
    TPM2B_DATA encryptionKeyIn = DUMMY_2B_DATA(.buffer);
    TPMT_SYM_DEF_OBJECT symmetricAlg = DUMMY_SYMMETRIC;
    TPM2B_DATA *encryptionKeyOut;
    TPM2B_PRIVATE *duplicate;
    TPM2B_ENCRYPTED_SECRET *outSymSeed;
    Esys_Duplicate(esys_context,
                       objectHandle_handle,
                       newParentHandle_handle,
                       ESYS_TR_PASSWORD,
                       ESYS_TR_NONE,
                       ESYS_TR_NONE,
                       &encryptionKeyIn,
                       &symmetricAlg,
                       &encryptionKeyOut, &duplicate, &outSymSeed);
}

void tis_test_Rewrap(void **state) {
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    ESYS_TR oldParent_handle = DUMMY_TR_HANDLE_KEY;
    ESYS_TR newParent_handle = DUMMY_TR_HANDLE_KEY;
    TPM2B_PRIVATE inDuplicate = DUMMY_2B_DATA(.buffer);
    TPM2B_NAME name = DUMMY_2B_DATA(.name);
    TPM2B_ENCRYPTED_SECRET inSymSeed = DUMMY_2B_DATA(.secret);
    TPM2B_PRIVATE *outDuplicate;
    TPM2B_ENCRYPTED_SECRET *outSymSeed;
    Esys_Rewrap(esys_context,
                    oldParent_handle,
                    newParent_handle,
                    ESYS_TR_PASSWORD,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    &inDuplicate,
                    &name, &inSymSeed, &outDuplicate, &outSymSeed);
}

void tis_test_Import(void **state) {
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    ESYS_TR parentHandle_handle = DUMMY_TR_HANDLE_KEY;
    TPM2B_DATA encryptionKey = DUMMY_2B_DATA(.buffer);
    //TPM2B_PUBLIC objectPublic = DUMMY_IN_PUBLIC_DATA;
    ////// init inPulbic
    TPM2B_PUBLIC objectPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                .size = 0,
            },
        },
    };
    // union defination
    TPMS_ECC_PARMS eccDetail = {
        .symmetric = {
            .algorithm = TPM2_ALG_NULL,
            .keyBits.aes = 128,
            .mode.aes = TPM2_ALG_ECB,
        },
        .scheme = {
            .scheme = TPM2_ALG_ECDSA,
            //.details = {.ecdsa = {.hashAlg = TPM2_ALG_SHA256}},
        },
        .curveID = TPM2_ECC_NIST_P256,
        .kdf = {.scheme = TPM2_ALG_NULL},
    };
    // union defination
    TPMU_ASYM_SCHEME details = {.ecdsa = {.hashAlg = TPM2_ALG_SHA256}};
    eccDetail.scheme.details = details;

    objectPublic.publicArea.parameters.eccDetail = eccDetail;

    TPMS_ECC_POINT ecc = {
        .x = {.size = 0, .buffer = {}},
        .y = {.size = 0, .buffer = {}},
    };
    objectPublic.publicArea.unique.ecc = ecc;
    //////

    TPM2B_PRIVATE duplicate = DUMMY_2B_DATA(.buffer);
    TPM2B_ENCRYPTED_SECRET inSymSeed = DUMMY_2B_DATA(.secret);
    TPMT_SYM_DEF_OBJECT symmetricAlg = DUMMY_SYMMETRIC;
    TPM2B_PRIVATE *outPrivate;
    Esys_Import(esys_context,
                    parentHandle_handle,
                    ESYS_TR_PASSWORD,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    &encryptionKey,
                    &objectPublic,
                    &duplicate, &inSymSeed, &symmetricAlg, &outPrivate);
}

void
tis_test_RSA_Encrypt(void **state) {
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    ESYS_TR keyHandle_handle = DUMMY_TR_HANDLE_KEY;
    TPM2B_PUBLIC_KEY_RSA message = DUMMY_2B_DATA(.buffer);
    TPMT_RSA_DECRYPT inScheme = DUMMY_RSA_DECRYPT;
    TPM2B_DATA label = DUMMY_2B_DATA(.buffer);
    TPM2B_PUBLIC_KEY_RSA *outData;
    Esys_RSA_Encrypt(esys_context,
                         keyHandle_handle,
                         ESYS_TR_NONE,
                         ESYS_TR_NONE,
                         ESYS_TR_NONE, &message, &inScheme, &label, &outData);
}

void
tis_test_RSA_Decrypt(void **state)
{
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    ESYS_TR keyHandle_handle = DUMMY_TR_HANDLE_KEY;
    TPM2B_PUBLIC_KEY_RSA cipherText = DUMMY_2B_DATA(.buffer);
    TPMT_RSA_DECRYPT inScheme = DUMMY_RSA_DECRYPT;
    TPM2B_DATA label = DUMMY_2B_DATA(.buffer);
    TPM2B_PUBLIC_KEY_RSA *message;
    r = Esys_RSA_Decrypt(esys_context,
                         keyHandle_handle,
                         ESYS_TR_PASSWORD,
                         ESYS_TR_NONE,
                         ESYS_TR_NONE,
                         &cipherText, &inScheme, &label, &message);
}

void
tis_test_ECDH_KeyGen(void **state)
{
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    ESYS_TR keyHandle_handle = DUMMY_TR_HANDLE_KEY;
    TPM2B_ECC_POINT *zPoint;
    TPM2B_ECC_POINT *pubPoint;
    r = Esys_ECDH_KeyGen(esys_context,
                         keyHandle_handle,
                         ESYS_TR_NONE,
                         ESYS_TR_NONE, ESYS_TR_NONE, &zPoint, &pubPoint);

}

void
tis_test_ECDH_ZGen(void **state)
{
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    ESYS_TR keyHandle_handle = DUMMY_TR_HANDLE_KEY;
    TPM2B_ECC_POINT inPoint = { 0 };
    TPM2B_ECC_POINT *outPoint;
    r = Esys_ECDH_ZGen(esys_context,
                       keyHandle_handle,
                       ESYS_TR_PASSWORD,
                       ESYS_TR_NONE, ESYS_TR_NONE, &inPoint, &outPoint);
}

void
tis_test_ECC_Parameters(void **state)
{
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    TPMI_ECC_CURVE curveID = TPM2_ECC_BN_P256;
    TPMS_ALGORITHM_DETAIL_ECC *parameters;
    r = Esys_ECC_Parameters(esys_context,
                            ESYS_TR_NONE,
                            ESYS_TR_NONE, ESYS_TR_NONE, curveID, &parameters);
}

void
tis_test_ZGen_2Phase(void **state)
{
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    ESYS_TR keyA_handle = DUMMY_TR_HANDLE_KEY;
    TPM2B_ECC_POINT inQsB = { 0 };
    TPM2B_ECC_POINT inQeB = { 0 };
    TPMI_ECC_KEY_EXCHANGE inScheme = TPM2_ALG_NULL;
    UINT16 counter = 0;
    TPM2B_ECC_POINT *outZ1;
    TPM2B_ECC_POINT *outZ2;
    r = Esys_ZGen_2Phase(esys_context,
                         keyA_handle,
                         ESYS_TR_PASSWORD,
                         ESYS_TR_NONE,
                         ESYS_TR_NONE,
                         &inQsB, &inQeB, inScheme, counter, &outZ1, &outZ2);
}

void
tis_test_EncryptDecrypt(void **state)
{
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    ESYS_TR keyHandle_handle = DUMMY_TR_HANDLE_KEY;
    TPMI_YES_NO decrypt = 0;
    TPMI_ALG_SYM_MODE mode = TPM2_ALG_NULL;
    TPM2B_IV ivIn = DUMMY_2B_DATA16(.buffer);
    TPM2B_MAX_BUFFER inData = DUMMY_2B_DATA(.buffer);
    TPM2B_MAX_BUFFER *outData;
    TPM2B_IV *ivOut;
    r = Esys_EncryptDecrypt(esys_context,
                            keyHandle_handle,
                            ESYS_TR_PASSWORD,
                            ESYS_TR_NONE,
                            ESYS_TR_NONE,
                            decrypt, mode, &ivIn, &inData, &outData, &ivOut);
}

void
tis_test_EncryptDecrypt2(void **state)
{
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    ESYS_TR keyHandle_handle = DUMMY_TR_HANDLE_KEY;
    TPM2B_MAX_BUFFER inData = DUMMY_2B_DATA(.buffer);
    TPMI_YES_NO decrypt = 0;
    TPMI_ALG_SYM_MODE mode = TPM2_ALG_NULL;
    TPM2B_IV ivIn = DUMMY_2B_DATA16(.buffer);
    TPM2B_MAX_BUFFER *outData;
    TPM2B_IV *ivOut;
    r = Esys_EncryptDecrypt2(esys_context,
                             keyHandle_handle,
                             ESYS_TR_PASSWORD,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             &inData, decrypt, mode, &ivIn, &outData, &ivOut);
}

void
tis_test_Hash(void **state)
{
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    TPM2B_MAX_BUFFER data = DUMMY_2B_DATA(.buffer);
    TPMI_ALG_HASH hashAlg = TPM2_ALG_SHA1;
    TPMI_RH_HIERARCHY hierarchy = TPM2_RH_OWNER;
    TPM2B_DIGEST *outHash;
    TPMT_TK_HASHCHECK *validation;
    r = Esys_Hash(esys_context,
                  ESYS_TR_NONE,
                  ESYS_TR_NONE,
                  ESYS_TR_NONE,
                  &data, hashAlg, hierarchy, &outHash, &validation);
}

void
tis_test_HMAC(void **state)
{
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    ESYS_TR handle_handle = DUMMY_TR_HANDLE_KEY;
    TPM2B_MAX_BUFFER buffer = DUMMY_2B_DATA(.buffer);
    TPMI_ALG_HASH hashAlg = TPM2_ALG_SHA1;
    TPM2B_DIGEST *outHMAC;
    r = Esys_HMAC(esys_context,
                  handle_handle,
                  ESYS_TR_PASSWORD,
                  ESYS_TR_NONE, ESYS_TR_NONE, &buffer, hashAlg, &outHMAC);
}

void
tis_test_GetRandom(void **state)
{
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    UINT16 bytesRequested = 0;
    TPM2B_DIGEST *randomBytes;
    r = Esys_GetRandom(esys_context,
                       ESYS_TR_NONE,
                       ESYS_TR_NONE,
                       ESYS_TR_NONE, bytesRequested, &randomBytes);
}

void
tis_test_StirRandom(void **state)
{
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    TPM2B_SENSITIVE_DATA inData = DUMMY_2B_DATA(.buffer);
    r = Esys_StirRandom(esys_context,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &inData);
}

void tis_test_HMAC_Start(void **state) {
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    ESYS_TR handle_handle = DUMMY_TR_HANDLE_KEY;
    TPM2B_AUTH auth = DUMMY_2B_DATA(.buffer);
    TPMI_ALG_HASH hashAlg = TPM2_ALG_SHA1;
    ESYS_TR sequenceHandle_handle;
    r = Esys_HMAC_Start(esys_context,
                        handle_handle,
                        ESYS_TR_PASSWORD,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE, &auth, hashAlg, &sequenceHandle_handle);
}

void tis_test_HashSequenceStart(void **state) {
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    TPM2B_AUTH auth = DUMMY_2B_DATA(.buffer);
    TPMI_ALG_HASH hashAlg = TPM2_ALG_SHA1;
    ESYS_TR sequenceHandle_handle;
    r = Esys_HashSequenceStart(esys_context,
                               ESYS_TR_NONE,
                               ESYS_TR_NONE,
                               ESYS_TR_NONE,
                               &auth, hashAlg, &sequenceHandle_handle);
}

void tis_test_SequenceUpdate(void **state) {
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    ESYS_TR sequenceHandle_handle = DUMMY_TR_HANDLE_KEY;
    TPM2B_MAX_BUFFER buffer = DUMMY_2B_DATA(.buffer);
    r = Esys_SequenceUpdate(esys_context,
                            sequenceHandle_handle,
                            ESYS_TR_PASSWORD,
                            ESYS_TR_NONE, ESYS_TR_NONE, &buffer);
}

void tis_test_SequenceComplete(void **state) {
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    ESYS_TR sequenceHandle_handle = DUMMY_TR_HANDLE_KEY;
    TPM2B_MAX_BUFFER buffer = DUMMY_2B_DATA(.buffer);
    TPMI_RH_HIERARCHY hierarchy = TPM2_RH_OWNER;
    TPM2B_DIGEST *result;
    TPMT_TK_HASHCHECK *validation;
    r = Esys_SequenceComplete(esys_context,
                              sequenceHandle_handle,
                              ESYS_TR_PASSWORD,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE,
                              &buffer, hierarchy, &result, &validation);
}

void tis_test_EventSequenceComplete(void **state) {
    TSS2_RC r;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys_context = (ESYS_CONTEXT *) * state;
    Esys_GetTcti(esys_context, &tcti);

    ESYS_TR pcrHandle_handle = 16;
    ESYS_TR sequenceHandle_handle = DUMMY_TR_HANDLE_KEY;
    TPM2B_MAX_BUFFER buffer = DUMMY_2B_DATA(.buffer);
    TPML_DIGEST_VALUES *results;
    r = Esys_EventSequenceComplete(esys_context,
                                   pcrHandle_handle,
                                   sequenceHandle_handle,
                                   ESYS_TR_PASSWORD,
                                   ESYS_TR_PASSWORD,
                                   ESYS_TR_NONE, &buffer, &results);
}

int main(int argc, char **argv) {
    void *state = NULL;
    tis_test_setup(&state);
    tis_test_Startup(&state);
    
    tis_test_HMAC_Start(&state);
   
    return 0;
}
