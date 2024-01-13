#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <mbedtls/sha256.h>
#include <mbedtls/md.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/error.h>

typedef enum {
    U2fNotifyRegister,
    U2fNotifyAuth,
    U2fNotifyAuthSuccess,
    U2fNotifyWink,
    U2fNotifyConnect,
    U2fNotifyDisconnect,
    U2fNotifyError,
} U2fNotifyEvent;



typedef struct  {
    uint8_t device_key[0x20];
    uint8_t cert_key[0x20];
    uint32_t counter;
    bool ready;
    bool user_present;
    //U2fEvtCallback callback;
    void* context;
    mbedtls_ecp_group group;
}U2fData;

typedef void (*U2fEvtCallback)(U2fNotifyEvent evt, void* context);

bool u2f_init(U2fData* instance);

void u2f_free(U2fData* instance);

void u2f_set_event_callback(U2fData* instance, U2fEvtCallback callback, void* context);

void u2f_confirm_user_present(U2fData* instance);

uint16_t u2f_msg_parse(U2fData* instance, uint8_t* buf, uint16_t len);

void u2f_wink(U2fData* instance);

void u2f_set_state(U2fData* instance, uint8_t state);

#ifdef __cplusplus
}
#endif