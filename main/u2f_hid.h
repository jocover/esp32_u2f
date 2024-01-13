#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "u2f.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/ringbuf.h"
#include "freertos/semphr.h"

//typedef struct U2fHid U2fHid;

#define HID_U2F_PACKET_LEN 64
#define U2F_HID_MAX_PAYLOAD_LEN ((HID_U2F_PACKET_LEN - 7) + 128 * (HID_U2F_PACKET_LEN - 5))

struct U2fHid_packet
{
    uint32_t cid;
    uint16_t len;
    uint8_t cmd;
    uint8_t payload[U2F_HID_MAX_PAYLOAD_LEN];
};

typedef struct
{
    // FuriThread *thread;
    // FuriTimer *lock_timer;
    //TaskHandle_t thread;
    QueueHandle_t hid_queue;
   // RingbufHandle_t hid_recvbuf;

    uint8_t seq_id_last;
    uint16_t req_buf_ptr;
    uint32_t req_len_left;
    uint32_t lock_cid;
    bool lock;
    U2fData *u2f_instance;
    struct U2fHid_packet packet;
}U2fHid;

void u2f_hid_init(U2fHid *u2f_hid,U2fData *u2f_inst);

void u2f_hid_stop(U2fHid* u2f_hid);

void u2f_hid_recv_data(U2fHid* u2f_hid,uint8_t const* data,uint16_t len);

void u2f_task(U2fHid* u2f_hid);

#ifdef __cplusplus
}
#endif