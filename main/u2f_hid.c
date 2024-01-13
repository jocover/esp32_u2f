#include "u2f_hid.h"
#include "u2f.h"
#include <stdlib.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/ringbuf.h"
#include "tusb.h"
#include "esp_random.h"

#define TAG "U2fHid"
#define WORKER_TAG TAG "Worker"

#define U2F_HID_TYPE_MASK 0x80 // Frame type mask
#define U2F_HID_TYPE_INIT 0x80 // Initial frame identifier
#define U2F_HID_TYPE_CONT 0x00 // Continuation frame identifier

#define U2F_HID_PING (U2F_HID_TYPE_INIT | 0x01)  // Echo data through local processor only
#define U2F_HID_MSG (U2F_HID_TYPE_INIT | 0x03)   // Send U2F message frame
#define U2F_HID_LOCK (U2F_HID_TYPE_INIT | 0x04)  // Send lock channel command
#define U2F_HID_INIT (U2F_HID_TYPE_INIT | 0x06)  // Channel initialization
#define U2F_HID_WINK (U2F_HID_TYPE_INIT | 0x08)  // Send device identification wink
#define U2F_HID_ERROR (U2F_HID_TYPE_INIT | 0x3f) // Error response

#define U2F_HID_ERR_NONE 0x00          // No error
#define U2F_HID_ERR_INVALID_CMD 0x01   // Invalid command
#define U2F_HID_ERR_INVALID_PAR 0x02   // Invalid parameter
#define U2F_HID_ERR_INVALID_LEN 0x03   // Invalid message length
#define U2F_HID_ERR_INVALID_SEQ 0x04   // Invalid message sequencing
#define U2F_HID_ERR_MSG_TIMEOUT 0x05   // Message has timed out
#define U2F_HID_ERR_CHANNEL_BUSY 0x06  // Channel busy
#define U2F_HID_ERR_LOCK_REQUIRED 0x0a // Command requires channel lock
#define U2F_HID_ERR_SYNC_FAIL 0x0b     // SYNC command failed
#define U2F_HID_ERR_OTHER 0x7f         // Other unspecified error

#define U2F_HID_BROADCAST_CID 0xFFFFFFFF

typedef enum
{
    WorkerEvtReserved = (1 << 0),
    WorkerEvtStop = (1 << 1),
    WorkerEvtConnect = (1 << 2),
    WorkerEvtDisconnect = (1 << 3),
    WorkerEvtRequest = (1 << 4),
    WorkerEvtUnlock = (1 << 5),
} WorkerEvtFlags;

static SemaphoreHandle_t u2f_hid_tx_requested = NULL;
static SemaphoreHandle_t u2f_hid_tx_done = NULL;

void tud_hid_report_complete_cb(uint8_t instance, uint8_t const *report, /*uint16_t*/ uint8_t len)
{

    if (xSemaphoreTake(u2f_hid_tx_requested, 0) != pdTRUE)
    {
        /* Semaphore should have been given before write attempt.
            Sometimes tinyusb can send one more cb even xfer_complete len is zero
        */
        return;
    }

    xSemaphoreGive(u2f_hid_tx_done);

    // uint8_t seq = report[4] & 0x80 ? 0 : report[4] + 1;
    // ESP_LOGI(TAG, "tud_hid_report_complete_cb ift:%d seq:%d len:%d", instance, seq, len);
    //  ESP_LOG_BUFFER_HEX(TAG, report, len);
}

static esp_err_t hid_wait_for_tx(const uint32_t block_time_ms)
{
    if (xSemaphoreTake(u2f_hid_tx_done, pdMS_TO_TICKS(block_time_ms)) != pdTRUE)
    {
        return ESP_ERR_TIMEOUT;
    }
    return ESP_OK;
}

bool u2f_send_response(uint8_t *data, uint8_t len)
{
    bool res = false;
    if (tud_hid_ready())
    {
        xSemaphoreGive(u2f_hid_tx_requested);
        res = tud_hid_report(0, data, len);
        if (hid_wait_for_tx(50) != ESP_OK)
        {
            xSemaphoreTake(u2f_hid_tx_requested, 0);
            ESP_LOGV(TAG, "hid tx timeout");
            return false;
        }
    }

    return res;
}

static void u2f_hid_send_response(U2fHid *u2f_hid)
{
    uint8_t packet_buf[HID_U2F_PACKET_LEN];
    uint16_t len_remain = u2f_hid->packet.len;
    uint8_t len_cur = 0;
    uint8_t seq_cnt = 0;
    uint16_t data_ptr = 0;

    memset(packet_buf, 0, HID_U2F_PACKET_LEN);
    memcpy(packet_buf, &(u2f_hid->packet.cid), sizeof(uint32_t)); //-V1086

    // Init packet
    packet_buf[4] = u2f_hid->packet.cmd;
    packet_buf[5] = u2f_hid->packet.len >> 8;
    packet_buf[6] = (u2f_hid->packet.len & 0xFF);
    len_cur = (len_remain < (HID_U2F_PACKET_LEN - 7)) ? (len_remain) : (HID_U2F_PACKET_LEN - 7);
    if (len_cur > 0)
        memcpy(&packet_buf[7], u2f_hid->packet.payload, len_cur);

    ESP_LOGD(TAG, "tud_hid_report1 len:%d", len_cur);
    u2f_send_response(packet_buf, HID_U2F_PACKET_LEN);
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, packet_buf, HID_U2F_PACKET_LEN,ESP_LOG_DEBUG);
    data_ptr = len_cur;
    len_remain -= len_cur;

    // Continuation packets
    while (len_remain > 0)
    {
        memset(&packet_buf[4], 0, HID_U2F_PACKET_LEN - 4);
        packet_buf[4] = seq_cnt;
        len_cur = (len_remain < (HID_U2F_PACKET_LEN - 5)) ? (len_remain) : (HID_U2F_PACKET_LEN - 5);
        memcpy(&packet_buf[5], &(u2f_hid->packet.payload[data_ptr]), len_cur);

        ESP_LOGD(TAG, "tud_hid_report2 len:%d", len_cur);
        u2f_send_response(packet_buf, HID_U2F_PACKET_LEN);
        ESP_LOG_BUFFER_HEX_LEVEL(TAG, packet_buf, HID_U2F_PACKET_LEN,ESP_LOG_DEBUG);
        seq_cnt++;
        len_remain -= len_cur;
        data_ptr += len_cur;
    }
}

static void u2f_hid_send_error(U2fHid *u2f_hid, uint8_t error)
{
    u2f_hid->packet.len = 1;
    u2f_hid->packet.cmd = U2F_HID_ERROR;
    u2f_hid->packet.payload[0] = error;
    u2f_hid_send_response(u2f_hid);
}

static bool u2f_hid_parse_request(U2fHid *u2f_hid)
{
    ESP_LOGD(
        WORKER_TAG,
        "Req cid=%lX cmd=%x len=%u",
        u2f_hid->packet.cid,
        u2f_hid->packet.cmd,
        u2f_hid->packet.len);

    if (u2f_hid->packet.cmd == U2F_HID_PING)
    { // PING - echo request back
        u2f_hid_send_response(u2f_hid);
    }
    else if (u2f_hid->packet.cmd == U2F_HID_MSG)
    { // MSG - U2F message
        if ((u2f_hid->lock == true) && (u2f_hid->packet.cid != u2f_hid->lock_cid))
            return false;
        uint16_t resp_len =
            u2f_msg_parse(u2f_hid->u2f_instance, u2f_hid->packet.payload, u2f_hid->packet.len);
        if (resp_len > 0)
        {
            u2f_hid->packet.len = resp_len;
            ESP_LOGD(TAG, "hid_send_response:%d", resp_len);
            u2f_hid_send_response(u2f_hid);
        }
        else
            return false;
    }
    else if (u2f_hid->packet.cmd == U2F_HID_LOCK)
    { // LOCK - lock all channels except current
        if (u2f_hid->packet.len != 1)
            return false;
        uint8_t lock_timeout = u2f_hid->packet.payload[0];
        if (lock_timeout == 0)
        { // Lock off
            u2f_hid->lock = false;
            u2f_hid->lock_cid = 0;
            ESP_LOGI(TAG, "Lock off");
        }
        else
        { // Lock on
            u2f_hid->lock = true;
            u2f_hid->lock_cid = u2f_hid->packet.cid;
            ESP_LOGI(TAG, "Lock on");
            // TODO furi_timer_start(u2f_hid->lock_timer, lock_timeout * 1000);
        }
    }
    else if (u2f_hid->packet.cmd == U2F_HID_INIT)
    { // INIT - channel initialization request
        if ((u2f_hid->packet.len != 8) || (u2f_hid->packet.cid != U2F_HID_BROADCAST_CID) ||
            (u2f_hid->lock == true))
            return false;
        u2f_hid->packet.len = 17;
        uint32_t random_cid = esp_random();
        memcpy(&(u2f_hid->packet.payload[8]), &random_cid, sizeof(uint32_t)); //-V1086
        u2f_hid->packet.payload[12] = 2;                                      // Protocol version
        u2f_hid->packet.payload[13] = 1;                                      // Device version major
        u2f_hid->packet.payload[14] = 0;                                      // Device version minor
        u2f_hid->packet.payload[15] = 1;                                      // Device build version
        u2f_hid->packet.payload[16] = 1;                                      // Capabilities: wink
        u2f_hid_send_response(u2f_hid);
    }
    else if (u2f_hid->packet.cmd == U2F_HID_WINK)
    { // WINK - notify user
        if (u2f_hid->packet.len != 0)
            return false;
        u2f_wink(u2f_hid->u2f_instance);
        u2f_hid->packet.len = 0; //-V1048
        u2f_hid_send_response(u2f_hid);
    }
    else
        return false;
    return true;
}

void u2f_hid_init(U2fHid *u2f_hid, U2fData *u2f_inst)
{
    // U2fHid *u2f_hid = malloc(sizeof(U2fHid));
    memset(u2f_hid, 0, sizeof(U2fHid));
    u2f_hid->u2f_instance = u2f_inst;
    // u2f_hid->hid_recvbuf = xRingbufferCreate(HID_RINGBUFFER_SIZE, RINGBUF_TYPE_BYTEBUF);

    u2f_hid->hid_queue = xQueueCreate(32, HID_U2F_PACKET_LEN);

    u2f_hid_tx_requested = xSemaphoreCreateBinary();
    u2f_hid_tx_done = xSemaphoreCreateBinary();
}

void u2f_hid_stop(U2fHid *u2f_hid)
{

    free(u2f_hid);
}

void u2f_hid_recv_data(U2fHid *u2f_hid, uint8_t const *data, uint16_t len_cur)
{

    uint8_t packet_buf[HID_U2F_PACKET_LEN];
    if (len_cur == 0)
    {
        return;
    }
    memcpy(packet_buf, data, len_cur);

    xQueueSend(u2f_hid->hid_queue, &packet_buf, 0);
    ESP_LOGD(TAG, "xQueueSend done len_cur:%d", len_cur);
}

void u2f_task(U2fHid *u2f_hid)
{

    uint8_t packet_buf[HID_U2F_PACKET_LEN];
    // TODO
    uint16_t len_cur = HID_U2F_PACKET_LEN;

    if (xQueueReceive(u2f_hid->hid_queue, packet_buf, 0))
    {

        if ((packet_buf[4] & U2F_HID_TYPE_MASK) == U2F_HID_TYPE_INIT)
        {
            if (len_cur < 7)
            {
                u2f_hid->req_len_left = 0;
                return; // Wrong chunk len
            }
            // Init packet
            u2f_hid->packet.len = (packet_buf[5] << 8) | (packet_buf[6]);
            if (u2f_hid->packet.len > U2F_HID_MAX_PAYLOAD_LEN)
            {
                u2f_hid->req_len_left = 0;
                return; // Wrong packet len
            }
            if (u2f_hid->packet.len > (len_cur - 7))
            {
                u2f_hid->req_len_left = u2f_hid->packet.len - (len_cur - 7);
                len_cur = len_cur - 7;
            }
            else
            {
                u2f_hid->req_len_left = 0;
                len_cur = u2f_hid->packet.len;
            }
            memcpy(&(u2f_hid->packet.cid), packet_buf, 4);
            u2f_hid->packet.cmd = packet_buf[4];
            u2f_hid->seq_id_last = 0;
            u2f_hid->req_buf_ptr = len_cur;
            if (len_cur > 0)
                memcpy(u2f_hid->packet.payload, &packet_buf[7], len_cur);
        }
        else
        {
            if (len_cur < 5)
            {
                u2f_hid->req_len_left = 0;
                return; // Wrong chunk len
            }
            // Continuation packet
            if (u2f_hid->req_len_left > 0)
            {
                uint32_t cid_temp = 0;
                memcpy(&cid_temp, packet_buf, 4);
                uint8_t seq_temp = packet_buf[4];
                if ((cid_temp == u2f_hid->packet.cid) &&
                    (seq_temp == u2f_hid->seq_id_last))
                {
                    if (u2f_hid->req_len_left > (len_cur - 5))
                    {
                        len_cur = len_cur - 5;
                        u2f_hid->req_len_left -= len_cur;
                    }
                    else
                    {
                        len_cur = u2f_hid->req_len_left;
                        u2f_hid->req_len_left = 0;
                    }
                    memcpy(
                        &(u2f_hid->packet.payload[u2f_hid->req_buf_ptr]),
                        &packet_buf[5],
                        len_cur);
                    u2f_hid->req_buf_ptr += len_cur;
                    u2f_hid->seq_id_last++;
                }
            }
        }
        if (u2f_hid->req_len_left == 0)
        {
            if (u2f_hid_parse_request(u2f_hid) == false)
            {
                u2f_hid_send_error(u2f_hid, U2F_HID_ERR_INVALID_CMD);
            }
        }
    }
}