#include "u2f_data.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "esp_log.h"
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include <mbedtls/sha256.h>

#define TAG "U2f"

#define NVS_PART_NAMESPACE "storage"
#define U2F_CERT_FILE "u2f_cert"
#define U2F_CERT_KEY_FILE "u2f_cert_key"
#define U2F_KEY_FILE "u2f_key"
#define U2F_CNT_FILE "u2f_cnt"

extern const unsigned char u2f_cert_start[] asm("_binary_u2f_cert_bin_start");
extern const unsigned char u2f_cert_end[] asm("_binary_u2f_cert_bin_end");

extern const unsigned char u2f_cert_key_start[] asm("_binary_u2f_cert_key_bin_start");
extern const unsigned char u2f_cert_key_end[] asm("_binary_u2f_cert_key_bin_end");

bool u2f_data_check(bool cert_only)
{
    return true;
}

bool u2f_data_cert_check()
{
    bool state = false;

    if ((u2f_cert_end - u2f_cert_start) > 0)
        state = true;
    ESP_LOGD(TAG, "u2f_data_cert_check:%d", u2f_cert_end - u2f_cert_start);
    return state;
}

uint32_t u2f_data_cert_load(uint8_t *cert)
{
    uint32_t cert_len = u2f_cert_end - u2f_cert_start;
    memcpy(cert, u2f_cert_start, cert_len);

    return cert_len;
}

bool u2f_data_cert_key_load(uint8_t *cert_key)
{

    bool state = false;

    uint32_t cert_ken_len = u2f_cert_key_end - u2f_cert_key_start;

    memcpy(cert_key, u2f_cert_start, cert_ken_len);
    if (cert_ken_len > 0)
        state = true;
    ESP_LOGD(TAG, "u2f_data_cert_key_load:%ld", cert_ken_len);
    return state;
}

bool u2f_data_key_load(uint8_t *device_key)
{

    uint8_t OPTIONAL_UNIQUE_ID[16];
    esp_efuse_read_field_blob(ESP_EFUSE_OPTIONAL_UNIQUE_ID, OPTIONAL_UNIQUE_ID, 16 * 8);

    mbedtls_sha256_context sha_ctx;

    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0);

    mbedtls_sha256_update(&sha_ctx, OPTIONAL_UNIQUE_ID, 16);
    mbedtls_sha256_finish(&sha_ctx, device_key);
    mbedtls_sha256_free(&sha_ctx);

    ESP_LOGD(TAG, "u2f_data_key_load");

    return true;
}

bool u2f_data_key_generate(uint8_t *device_key)
{

    return true;
}

static uint32_t u2f_cnt = 0;

bool u2f_data_cnt_read(uint32_t *cnt_val)
{

    *cnt_val = u2f_cnt;

    return true;
}

bool u2f_data_cnt_write(uint32_t cnt_val)
{

    u2f_cnt = cnt_val;

    return true;
}
