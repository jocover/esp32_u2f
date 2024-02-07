#include "device.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/ringbuf.h"
#include "class/hid/hid_device.h"
#include "ctaphid.h"
#include "esp_log.h"
#include "ctaphid.h"
#include "lfs.h"
#include "esp_timer.h"
#include "driver/gpio.h"
#include "driver/gptimer.h"
#include "esp_partition.h"
#include "esp_timer.h"
#include <memzero.h>
#include "ctap.h"
#include "sdkconfig.h"
#include "ccid_device.h"
#include "ccid.h"
#include "applets.h"
#include "esp_mac.h"

#define NVS_PARTITION_LABEL "lfs"

extern const unsigned char u2f_cert_start[] asm("_binary_u2f_cert_bin_start");
extern const unsigned char u2f_cert_end[] asm("_binary_u2f_cert_bin_end");

extern const unsigned char u2f_cert_key_start[] asm("_binary_u2f_cert_key_bin_start");
extern const unsigned char u2f_cert_key_end[] asm("_binary_u2f_cert_key_bin_end");

extern const unsigned char u2f_aaguid_start[] asm("_binary_u2f_aaguid_bin_start");
extern const unsigned char u2f_aaguid_end[] asm("_binary_u2f_aaguid_bin_end");

static SemaphoreHandle_t hid_tx_requested = NULL;
static SemaphoreHandle_t hid_tx_done = NULL;
static RingbufHandle_t hid_rx_rb = NULL;

volatile static uint8_t touch_result;

typedef struct
{
    int8_t blink_status;
    uint32_t blink_timeout;
    uint32_t blink_conter;
} led_blink_status;
static led_blink_status led_status;
static gptimer_handle_t gptimer = NULL;

typedef enum
{
    WAIT_NONE = 1,
    WAIT_CCID,
    WAIT_CTAPHID,
    WAIT_DEEP,
    WAIT_DEEP_TOUCHED,
    WAIT_DEEP_CANCEL
} wait_status_t;
volatile static wait_status_t wait_status = WAIT_NONE; // WAIT_NONE is not 0, hence inited

uint8_t device_is_blinking(void) { return led_status.blink_timeout != UINT32_MAX; }

// fork git version 8a47c6685c776723a424e311c4077186f4a30f8e

#define TAG "device"

#define LOOKAHEAD_SIZE 128
#define WRITE_SIZE 128
#define READ_SIZE 128

#define FLASH_PAGE_SIZE 0x1000
#define FLASH_SIZE 0x100000

static struct lfs_config config;
extern uint8_t _lfs_begin;

static esp_partition_t *partition;

int littlefs_api_read(const struct lfs_config *c, lfs_block_t block,
                      lfs_off_t off, void *buffer, lfs_size_t size)
{
    size_t part_off = (block * c->block_size) + off;
    esp_err_t err = esp_partition_read(partition, part_off, buffer, size);
    if (err)
    {
        // ESP_LOGE(TAG,"failed to read addr %08x, size %08x, err %d", part_off, size, err);
        return LFS_ERR_IO;
    }
    return 0;
}

int littlefs_api_prog(const struct lfs_config *c, lfs_block_t block,
                      lfs_off_t off, const void *buffer, lfs_size_t size)
{
    size_t part_off = (block * c->block_size) + off;
    esp_err_t err = esp_partition_write(partition, part_off, buffer, size);
    if (err)
    {
        // ESP_LOGE(TAG,"failed to write addr %08x, size %08x, err %d", part_off, size, err);
        return LFS_ERR_IO;
    }
    return 0;
}

int littlefs_api_erase(const struct lfs_config *c, lfs_block_t block)
{
    size_t part_off = block * c->block_size;
    esp_err_t err = esp_partition_erase_range(partition, part_off, c->block_size);
    if (err)
    {
        // ESP_LOGE(TAG,"failed to erase addr %08x, size %08x, err %d", part_off, c->block_size, err);
        return LFS_ERR_IO;
    }
    return 0;
}

int littlefs_api_sync(const struct lfs_config *c)
{
    /* Unnecessary for esp-idf */
    return 0;
}

void littlefs_init()
{
    memzero(&config, sizeof(config));
    config.read = littlefs_api_read;
    config.prog = littlefs_api_prog;
    config.erase = littlefs_api_erase;
    config.sync = littlefs_api_sync;
    config.read_size = READ_SIZE;
    config.prog_size = WRITE_SIZE;
    config.block_size = FLASH_PAGE_SIZE;
    config.block_count = FLASH_SIZE / FLASH_PAGE_SIZE;
    config.block_cycles = 512;
    config.cache_size = LFS_CACHE_SIZE;
    config.lookahead_size = LOOKAHEAD_SIZE;

    ESP_LOGI(TAG, "Flash %lu blocks (%d bytes)", config.block_count, FLASH_PAGE_SIZE);

    partition = (esp_partition_t *)esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_UNDEFINED, "lfs");
    if (!partition)
    {
        ERR_MSG("Can not find partition lfs!\n");
        for (;;)
            ;
    }

    int err;
    for (int retry = 0; retry < 3; retry++)
    {
        err = fs_mount(&config);
        if (!err)
            return;
    }
    // should happen for the first boot
    ESP_LOGW(TAG, "Formating data area...");
    fs_format(&config);
    err = fs_mount(&config);
    if (err)
    {
        ESP_LOGI(TAG, "Failed to mount FS after formating");
        for (;;)
            ;
    }
}

static bool IRAM_ATTR toggle_led(gptimer_handle_t timer, const gptimer_alarm_event_data_t *edata, void *user_data)
{
    led_blink_status *status = (led_blink_status *)user_data;

    if (status->blink_timeout > status->blink_conter || status->blink_timeout == UINT32_MAX)
    {

        status->blink_status = !status->blink_status;
    }
    else
    {
        status->blink_status = 0;
    }

    gpio_set_level(CONFIG_BLINK_GPIO, status->blink_status);

    if (status->blink_timeout != UINT32_MAX)
    {
        status->blink_conter += edata->alarm_value / 1000; // ns to ms
    }
    return 0;
}

void init_blinking()
{

    gpio_reset_pin(CONFIG_BLINK_GPIO);
    /* Set the GPIO as a push/pull output */
    gpio_set_direction(CONFIG_BLINK_GPIO, GPIO_MODE_OUTPUT);

    gptimer_config_t timer_config = {
        .clk_src = GPTIMER_CLK_SRC_DEFAULT,
        .direction = GPTIMER_COUNT_UP,
        .resolution_hz = 1 * 1000 * 1000, // 1MHz, 1 tick = 1us
    };
    ESP_ERROR_CHECK(gptimer_new_timer(&timer_config, &gptimer));

    gptimer_event_callbacks_t cbs = {
        .on_alarm = toggle_led,
    };

    ESP_ERROR_CHECK(gptimer_register_event_callbacks(gptimer, &cbs, &led_status));
    ESP_ERROR_CHECK(gptimer_enable(gptimer));

    gptimer_alarm_config_t alarm_config = {
        .reload_count = 0,
        .alarm_count = 1000000, // to ns
        .flags.auto_reload_on_alarm = true,
    };

    ESP_ERROR_CHECK(gptimer_set_alarm_action(gptimer, &alarm_config));

    ESP_ERROR_CHECK(gptimer_start(gptimer));
}

void start_blinking_interval(uint8_t sec, uint32_t interval)
{

    if (sec == 0)
    {
        led_status.blink_timeout = UINT32_MAX;
    }
    else
    {
        led_status.blink_conter = 0;
        led_status.blink_timeout = sec * 1000;
    }
    gptimer_alarm_config_t alarm_config = {
        .reload_count = 0,
        .alarm_count = interval * 1000,
        .flags.auto_reload_on_alarm = true,
    };

    ESP_ERROR_CHECK(gptimer_set_alarm_action(gptimer, &alarm_config));
}

void stop_blinking(void)
{
    led_status.blink_timeout = 0;
    led_status.blink_conter = 0;
}

void device_init(void)
{
    littlefs_init();

    init_blinking();

#ifdef CONFIG_BUTTON_ENABLE
    const gpio_config_t boot_button_config = {
        .pin_bit_mask = BIT64(CONFIG_BUTTON_GPIO),
        .mode = GPIO_MODE_INPUT,
        .intr_type = GPIO_INTR_DISABLE,
        .pull_up_en = true,
        .pull_down_en = false,
    };

    ESP_ERROR_CHECK(gpio_config(&boot_button_config));
#endif

    hid_rx_rb = xRingbufferCreate(HID_RPT_SIZE * 32, RINGBUF_TYPE_BYTEBUF);
    hid_tx_requested = xSemaphoreCreateBinary();
    hid_tx_done = xSemaphoreCreateBinary();

    CTAPHID_Init();
    CCID_Init();

    if (get_file_size("ctap_cert") <= 0)
    {
        ESP_LOGI(TAG, "cert file initialization");

        CAPDU apdu_cert;

        apdu_cert.lc = u2f_cert_end - u2f_cert_start;
        apdu_cert.data = (uint8_t *)u2f_cert_start;

        ctap_install_cert(&apdu_cert, NULL);

        apdu_cert.lc = u2f_cert_key_end - u2f_cert_key_start;
        apdu_cert.data = (uint8_t *)u2f_cert_key_start;
        ctap_install_private_key(&apdu_cert, NULL);

        uint8_t sta_mac[6];
        esp_efuse_mac_get_default(sta_mac);

        write_file("sn", sta_mac + 2, 0, 4, 1);
    }

    applets_install();

    ESP_LOGI(TAG, "u2f device init done");
}

void device_recv_data(uint8_t const *data, uint16_t len)
{

    if (len == 0)
    {
        return;
    }
    xRingbufferSend(hid_rx_rb, data, HID_RPT_SIZE, 0);
}

void device_loop(uint8_t has_touch)
{
    uint8_t packet_buf[HID_RPT_SIZE];
    size_t item_size = 0;
    uint8_t *data = xRingbufferReceiveUpTo(hid_rx_rb, &item_size, 0, HID_RPT_SIZE);

    if (item_size == HID_RPT_SIZE)
    {
        memcpy(packet_buf, data, item_size);
        vRingbufferReturnItem(hid_rx_rb, data);
        CTAPHID_OutEvent(packet_buf);
    }

    CTAPHID_Loop(0);

    CCID_Loop();
}

void tud_hid_report_complete_cb(uint8_t instance, uint8_t const *report, /*uint16_t*/ uint8_t len)
{

    if (xSemaphoreTake(hid_tx_requested, 0) != pdTRUE)
    {
        /* Semaphore should have been given before write attempt.
            Sometimes tinyusb can send one more cb even xfer_complete len is zero
        */
        return;
    }

    xSemaphoreGive(hid_tx_done);
}

static esp_err_t hid_wait_for_tx(const uint32_t block_time_ms)
{
    if (xSemaphoreTake(hid_tx_done, pdMS_TO_TICKS(block_time_ms)) != pdTRUE)
    {
        return ESP_ERR_TIMEOUT;
    }
    return ESP_OK;
}

void device_send_response(uint8_t *data, uint8_t len)
{

    if (tud_hid_ready())
    {
        xSemaphoreGive(hid_tx_requested);
        tud_hid_report(0, data, len);
        if (hid_wait_for_tx(50) != ESP_OK)
        {
            xSemaphoreTake(hid_tx_requested, 0);
            ESP_LOGV(TAG, "hid tx timeout");
            return;
        }
    }
}

int send_keepalive_during_processing(uint8_t entry)
{
    if (entry == WAIT_ENTRY_CTAPHID)
        CTAPHID_SendKeepAlive(KEEPALIVE_STATUS_PROCESSING);
    DBG_MSG("KEEPALIVE\n");
    return 0;
}

uint8_t is_nfc(void)
{
    return false;
}

uint8_t get_touch_result(void)
{
#ifdef CONFIG_BUTTON_ENABLE

    if (!gpio_get_level(CONFIG_BUTTON_GPIO))
    {
        set_touch_result(TOUCH_SHORT);
    }
#else
    set_touch_result(TOUCH_SHORT);
#endif

    return touch_result;
}

void set_touch_result(uint8_t result) { touch_result = result; }

uint32_t device_get_tick(void)
{

    return esp_timer_get_time() / 1000;
}

uint8_t wait_for_user_presence(uint8_t entry)
{
    start_blinking(0);
    uint32_t start = device_get_tick();
    int32_t last = start;
    ESP_LOGD(TAG, "start %lu\n", start);
    wait_status_t shallow = wait_status;
    if (wait_status == WAIT_NONE)
    {
        switch (entry)
        {
        case WAIT_ENTRY_CCID:
            wait_status = WAIT_CCID;
            break;
        case WAIT_ENTRY_CTAPHID:
            wait_status = WAIT_CTAPHID;
            break;
        }
    }
    else
        wait_status = WAIT_DEEP;
    while (get_touch_result() == TOUCH_NO)
    {
        if (wait_status == WAIT_DEEP_TOUCHED || wait_status == WAIT_DEEP_CANCEL)
            break;
        if (CTAPHID_Loop(wait_status != WAIT_CCID) == LOOP_CANCEL)
        {
            ESP_LOGD(TAG, "Cancelled by host");
            if (wait_status != WAIT_DEEP)
            {
                stop_blinking();
                wait_status = WAIT_NONE; // namely shallow
            }
            else
                wait_status = WAIT_DEEP_CANCEL;
            return USER_PRESENCE_CANCEL;
        }
        uint32_t now = device_get_tick();
        if (now - start >= 30000)
        {
            ESP_LOGD(TAG, "timeout at %lu", now);
            if (wait_status != WAIT_DEEP)
                stop_blinking();
            wait_status = shallow;
            return USER_PRESENCE_TIMEOUT;
        }
        if (now - last >= 100)
        {
            last = now;
            if (wait_status != WAIT_CCID)
                CTAPHID_SendKeepAlive(KEEPALIVE_STATUS_UPNEEDED);
        }
    }
    set_touch_result(TOUCH_NO);
    if (wait_status != WAIT_DEEP)
        stop_blinking();
    if (wait_status == WAIT_DEEP)
        wait_status = WAIT_DEEP_TOUCHED;
    else if (wait_status == WAIT_DEEP_CANCEL)
    {
        wait_status = WAIT_NONE;
        return USER_PRESENCE_TIMEOUT;
    }
    else
        wait_status = WAIT_NONE;
    return USER_PRESENCE_OK;
}

void device_get_aaguid(uint8_t *data, uint8_t len)
{

    memcpy(data, u2f_aaguid_start, len);
}

int device_spinlock_lock(spinlock_t *lock, uint32_t blocking)
{

    if (blocking)
    {
        spinlock_acquire(lock, SPINLOCK_WAIT_FOREVER);
    }
    else
    {

        spinlock_acquire(lock, SPINLOCK_NO_WAIT);
    }

    return 0;
}

void device_spinlock_unlock(spinlock_t *lock)
{
    spinlock_release(lock);
}

esp_timer_handle_t m_timer_timeout = NULL;

void device_set_timeout(void (*callback)(void *), uint16_t timeout)
{
    if (m_timer_timeout)
    {
        esp_timer_stop(m_timer_timeout);
        esp_timer_delete(m_timer_timeout);
        m_timer_timeout = NULL;
    }

    if (timeout)
    {
        const esp_timer_create_args_t timer_args = {
            .callback = callback,
            /* name is optional, but may help identify the timer when debugging */
            .name = "one-shot"};

        esp_timer_create(&timer_args, &m_timer_timeout);
        esp_timer_start_once(m_timer_timeout, timeout * 1000);
    }
}

int device_atomic_compare_and_swap(volatile uint32_t *var, uint32_t expect, uint32_t update)
{
    if (*var == expect)
    {
        *var = update;
        return 0;
    }
    else
    {
        return -1;
    }
}

__attribute__((weak)) int strong_user_presence_test(void)
{
    for (int i = 0; i < 5; i++)
    {
        const uint8_t wait_sec = 2;
        start_blinking_interval(wait_sec, (i & 1) ? 200 : 50);
        uint32_t now, begin = device_get_tick();
        bool user_presence = false;
        do
        {
            if (get_touch_result() == TOUCH_SHORT)
            {
                user_presence = true;
                set_touch_result(TOUCH_NO);
                stop_blinking();
                // wait for some time before next user-precense test
                begin = device_get_tick();
            }
            now = device_get_tick();
        } while (now - begin < 1000 * wait_sec);
        if (!user_presence)
        {
            return -1;
        }
    }
    return 0;
}

void device_delay(int ms)
{

    vTaskDelay(pdMS_TO_TICKS(ms));
}