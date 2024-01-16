#include "device.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "class/hid/hid_device.h"
#include "ctaphid.h"
#include "esp_log.h"
#include "ctaphid.h"
#include "lfs.h"
#include "esp_timer.h"
#include "driver/gpio.h"
#include "esp_partition.h"
#include <memzero.h>
#include "ctap.h"
#include "sdkconfig.h"

#define NVS_PARTITION_LABEL "lfs"

extern const unsigned char u2f_cert_start[] asm("_binary_u2f_cert_bin_start");
extern const unsigned char u2f_cert_end[] asm("_binary_u2f_cert_bin_end");

extern const unsigned char u2f_cert_key_start[] asm("_binary_u2f_cert_key_bin_start");
extern const unsigned char u2f_cert_key_end[] asm("_binary_u2f_cert_key_bin_end");

static SemaphoreHandle_t hid_tx_requested = NULL;
static SemaphoreHandle_t hid_tx_done = NULL;
static QueueHandle_t hid_queue = NULL;
static TaskHandle_t led_btn_task = NULL;

volatile static uint8_t touch_result;
static uint32_t last_blink = UINT32_MAX, blink_timeout, blink_interval;

static enum { ON,
              OFF } led_status;
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

uint8_t device_is_blinking(void) { return last_blink != UINT32_MAX; }

// fork git version 8a47c6685c776723a424e311c4077186f4a30f8e

#define TAG "device"

#define LOOKAHEAD_SIZE 16
#define WRITE_SIZE 8
#define READ_SIZE 1

#define FLASH_PAGE_SIZE 0x1000
#define FLASH_SIZE 0x100000

static struct lfs_config config;
static uint8_t read_buffer[LFS_CACHE_SIZE];
static uint8_t prog_buffer[LFS_CACHE_SIZE];
static alignas(4) uint8_t lookahead_buffer[LOOKAHEAD_SIZE];
extern uint8_t _lfs_begin;

static esp_partition_t *partition;

int littlefs_api_read(const struct lfs_config *c, lfs_block_t block,
                      lfs_off_t off, void *buffer, lfs_size_t size)
{
    size_t part_off = (block * c->block_size) + off;
    esp_err_t err = esp_partition_read(partition, part_off, buffer, size);
    if (err)
    {
        ERR_MSG("failed to read addr %08x, size %08x, err %d", part_off, size, err);
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
        ERR_MSG("failed to write addr %08x, size %08x, err %d", part_off, size, err);
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
        ERR_MSG("failed to erase addr %08x, size %08x, err %d", part_off, c->block_size, err);
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
    config.block_cycles = 100000;
    config.cache_size = LFS_CACHE_SIZE;
    config.lookahead_size = LOOKAHEAD_SIZE;
    config.read_buffer = read_buffer;
    config.prog_buffer = prog_buffer;
    config.lookahead_buffer = lookahead_buffer;
    DBG_MSG("Flash %u blocks (%u bytes)\r\n", config.block_count, FLASH_PAGE_SIZE);

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
    DBG_MSG("Formating data area...\r\n");
    fs_format(&config);
    err = fs_mount(&config);
    if (err)
    {
        ESP_LOGI(TAG, "Failed to mount FS after formating\r\n");
        for (;;)
            ;
    }
}

#ifdef CONFIG_BLINK_LED_STRIP

static led_strip_handle_t led_strip;

static void blink_led(uint8_t s_led_state)
{
    /* If the addressable LED is enabled */
    if (s_led_state)
    {
        /* Set the LED pixel using RGB from 0 (0%) to 255 (100%) for each color */
        led_strip_set_pixel(led_strip, 0, 16, 16, 16);
        /* Refresh the strip to send data */
        led_strip_refresh(led_strip);
    }
    else
    {
        /* Set all LED off to clear all pixels */
        led_strip_clear(led_strip);
    }
}

static void configure_led(void)
{
    ESP_LOGI(TAG, "Example configured to blink addressable LED!");
    /* LED strip initialization with the GPIO and pixels number*/
    led_strip_config_t strip_config = {
        .strip_gpio_num = CONFIG_BLINK_GPIO,
        .max_leds = 1, // at least one LED on board
    };
#if CONFIG_BLINK_LED_STRIP_BACKEND_RMT
    led_strip_rmt_config_t rmt_config = {
        .resolution_hz = 10 * 1000 * 1000, // 10MHz
        .flags.with_dma = false,
    };
    ESP_ERROR_CHECK(led_strip_new_rmt_device(&strip_config, &rmt_config, &led_strip));
#elif CONFIG_BLINK_LED_STRIP_BACKEND_SPI
    led_strip_spi_config_t spi_config = {
        .spi_bus = SPI2_HOST,
        .flags.with_dma = true,
    };
    ESP_ERROR_CHECK(led_strip_new_spi_device(&strip_config, &spi_config, &led_strip));
#else
#error "unsupported LED strip backend"
#endif
    /* Set all LED off to clear all pixels */
    led_strip_clear(led_strip);
}

#elif CONFIG_BLINK_LED_GPIO

static void blink_led(uint8_t s_led_state)
{
    /* Set the GPIO level according to the state (LOW or HIGH)*/
    gpio_set_level(CONFIG_BLINK_GPIO, s_led_state);
}

static void configure_led(void)
{
    ESP_LOGI(TAG, "Example configured to blink GPIO LED!");
    gpio_reset_pin(CONFIG_BLINK_GPIO);
    /* Set the GPIO as a push/pull output */
    gpio_set_direction(CONFIG_BLINK_GPIO, GPIO_MODE_OUTPUT);
}

#else
static void blink_led(uint8_t s_led_state)();
static void configure_led(void){};
#endif

void device_init(void)
{
    littlefs_init();

    configure_led();

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
    hid_queue = xQueueCreate(32, HID_RPT_SIZE);
    hid_tx_requested = xSemaphoreCreateBinary();
    hid_tx_done = xSemaphoreCreateBinary();

    CTAPHID_Init();

    if (get_file_size("ctap_cert") <= 0)
    {
        ESP_LOGI(TAG, "cert file initialization");

        ctap_install(true);

        ctap_install_cert(u2f_cert_start, u2f_cert_end - u2f_cert_start);
        ctap_install_private_key(u2f_cert_key_start, u2f_cert_key_end - u2f_cert_key_start);
    }

    xTaskCreate(device_update_led_btn, "led_btn_task", configMINIMAL_STACK_SIZE * 2, NULL, 10, &led_btn_task);

    ESP_LOGI(TAG, "u2f device init done");
}

void device_recv_data(uint8_t const *data, uint16_t len)
{

    uint8_t packet_buf[HID_RPT_SIZE];
    if (len == 0)
    {
        return;
    }
    memcpy(packet_buf, data, len);

    xQueueSend(hid_queue, &packet_buf, 0);
}

void device_loop(uint8_t has_touch)
{

    uint8_t packet_buf[HID_RPT_SIZE];

    if (xQueueReceive(hid_queue, packet_buf, 0))
    {
        CTAPHID_OutEvent(packet_buf);
    }

    CTAPHID_Loop(0);

    //ESP_LOGI(TAG, "[APP] Free memory: %" PRIu32 " bytes", esp_get_free_heap_size());
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

    return touch_result;
}

void set_touch_result(uint8_t result) { touch_result = result; }

uint32_t device_get_tick(void)
{

    return esp_timer_get_time() / 1000;
}

void led_off(void)
{
    /* Set the GPIO level according to the state (LOW or HIGH)*/
    blink_led(0);
}

void led_on(void)
{
    /* Set the GPIO level according to the state (LOW or HIGH)*/
    blink_led(1);
}

static void toggle_led(void)
{
    if (led_status == ON)
    {
        led_off();
        led_status = OFF;
    }
    else
    {
        led_on();
        led_status = ON;
    }
}

void device_update_led_btn(void *pvParam)
{
    while (1)
    {
        uint32_t now = device_get_tick();
        if (now > blink_timeout)
            stop_blinking();
        if (now >= last_blink && now - last_blink >= blink_interval)
        {
            last_blink = now;
            toggle_led();
        }

#ifdef CONFIG_BUTTON_ENABLE
        if (!gpio_get_level(CONFIG_BUTTON_GPIO))
        {
            set_touch_result(TOUCH_SHORT);
        }
#else
        // TODO fake touch button
        set_touch_result(TOUCH_SHORT);
#endif
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

void start_blinking_interval(uint8_t sec, uint32_t interval)
{
    if (device_is_blinking())
        return;
    last_blink = device_get_tick();
    blink_interval = interval;
    if (sec == 0)
    {
        blink_timeout = UINT32_MAX;
    }
    else
    {
        blink_timeout = last_blink + sec * 1000;
    }
    toggle_led();
}

void stop_blinking(void)
{
    last_blink = UINT32_MAX;
    led_off();
    led_status = OFF;
}

uint8_t wait_for_user_presence(uint8_t entry)
{
    start_blinking(0);
    uint32_t start = device_get_tick();
    int32_t last = start;
    DBG_MSG("start %u\n", start);
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
            DBG_MSG("Cancelled by host");
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
            DBG_MSG("timeout at %u\n", now);
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
