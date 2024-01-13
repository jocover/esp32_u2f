/*
 * SPDX-FileCopyrightText: 2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */

#include <stdlib.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "tusb_config.h"
#include "tusb.h"
#include "class/hid/hid_device.h"
#include "driver/gpio.h"
#include "sdkconfig.h"
#include "esp_private/usb_phy.h"
#include "u2f_hid.h"
#include "u2f.h"

static U2fHid u2f_hid;
static U2fData u2f_data;

#define APP_BUTTON (GPIO_NUM_0) // Use BOOT signal by default
static const char *TAG = "main";

/************* TinyUSB descriptors ****************/
#define TUD_U2F_INOUT_DESC_LEN (8 + 9 + 9 + 7 + 7)
#define TUSB_DESC_TOTAL_LEN (TUD_CONFIG_DESC_LEN + TUD_U2F_INOUT_DESC_LEN )

static const tusb_desc_device_t hid_u2f_device_desc = {
    .bLength = sizeof(hid_u2f_device_desc),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = 0x0200,
    .bDeviceClass = TUSB_CLASS_MISC,
    .bDeviceSubClass = MISC_SUBCLASS_COMMON,
    .bDeviceProtocol = MISC_PROTOCOL_IAD,
    .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor = 0x303a,
    .idProduct = 0x4004,
    .bcdDevice = 0x0010,
    .iManufacturer = 0x01,
    .iProduct = 0x02,
    .iSerialNumber = 0x03,
    .bNumConfigurations = 0x01};

static char const *string_desc_arr[] = {
    (const char[]){0x09, 0x04}, // 0: is supported language is English (0x0409)
    "Espressif Inc.",     // 1: Manufacturer
    "U2F Token",                // 2: Product
    "123456",                   // 3: Serials
};
/**
 * @brief HID report descriptor
 *
 * In this example we implement Keyboard + Mouse HID device,
 * so we must define both report descriptors
 */
const uint8_t u2f_report_descriptor[] = {
    TUD_HID_REPORT_DESC_FIDO_U2F(CFG_TUD_HID_EP_BUFSIZE)};

/**
 * @brief Configuration descriptor
 *
 * This is a simple configuration descriptor that defines 1 configuration and 1 HID interface
 */

// HID Input & Output descriptor
// Interface number, string index, protocol, report descriptor len, EP OUT & IN address, size & polling interval
#define TUD_U2F_INOUT_DESCRIPTOR(_itfnum, _stridx, _boot_protocol, _report_desc_len, _epout, _epin, _epsize, _ep_interval)                            \
    8, TUSB_DESC_INTERFACE_ASSOCIATION, _itfnum, 1, TUSB_CLASS_UNSPECIFIED, HID_SUBCLASS_NONE, HID_ITF_PROTOCOL_NONE, _stridx,                        \
        9, TUSB_DESC_INTERFACE, _itfnum, 0, 2, TUSB_CLASS_HID, (uint8_t)((_boot_protocol) ? (uint8_t)HID_SUBCLASS_BOOT : 0), _boot_protocol, _stridx, \
        9, HID_DESC_TYPE_HID, U16_TO_U8S_LE(0x0111), 0, 1, HID_DESC_TYPE_REPORT, U16_TO_U8S_LE(_report_desc_len),                                     \
        7, TUSB_DESC_ENDPOINT, _epout, TUSB_XFER_INTERRUPT, U16_TO_U8S_LE(_epsize), _ep_interval,                                                     \
        7, TUSB_DESC_ENDPOINT, _epin, TUSB_XFER_INTERRUPT, U16_TO_U8S_LE(_epsize), _ep_interval

static const uint8_t u2f_configuration_descriptor[] = {
    // Configuration number, interface count, string index, total length, attribute, power in mA
    TUD_CONFIG_DESCRIPTOR(1, 1, 0, TUSB_DESC_TOTAL_LEN, 0, 100),

    // Interface number, string index, protocol, report descriptor len, EP OUT & IN address, size & polling interval
    TUD_U2F_INOUT_DESCRIPTOR(0, 2, HID_ITF_PROTOCOL_NONE, sizeof(u2f_report_descriptor), 0x03, 0x80 | 0x03, CFG_TUD_HID_EP_BUFSIZE, 5),

};

/********* TinyUSB HID callbacks ***************/

// Invoked when received GET HID REPORT DESCRIPTOR request
// Application return pointer to descriptor, whose contents must exist long enough for transfer to complete
uint8_t const *tud_hid_descriptor_report_cb(uint8_t instance)
{
   
    // We use only one interface and one HID report descriptor, so we can ignore parameter 'instance'
    return u2f_report_descriptor;
}


static uint16_t _desc_str[32];

uint8_t const *tud_descriptor_configuration_cb(uint8_t index)
{
    return u2f_configuration_descriptor;
}

uint8_t const *tud_descriptor_device_cb(void)
{
    return (uint8_t const *)&hid_u2f_device_desc;
}


uint16_t const *tud_descriptor_string_cb(const uint8_t index, const uint16_t langid)
{
    uint8_t chr_count;

    if (index == 0)
    {
        memcpy(&_desc_str[1], string_desc_arr[0], 2);
        chr_count = 1;
    }
    else
    {
        // Convert ASCII string into UTF-16

        if (!(index < sizeof(string_desc_arr) / sizeof(string_desc_arr[0])))
        {
            return NULL;
        }

        const char *str = string_desc_arr[index];

        // Cap at max char
        chr_count = strlen(str);
        if (chr_count > 31)
        {
            chr_count = 31;
        }

        for (uint8_t i = 0; i < chr_count; i++)
        {
            _desc_str[1 + i] = str[i];
        }
    }

    // first byte is length (including header), second byte is string type
    _desc_str[0] = (TUSB_DESC_STRING << 8) | (2 * chr_count + 2);

    return _desc_str;
}


// Invoked when received GET_REPORT control request
// Application must fill buffer report's content and return its length.
// Return zero will cause the stack to STALL request
uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t report_type, uint8_t *buffer, uint16_t reqlen)
{
    (void)instance;
    (void)report_id;
    (void)report_type;
    (void)buffer;
    (void)reqlen;

    return 0;
}

// Invoked when received SET_REPORT control request or
// received data on OUT endpoint ( Report ID = 0, Type = 0 )
void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t report_type, uint8_t const *buffer, uint16_t bufsize)
{

    u2f_hid_recv_data(&u2f_hid, buffer, bufsize);

}

/********* Application ***************/

static usb_phy_handle_t s_phy_hdl;

static void usb_phy_init(void)
{
    // Configure USB PHY
    usb_phy_config_t phy_conf = {
        .controller = USB_PHY_CTRL_OTG,
        .otg_mode = USB_OTG_MODE_DEVICE,
    };
    phy_conf.target = USB_PHY_TARGET_INT;
    usb_new_phy(&phy_conf, &s_phy_hdl);

    ESP_LOGI(TAG, "TinyUSB Driver installed");
}

static void tusb_device_task(void *pvParameters)
{
    while (1)
    {
        tud_task();
    }
    vTaskDelete(NULL);
}


void app_main(void)
{

    
    if (u2f_init(&u2f_data))
    {
        u2f_hid_init(&u2f_hid,&u2f_data);
    }
    else
    {
        ESP_LOGE(TAG, "u2f init failed");
    }

    usb_phy_init();

    tusb_init();

    xTaskCreate(tusb_device_task, "tusb_device_task", 8 * 1024, NULL, 5, NULL);

    while (1)
    {
        u2f_task(&u2f_hid);
        
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}
