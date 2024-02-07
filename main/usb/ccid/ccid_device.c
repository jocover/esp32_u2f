#include <stdio.h>
#include "esp_log.h"
#include "tusb.h"
#include "device/usbd.h"
#include "device/usbd_pvt.h"
#include "device/dcd.h"
#include "ccid_device.h"

#define TAG "CCID"

#define ITF_MEM_RESET_SIZE offsetof(ccidd_interface_t, rx_ff)

// TODO: multiple instances to be tested & completed
CFG_TUSB_MEM_SECTION static ccidd_interface_t _ccidd_itf[CFG_TUD_CCID];

//--------------------------------------------------------------------+
// Read API
//--------------------------------------------------------------------+
static void _prep_out_transaction(ccidd_interface_t *p_itf)
{
    uint8_t const rhport = 0;
    uint16_t available = tu_fifo_remaining(&p_itf->rx_ff);

    TU_VERIFY(available >= sizeof(p_itf->epout_buf), );  // This pre-check reduces endpoint claiming
    TU_VERIFY(usbd_edpt_claim(rhport, p_itf->ep_out), ); // claim endpoint

    available = tu_fifo_remaining(&p_itf->rx_ff); // fifo can be changed before endpoint is claimed
    if (available >= sizeof(p_itf->epout_buf))
    {
        usbd_edpt_xfer(rhport, p_itf->ep_out, p_itf->epout_buf, sizeof(p_itf->epout_buf));
    }
    else
    {
        usbd_edpt_release(rhport, p_itf->ep_out); // Release endpoint since we don't make any transfer
    }
}

uint32_t tud_ccid_n_read(uint8_t itf, void *buffer, uint32_t bufsize)
{
    ccidd_interface_t *p_itf = &_ccidd_itf[itf];
    TU_VERIFY(p_itf->ep_out);

    uint32_t const num_read = tu_fifo_read_n(&p_itf->rx_ff, buffer, bufsize);
    _prep_out_transaction(p_itf);
    return num_read;
}

//--------------------------------------------------------------------+
// Write API
//--------------------------------------------------------------------+
uint32_t tud_ccid_write_n_flush(ccidd_interface_t *p_itf)
{
    if (!tu_fifo_count(&p_itf->tx_ff)) // No data to send
        return 0;

    uint8_t const rhport = 0;
    TU_VERIFY(usbd_edpt_claim(rhport, p_itf->ep_in), 0); // skip if previous transfer not complete

    uint16_t count = tu_fifo_read_n(&p_itf->tx_ff, p_itf->epin_buf, sizeof(p_itf->epin_buf));
    if (count)
    {
        TU_ASSERT(usbd_edpt_xfer(rhport, p_itf->ep_in, p_itf->epin_buf, count), 0);
        return count;
    }
    else
    {
        usbd_edpt_release(rhport, p_itf->ep_in); // Release endpoint since we don't make any transfer
        return 0;
    }
}

uint32_t tud_ccid_n_write(uint8_t itf, void const *buffer, uint32_t bufsize)
{
    ccidd_interface_t *p_itf = &_ccidd_itf[itf];
    TU_VERIFY(p_itf->ep_in);

    uint16_t ret = tu_fifo_write_n(&p_itf->tx_ff, buffer, bufsize);
    return tud_ccid_write_n_flush(p_itf) > 0 ? ret : 0;
}

//--------------------------------------------------------------------+
// USBD Driver API
//--------------------------------------------------------------------+
static void ccid_init(void)
{
    tu_memclr(&_ccidd_itf, sizeof(_ccidd_itf));

    for (uint8_t i = 0; i < CFG_TUD_CCID; i++)
    {
        ccidd_interface_t *p_itf = &_ccidd_itf[i];
        tu_fifo_config(&p_itf->rx_ff, p_itf->rx_ff_buf, CFG_TUD_CCID_RX_BUFSIZE, 1, false);
        tu_fifo_config(&p_itf->tx_ff, p_itf->tx_ff_buf, CFG_TUD_CCID_TX_BUFSIZE, 1, false);
    }
}

static void ccid_reset(uint8_t rhport)
{
    (void)rhport;

    for (uint8_t i = 0; i < CFG_TUD_CCID; i++)
    {
        ccidd_interface_t *p_itf = &_ccidd_itf[i];
        tu_memclr(p_itf, ITF_MEM_RESET_SIZE);
        tu_fifo_clear(&p_itf->rx_ff);
        tu_fifo_clear(&p_itf->tx_ff);
    }
}

static uint16_t ccid_open(uint8_t rhport, tusb_desc_interface_t const *desc_itf, uint16_t max_len)
{
    if (desc_itf->bInterfaceClass != TUSB_CLASS_SMART_CARD)
        return 0; // not our interface class

    // desc_intf->bInterfaceSubClass == 0 && desc_intf->bInterfaceProtocol == 0
    uint16_t drv_len = sizeof(tusb_desc_interface_t);
    TU_VERIFY(max_len >= drv_len, 0);

    uint8_t const *p_desc = (uint8_t const *)desc_itf;

    //------------- CCID descriptor -------------//
    p_desc = tu_desc_next(p_desc);
    TU_ASSERT(CCID_DESC_TYPE_CCID == tu_desc_type(p_desc), 0);
    drv_len += tu_desc_len(p_desc);

    ccidd_interface_t *p_itf = NULL;
    for (uint8_t i = 0; i < CFG_TUD_CCID; i++)
    { // Find available interface
        if (_ccidd_itf[i].ep_in == 0 && _ccidd_itf[i].ep_out == 0)
        {
            p_itf = &_ccidd_itf[i];
            break;
        }
    }
    TU_ASSERT(p_itf);

    p_itf->itf_num = desc_itf->bInterfaceNumber;
    (void)p_itf->itf_num;

    //------------- Endpoint Descriptor -------------//
    p_desc = tu_desc_next(p_desc);
    uint8_t numEp = desc_itf->bNumEndpoints;
    TU_ASSERT(usbd_open_edpt_pair(rhport, p_desc, numEp, TUSB_XFER_BULK, &p_itf->ep_out, &p_itf->ep_in), 0);
    drv_len += numEp * sizeof(tusb_desc_endpoint_t);

    if (p_itf->ep_out)
    {
        _prep_out_transaction(p_itf);
    }

    if (p_itf->ep_in)
    {
        tud_ccid_write_n_flush(p_itf);
    }

    return drv_len;
}

static bool ccid_control_xfer_cb(uint8_t rhport, uint8_t stage, tusb_control_request_t const *request)
{
    return false; // no control transfers supported
}

static bool ccid_xfer_cb(uint8_t rhport, uint8_t ep_addr, xfer_result_t result, uint32_t xferred_bytes)
{
    (void)rhport;
    (void)result;

    uint8_t itf;
    ccidd_interface_t *p_itf;

    for (itf = 0; itf < CFG_TUD_CCID; itf++)
    { // Identify which interface to use
        p_itf = &_ccidd_itf[itf];
        if ((ep_addr == p_itf->ep_out) || (ep_addr == p_itf->ep_in))
            break;
    }
    TU_ASSERT(itf < CFG_TUD_CCID);

    if (ep_addr == p_itf->ep_out)
    { // receive new data
        tu_fifo_write_n(&p_itf->rx_ff, p_itf->epout_buf, (uint16_t)xferred_bytes);

        if (tud_ccid_rx_cb) // invoke receive callback if available
            tud_ccid_rx_cb(itf);

        _prep_out_transaction(p_itf); // prepare for next
    }
    else if (ep_addr == p_itf->ep_in)
    {
        if (tud_ccid_tx_cb)
            tud_ccid_tx_cb(itf, (uint16_t)xferred_bytes);

        tud_ccid_write_n_flush(p_itf);
    }

    return true;
}

uint32_t tud_ccid_n_available(uint8_t itf) { return tu_fifo_count(&_ccidd_itf[itf].rx_ff); }

bool tud_ccid_n_mounted(uint8_t itf) {
  // Return true if the interface is mounted
  return _ccidd_itf[itf].ep_in && _ccidd_itf[itf].ep_out;
}

// static void ccid_sof(uint8_t rhport, uint32_t frame_count) { }// optional

static usbd_class_driver_t const _ccid_driver = {
#if CFG_TUSB_DEBUG >= 2
    .name = "CCID", //
#endif
    .init = ccid_init,                       //
    .reset = ccid_reset,                     //
    .open = ccid_open,                       //
    .control_xfer_cb = ccid_control_xfer_cb, //
    .xfer_cb = ccid_xfer_cb,                 //
    .sof = NULL};

usbd_class_driver_t const *usbd_app_driver_get_cb(uint8_t *driver_count)
{ // callback to add application driver
    *driver_count = 1;
    return &_ccid_driver;
}