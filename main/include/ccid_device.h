#ifndef _DEVICE_CCID_H_
#define _DEVICE_CCID_H_

#include "tusb.h"
#include "ccid.h"

#define CFG_TUD_CCID 			(1)

#define CFG_TUD_CCID_EP_BUFSIZE	64

// Starting endpoints; adjusted elsewhere as needed
#define CCID_EPOUT				(0x02)
#define CCID_EPIN				(0x82)

#define CCID_HDR_SZ				(10) // CCID message header size
#define CCID_DESC_SZ			(54) // CCID function descriptor size
#define CCID_DESC_TYPE_CCID		(0x21) // CCID Descriptor

#define CCID_VERSION			(0x0110)
#define CCID_IFSD				  (ABDATA_SIZE)
#define CCID_FEATURES			(0x40000 | 0x40 | 0x20 | 0x10 | 0x08 | 0x04 | 0x02)
#define CCID_MSGLEN				(CCID_IFSD + CCID_HDR_SZ)
#define CCID_CLAGET				(0xFF)
#define CCID_CLAENV				(0xFF)

#define CFG_TUD_CCID_TX_BUFSIZE	CCID_MSGLEN*8
#define CFG_TUD_CCID_RX_BUFSIZE	CCID_MSGLEN*8

#define TUD_CCID_DESC_LEN (9 + CCID_DESC_SZ + 7 + 7)

// CCID Descriptor Template
// Interface number, string index, EP notification address and size, EP data address (out, in) and size.
#define TUD_CCID_DESCRIPTOR(_itfnum, _stridx, _epout, _epin, _epsize) \
  /* CCID Interface */\
  9, TUSB_DESC_INTERFACE, _itfnum, 0, 2, TUSB_CLASS_SMART_CARD, 0, 0, _stridx,\
  /* CCID Function, version, max slot index, supported voltages and protocols */\
  CCID_DESC_SZ, CCID_DESC_TYPE_CCID, U16_TO_U8S_LE(CCID_VERSION), 0, 0x7, U32_TO_U8S_LE(3),\
  /* default clock, maximum clock, num clocks, current datarate, max datarate */\
  U32_TO_U8S_LE(4000), U32_TO_U8S_LE(5000), 0, U32_TO_U8S_LE(9600), U32_TO_U8S_LE(625000),\
  /* num datarates, max IFSD, sync. protocols, mechanical, features */\
  0, U32_TO_U8S_LE(CCID_IFSD), U32_TO_U8S_LE(0), U32_TO_U8S_LE(0), U32_TO_U8S_LE(CCID_FEATURES),\
  /* max msg len, get response CLA, envelope CLA, LCD layout, PIN support, max busy slots */\
  U32_TO_U8S_LE(CCID_MSGLEN), CCID_CLAGET, CCID_CLAENV, U16_TO_U8S_LE(0), 0, 1,\
  \
  /* Endpoint Out */\
  7, TUSB_DESC_ENDPOINT, _epout, TUSB_XFER_BULK, U16_TO_U8S_LE(_epsize), 0,\
  /* Endpoint In */\
  7, TUSB_DESC_ENDPOINT, _epin, TUSB_XFER_BULK, U16_TO_U8S_LE(_epsize), 0\


typedef struct {
	uint8_t itf_num;
	uint8_t ep_in;
	uint8_t ep_out;

	tu_fifo_t rx_ff;	// nothing is cleared on reset from here on
	tu_fifo_t tx_ff;
	uint8_t rx_ff_buf[CFG_TUD_CCID_RX_BUFSIZE];
	uint8_t tx_ff_buf[CFG_TUD_CCID_TX_BUFSIZE];

	CFG_TUSB_MEM_ALIGN uint8_t epout_buf[CFG_TUD_CCID_EP_BUFSIZE];
	CFG_TUSB_MEM_ALIGN uint8_t epin_buf[CFG_TUD_CCID_EP_BUFSIZE];
} ccidd_interface_t;

TU_ATTR_WEAK void tud_ccid_rx_cb(uint8_t itf);
TU_ATTR_WEAK void tud_ccid_tx_cb(uint8_t itf, uint16_t xferred_bytes);

bool tud_ccid_n_mounted(uint8_t itf);
uint32_t tud_ccid_n_available(uint8_t itf);
uint32_t tud_ccid_n_read(uint8_t itf, void *buffer, uint32_t bufsize);
uint32_t tud_ccid_n_write(uint8_t itf, void const*buffer, uint32_t bufsize);
uint32_t tud_ccid_write_n_flush(ccidd_interface_t *p_itf);

static inline uint32_t tud_ccid_read (void* buffer, uint32_t bufsize)
{
  return tud_ccid_n_read(0, buffer, bufsize);
}

static inline uint32_t tud_ccid_write (void const* buffer, uint32_t bufsize)
{
  return tud_ccid_n_write(0, buffer, bufsize);
}

static inline uint32_t tud_ccid_write_flush (void)
{
  return tud_ccid_write_n_flush(0);
}

static inline uint32_t tud_ccid_available(void) { return tud_ccid_n_available(0); }

static inline bool tud_ccid_mounted(void) { return tud_ccid_n_mounted(0); }

#endif //_CCID_H_