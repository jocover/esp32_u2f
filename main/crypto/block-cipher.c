// SPDX-License-Identifier: Apache-2.0
#include <block-cipher.h>
#include <memzero.h>
#include <string.h>

static void xor_buf(const uint8_t *in, uint8_t *out, size_t len);
static void increment_iv(uint8_t *iv, uint8_t block_size);

int block_cipher_enc(block_cipher_config *cfg) {
  if (cfg->block_size % 8 != 0 || cfg->in_size % cfg->block_size != 0) return -1;

  uint8_t buf_in[cfg->block_size], iv_buf[cfg->block_size];
  int blocks = cfg->in_size / cfg->block_size;

  if (cfg->mode != ECB) {
    if (cfg->iv == NULL) return -1;
    memcpy(iv_buf, cfg->iv, cfg->block_size);
  }

  int ret = 0;
  for (int idx = 0; idx < blocks; idx++) {
    switch (cfg->mode) {
    case ECB:
      ret = cfg->encrypt(cfg->in + idx * cfg->block_size, cfg->out + idx * cfg->block_size, cfg->key);
      break;
    case CBC:
      memcpy(buf_in, cfg->in + idx * cfg->block_size, cfg->block_size);
      xor_buf(iv_buf, buf_in, cfg->block_size);
      ret = cfg->encrypt(buf_in, cfg->out + idx * cfg->block_size, cfg->key);
      if (ret < 0) break;
      ret = cfg->encrypt(buf_in, iv_buf, cfg->key);
      memcpy(cfg->out + idx * cfg->block_size, iv_buf, cfg->block_size);
      break;
    case CFB:
      ret = cfg->encrypt(iv_buf, iv_buf, cfg->key);
      xor_buf(cfg->in + idx * cfg->block_size, iv_buf, cfg->block_size);
      memcpy(cfg->out + idx * cfg->block_size, iv_buf, cfg->block_size);
      break;
    case OFB:
      ret = cfg->encrypt(iv_buf, iv_buf, cfg->key);
      memcpy(buf_in, cfg->in + idx * cfg->block_size, cfg->block_size);
      xor_buf(iv_buf, buf_in, cfg->block_size);
      memcpy(cfg->out + idx * cfg->block_size, buf_in, cfg->block_size);
      break;
    case CTR:
      ret = cfg->encrypt(iv_buf, buf_in, cfg->key);
      xor_buf(cfg->in + idx * cfg->block_size, buf_in, cfg->block_size);
      memcpy(cfg->out + idx * cfg->block_size, buf_in, cfg->block_size);
      increment_iv(iv_buf, cfg->block_size);
      break;
    default:
      ret = -1;
      break;
    }
    if (ret < 0) break;
  }

  memzero(buf_in, sizeof(buf_in));
  memzero(iv_buf, sizeof(iv_buf));
  return ret;
}

int block_cipher_dec(block_cipher_config *cfg) {
  if (cfg->block_size % 8 != 0 || cfg->in_size % cfg->block_size != 0) return -1;

  uint8_t buf_in[cfg->block_size], iv_buf[cfg->block_size];
  int blocks = cfg->in_size / cfg->block_size;

  if (cfg->mode != ECB) {
    if (cfg->iv == NULL) return -1;
    memcpy(iv_buf, cfg->iv, cfg->block_size);
  }

  int ret = 0;
  for (int idx = 0; idx < blocks; idx++) {
    switch (cfg->mode) {
    case ECB:
      ret = cfg->decrypt(cfg->in + idx * cfg->block_size, cfg->out + idx * cfg->block_size, cfg->key);
      break;
    case CBC:
      memcpy(buf_in, cfg->in + idx * cfg->block_size, cfg->block_size);
      ret = cfg->decrypt(buf_in, cfg->out + idx * cfg->block_size, cfg->key);
      xor_buf(iv_buf, cfg->out + idx * cfg->block_size, cfg->block_size);
      memcpy(iv_buf, buf_in, cfg->block_size);
      break;
    case CFB:
      ret = cfg->encrypt(iv_buf, iv_buf, cfg->key);
      memcpy(buf_in, cfg->in + idx * cfg->block_size, cfg->block_size);
      xor_buf(cfg->in + idx * cfg->block_size, iv_buf, cfg->block_size);
      memcpy(cfg->out + idx * cfg->block_size, iv_buf, cfg->block_size);
      memcpy(iv_buf, buf_in, cfg->block_size);
      break;
    case OFB:
      ret = cfg->encrypt(iv_buf, iv_buf, cfg->key);
      memcpy(buf_in, cfg->in + idx * cfg->block_size, cfg->block_size);
      xor_buf(iv_buf, buf_in, cfg->block_size);
      memcpy(cfg->out + idx * cfg->block_size, buf_in, cfg->block_size);
      break;
    case CTR:
      ret = cfg->encrypt(iv_buf, buf_in, cfg->key);
      xor_buf(cfg->in + idx * cfg->block_size, buf_in, cfg->block_size);
      memcpy(cfg->out + idx * cfg->block_size, buf_in, cfg->block_size);
      increment_iv(iv_buf, cfg->block_size);
      break;
    default:
      ret = -1;
      break;
    }
    if (ret < 0) break;
  }

  memzero(buf_in, sizeof(buf_in));
  memzero(iv_buf, sizeof(iv_buf));
  return ret;
}

static void xor_buf(const uint8_t *in, uint8_t *out, size_t len) {
  size_t idx;

  for (idx = 0; idx < len; idx++)
    out[idx] ^= in[idx];
}

static void increment_iv(uint8_t *iv, uint8_t block_size) {
  for (int idx = block_size - 1; idx >= 0; idx--) {
    iv[idx]++;
    if (iv[idx] != 0) break;
  }
}
