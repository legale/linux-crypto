/*
 * GOST R 34.12-2015 (Kyznyechik) cipher.
 *
 * Copyright (c) 2018 Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */
#ifndef _CRYPTO_KUZNYECHIK_H
#define _CRYPTO_KUZNYECHIK_H

#define KUZNYECHIK_KEY_SIZE	32
#define KUZNYECHIK_BLOCK_SIZE	16

#include <linux/scatterlist.h>
#include <linux/types.h>

struct crypto_shash;
struct crypto_skcipher;

int kuznechik_ctr_omac_sg(struct crypto_skcipher *cipher,
  struct crypto_shash *mac, struct scatterlist *sg, int nents,
  unsigned int assoc_len, unsigned int data_len,
  const u8 iv[KUZNYECHIK_BLOCK_SIZE], bool encrypt,
  u8 tag[KUZNYECHIK_BLOCK_SIZE]);

#endif
