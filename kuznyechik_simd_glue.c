// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * GOST R 34.12-2015 (Kuznyechik), x86-64 SIMD implementation.
 */

#include <crypto/internal/hash.h>
#include <crypto/internal/simd.h>
#include <crypto/internal/skcipher.h>
#include <linux/crypto.h>
#include <linux/module.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h>
#endif

#include <asm/cpufeature.h>
#include <asm/simd.h>

#include <crypto/kuznyechik.h>

#include "kuztable.h"

#define KUZ_SUBKEYS_SIZE (KUZNYECHIK_BLOCK_SIZE * 10)
#define KUZ_PAR_BLOCKS 4
#define KUZ_PAR_SIZE (KUZ_PAR_BLOCKS * KUZNYECHIK_BLOCK_SIZE)

struct kuz_simd_ctx {
  u8 key[KUZ_SUBKEYS_SIZE];
  u8 dekey[KUZ_SUBKEYS_SIZE];
};

struct kuz_cmac_ctx {
  struct kuz_simd_ctx cipher;
  u8 k1[KUZNYECHIK_BLOCK_SIZE];
  u8 k2[KUZNYECHIK_BLOCK_SIZE];
};

struct kuz_cmac_desc_ctx {
  u8 state[KUZNYECHIK_BLOCK_SIZE];
  u8 buf[KUZNYECHIK_BLOCK_SIZE];
  unsigned int len;
};

asmlinkage void kuz_encrypt_1way(const u8 *key, u8 *dst, const u8 *src,
                                 const u8 *table);
asmlinkage void kuz_encrypt_4way(const u8 *key, u8 *dst, const u8 *src,
                                 const u8 *table);
asmlinkage void kuz_decrypt_4way(const u8 *dekey, u8 *dst, const u8 *src,
                                 const u8 *inv_table,
                                 const u8 *inv_ls_table);

static void kuz_l(u8 *out, const u8 *in, const u8 table[16][256 * 16])
{
  u64 lo = 0;
  u64 hi = 0;
  const u8 *p;
  unsigned int i;

  for (i = 0; i < KUZNYECHIK_BLOCK_SIZE; i++) {
    p = &table[i][in[i] * KUZNYECHIK_BLOCK_SIZE];
    lo ^= get_unaligned_le64(p);
    hi ^= get_unaligned_le64(p + sizeof(lo));
  }

  put_unaligned_le64(lo, out);
  put_unaligned_le64(hi, out + sizeof(lo));
}

static void kuz_lsx(u8 *out, const u8 *in, const u8 *key)
{
  u8 block[KUZNYECHIK_BLOCK_SIZE];
  unsigned int i;

  for (i = 0; i < KUZNYECHIK_BLOCK_SIZE; i++)
    block[i] = in[i] ^ key[i];
  kuz_l(out, block, kuz_table);
}

static void kuz_subkey(u8 *out, const u8 *key, unsigned int n)
{
  u8 block[KUZNYECHIK_BLOCK_SIZE];

  kuz_lsx(block, key, kuz_key_table[n]);
  crypto_xor_cpy(out + 16, block, key + 16, 16);
  kuz_lsx(block, out + 16, kuz_key_table[n + 1]);
  crypto_xor_cpy(out, block, key, 16);
  kuz_lsx(block, out, kuz_key_table[n + 2]);
  crypto_xor(out + 16, block, 16);
  kuz_lsx(block, out + 16, kuz_key_table[n + 3]);
  crypto_xor(out, block, 16);
  kuz_lsx(block, out, kuz_key_table[n + 4]);
  crypto_xor(out + 16, block, 16);
  kuz_lsx(block, out + 16, kuz_key_table[n + 5]);
  crypto_xor(out, block, 16);
  kuz_lsx(block, out, kuz_key_table[n + 6]);
  crypto_xor(out + 16, block, 16);
  kuz_lsx(block, out + 16, kuz_key_table[n + 7]);
  crypto_xor(out, block, 16);
}

static int kuz_expand_key(struct kuz_simd_ctx *ctx, const u8 *key,
                          unsigned int key_len)
{
  unsigned int i;

  if (key_len != KUZNYECHIK_KEY_SIZE)
    return -EINVAL;

  memcpy(ctx->key, key, KUZNYECHIK_KEY_SIZE);
  kuz_subkey(ctx->key + 32, ctx->key, 0);
  kuz_subkey(ctx->key + 64, ctx->key + 32, 8);
  kuz_subkey(ctx->key + 96, ctx->key + 64, 16);
  kuz_subkey(ctx->key + 128, ctx->key + 96, 24);

  for (i = 0; i < 10; i++)
    kuz_l(ctx->dekey + 16 * i, ctx->key + 16 * i, kuz_table_inv);

  return 0;
}

static int kuz_simd_setkey(struct crypto_skcipher *tfm, const u8 *key,
                           unsigned int key_len)
{
  return kuz_expand_key(crypto_skcipher_ctx(tfm), key, key_len);
}

static void kuz_decrypt_final(const struct kuz_simd_ctx *ctx, u8 *dst,
                              unsigned int bytes)
{
  unsigned int i;

  for (i = 0; i < bytes; i++)
    dst[i] = pi_inv[dst[i]] ^ ctx->key[i & 15];
}

static void kuz_encrypt_blocks(const struct kuz_simd_ctx *ctx, u8 *dst,
                               const u8 *src, unsigned int bytes)
{
  while (bytes >= KUZ_PAR_SIZE) {
    kuz_encrypt_4way(ctx->key, dst, src, (const u8 *)kuz_table);
    bytes -= KUZ_PAR_SIZE;
    src += KUZ_PAR_SIZE;
    dst += KUZ_PAR_SIZE;
  }

  while (bytes) {
    kuz_encrypt_1way(ctx->key, dst, src, (const u8 *)kuz_table);
    bytes -= KUZNYECHIK_BLOCK_SIZE;
    src += KUZNYECHIK_BLOCK_SIZE;
    dst += KUZNYECHIK_BLOCK_SIZE;
  }
}

static void kuz_decrypt_blocks(const struct kuz_simd_ctx *ctx, u8 *dst,
                               const u8 *src, unsigned int bytes)
{
  u8 in[KUZ_PAR_SIZE] __aligned(16);
  u8 out[KUZ_PAR_SIZE] __aligned(16);

  while (bytes >= KUZ_PAR_SIZE) {
    kuz_decrypt_4way(ctx->dekey, dst, src, (const u8 *)kuz_table_inv,
                     (const u8 *)kuz_table_inv_LS);
    kuz_decrypt_final(ctx, dst, KUZ_PAR_SIZE);
    bytes -= KUZ_PAR_SIZE;
    src += KUZ_PAR_SIZE;
    dst += KUZ_PAR_SIZE;
  }

  if (!bytes)
    return;

  memcpy(in, src, bytes);
  memset(in + bytes, 0, KUZ_PAR_SIZE - bytes);
  kuz_decrypt_4way(ctx->dekey, out, in, (const u8 *)kuz_table_inv,
                   (const u8 *)kuz_table_inv_LS);
  kuz_decrypt_final(ctx, out, bytes);
  memcpy(dst, out, bytes);
}

static int kuz_simd_crypt(struct skcipher_request *req, bool decrypt)
{
  struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
  const struct kuz_simd_ctx *ctx = crypto_skcipher_ctx(tfm);
  struct skcipher_walk walk;
  unsigned int bytes;
  int err;

  if (!crypto_simd_usable())
    return -EOPNOTSUPP;

  err = skcipher_walk_virt(&walk, req, false);
  while (walk.nbytes) {
    bytes = round_down(walk.nbytes, KUZNYECHIK_BLOCK_SIZE);

    kernel_fpu_begin();
    if (decrypt)
      kuz_decrypt_blocks(ctx, walk.dst.virt.addr, walk.src.virt.addr,
                         bytes);
    else
      kuz_encrypt_blocks(ctx, walk.dst.virt.addr, walk.src.virt.addr,
                         bytes);
    kernel_fpu_end();

    err = skcipher_walk_done(&walk, walk.nbytes - bytes);
  }

  return err;
}

static int kuz_simd_encrypt(struct skcipher_request *req)
{
  return kuz_simd_crypt(req, false);
}

static int kuz_simd_decrypt(struct skcipher_request *req)
{
  return kuz_simd_crypt(req, true);
}

static void kuz_ctr_blocks(const struct kuz_simd_ctx *ctx, u8 *dst,
                           const u8 *src, unsigned int bytes, u8 *ctr)
{
  u8 counters[KUZ_PAR_SIZE] __aligned(16);
  u8 stream[KUZ_PAR_SIZE] __aligned(16);
  unsigned int i;
  unsigned int n;

  while (bytes >= KUZ_PAR_SIZE) {
    for (i = 0; i < KUZ_PAR_BLOCKS; i++) {
      memcpy(counters + i * KUZNYECHIK_BLOCK_SIZE, ctr,
             KUZNYECHIK_BLOCK_SIZE);
      crypto_inc(ctr, KUZNYECHIK_BLOCK_SIZE);
    }
    kuz_encrypt_4way(ctx->key, stream, counters, (const u8 *)kuz_table);
    crypto_xor_cpy(dst, src, stream, KUZ_PAR_SIZE);
    bytes -= KUZ_PAR_SIZE;
    src += KUZ_PAR_SIZE;
    dst += KUZ_PAR_SIZE;
  }

  while (bytes) {
    kuz_encrypt_1way(ctx->key, stream, ctr, (const u8 *)kuz_table);
    n = min_t(unsigned int, bytes, KUZNYECHIK_BLOCK_SIZE);
    crypto_xor_cpy(dst, src, stream, n);
    crypto_inc(ctr, KUZNYECHIK_BLOCK_SIZE);
    bytes -= n;
    src += n;
    dst += n;
  }
}

static int kuz_ctr_crypt(struct skcipher_request *req)
{
  struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
  const struct kuz_simd_ctx *ctx = crypto_skcipher_ctx(tfm);
  struct skcipher_walk walk;
  unsigned int bytes;
  int err;

  if (!crypto_simd_usable())
    return -EOPNOTSUPP;

  err = skcipher_walk_virt(&walk, req, false);
  while (walk.nbytes) {
    bytes = walk.nbytes;
    if (bytes < walk.total)
      bytes = round_down(bytes, walk.stride);

    kernel_fpu_begin();
    kuz_ctr_blocks(ctx, walk.dst.virt.addr, walk.src.virt.addr, bytes,
                   walk.iv);
    kernel_fpu_end();

    err = skcipher_walk_done(&walk, walk.nbytes - bytes);
  }

  return err;
}

static void kuz_cmac_double(u8 *out, const u8 *in)
{
  u8 carry = in[0] >> 7;
  unsigned int i;

  for (i = 0; i < KUZNYECHIK_BLOCK_SIZE - 1; i++)
    out[i] = (in[i] << 1) | (in[i + 1] >> 7);
  out[KUZNYECHIK_BLOCK_SIZE - 1] = (in[KUZNYECHIK_BLOCK_SIZE - 1] << 1) ^
                                   (0x87 & -carry);
}

static int kuz_cmac_setkey(struct crypto_shash *tfm, const u8 *key,
                           unsigned int key_len)
{
  struct kuz_cmac_ctx *ctx = crypto_shash_ctx(tfm);
  u8 block[KUZNYECHIK_BLOCK_SIZE] = {};
  int err;

  err = kuz_expand_key(&ctx->cipher, key, key_len);
  if (err)
    return err;
  if (!crypto_simd_usable())
    return -EOPNOTSUPP;

  kernel_fpu_begin();
  kuz_encrypt_1way(ctx->cipher.key, block, block, (const u8 *)kuz_table);
  kernel_fpu_end();
  kuz_cmac_double(ctx->k1, block);
  kuz_cmac_double(ctx->k2, ctx->k1);
  memzero_explicit(block, sizeof(block));
  return 0;
}

static int kuz_cmac_init(struct shash_desc *desc)
{
  struct kuz_cmac_desc_ctx *dctx = shash_desc_ctx(desc);

  memset(dctx, 0, sizeof(*dctx));
  return 0;
}

static void kuz_cmac_process(const struct kuz_cmac_ctx *ctx,
                             struct kuz_cmac_desc_ctx *dctx,
                             const u8 *block)
{
  u8 tmp[KUZNYECHIK_BLOCK_SIZE];

  crypto_xor_cpy(tmp, dctx->state, block, KUZNYECHIK_BLOCK_SIZE);
  kuz_encrypt_1way(ctx->cipher.key, dctx->state, tmp,
                   (const u8 *)kuz_table);
}

static int kuz_cmac_update(struct shash_desc *desc, const u8 *data,
                           unsigned int len)
{
  const struct kuz_cmac_ctx *ctx = crypto_shash_ctx(desc->tfm);
  struct kuz_cmac_desc_ctx *dctx = shash_desc_ctx(desc);
  unsigned int n;

  if (!len)
    return 0;
  if (!crypto_simd_usable())
    return -EOPNOTSUPP;

  kernel_fpu_begin();
  if (dctx->len == KUZNYECHIK_BLOCK_SIZE) {
    kuz_cmac_process(ctx, dctx, dctx->buf);
    dctx->len = 0;
  }
  if (dctx->len) {
    n = min_t(unsigned int, len, KUZNYECHIK_BLOCK_SIZE - dctx->len);
    memcpy(dctx->buf + dctx->len, data, n);
    dctx->len += n;
    data += n;
    len -= n;
    if (dctx->len == KUZNYECHIK_BLOCK_SIZE && len) {
      kuz_cmac_process(ctx, dctx, dctx->buf);
      dctx->len = 0;
    }
  }
  while (len > KUZNYECHIK_BLOCK_SIZE) {
    kuz_cmac_process(ctx, dctx, data);
    data += KUZNYECHIK_BLOCK_SIZE;
    len -= KUZNYECHIK_BLOCK_SIZE;
  }
  if (len) {
    memcpy(dctx->buf + dctx->len, data, len);
    dctx->len += len;
  }
  kernel_fpu_end();
  return 0;
}

static int kuz_cmac_final(struct shash_desc *desc, u8 *out)
{
  const struct kuz_cmac_ctx *ctx = crypto_shash_ctx(desc->tfm);
  struct kuz_cmac_desc_ctx *dctx = shash_desc_ctx(desc);
  u8 block[KUZNYECHIK_BLOCK_SIZE] = {};

  if (!crypto_simd_usable())
    return -EOPNOTSUPP;

  if (dctx->len == KUZNYECHIK_BLOCK_SIZE) {
    crypto_xor_cpy(block, dctx->buf, ctx->k1,
                   KUZNYECHIK_BLOCK_SIZE);
  } else {
    memcpy(block, dctx->buf, dctx->len);
    block[dctx->len] = 0x80;
    crypto_xor(block, ctx->k2, KUZNYECHIK_BLOCK_SIZE);
  }
  crypto_xor(block, dctx->state, KUZNYECHIK_BLOCK_SIZE);

  kernel_fpu_begin();
  kuz_encrypt_1way(ctx->cipher.key, out, block, (const u8 *)kuz_table);
  kernel_fpu_end();
  memzero_explicit(block, sizeof(block));
  return 0;
}

static struct skcipher_alg kuz_simd_algs[] = {
  {
    .base.cra_name = "ecb(kuznyechik-simd)",
    .base.cra_driver_name = "ecb-kuznyechik-simd-x86_64",
    .base.cra_priority = 300,
    .base.cra_blocksize = KUZNYECHIK_BLOCK_SIZE,
    .base.cra_ctxsize = sizeof(struct kuz_simd_ctx),
    .base.cra_module = THIS_MODULE,
    .min_keysize = KUZNYECHIK_KEY_SIZE,
    .max_keysize = KUZNYECHIK_KEY_SIZE,
    .chunksize = KUZ_PAR_SIZE,
    .setkey = kuz_simd_setkey,
    .encrypt = kuz_simd_encrypt,
    .decrypt = kuz_simd_decrypt,
  }, {
    .base.cra_name = "ctr(kuznyechik-simd)",
    .base.cra_driver_name = "ctr-kuznyechik-simd-x86_64",
    .base.cra_priority = 300,
    .base.cra_blocksize = 1,
    .base.cra_ctxsize = sizeof(struct kuz_simd_ctx),
    .base.cra_module = THIS_MODULE,
    .min_keysize = KUZNYECHIK_KEY_SIZE,
    .max_keysize = KUZNYECHIK_KEY_SIZE,
    .ivsize = KUZNYECHIK_BLOCK_SIZE,
    .chunksize = KUZ_PAR_SIZE,
    .setkey = kuz_simd_setkey,
    .encrypt = kuz_ctr_crypt,
    .decrypt = kuz_ctr_crypt,
  },
};

static struct shash_alg kuz_cmac_alg = {
  .digestsize = KUZNYECHIK_BLOCK_SIZE,
  .init = kuz_cmac_init,
  .update = kuz_cmac_update,
  .final = kuz_cmac_final,
  .setkey = kuz_cmac_setkey,
  .descsize = sizeof(struct kuz_cmac_desc_ctx),
  .base = {
    .cra_name = "cmac(kuznyechik-simd)",
    .cra_driver_name = "cmac-kuznyechik-simd-x86_64",
    .cra_priority = 300,
    .cra_flags = CRYPTO_ALG_TYPE_SHASH,
    .cra_blocksize = KUZNYECHIK_BLOCK_SIZE,
    .cra_ctxsize = sizeof(struct kuz_cmac_ctx),
    .cra_module = THIS_MODULE,
  },
};

static int __init kuz_simd_init(void)
{
  int err;

  if (!boot_cpu_has(X86_FEATURE_XMM2))
    return -ENODEV;

  err = crypto_register_skciphers(kuz_simd_algs,
                                  ARRAY_SIZE(kuz_simd_algs));
  if (err)
    return err;
  err = crypto_register_shash(&kuz_cmac_alg);
  if (err)
    crypto_unregister_skciphers(kuz_simd_algs,
                                ARRAY_SIZE(kuz_simd_algs));
  return err;
}

static void __exit kuz_simd_exit(void)
{
  crypto_unregister_shash(&kuz_cmac_alg);
  crypto_unregister_skciphers(kuz_simd_algs, ARRAY_SIZE(kuz_simd_algs));
}

module_init(kuz_simd_init);
module_exit(kuz_simd_exit);

MODULE_DESCRIPTION("GOST R 34.12-2015 Kuznyechik x86-64 SIMD cipher");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS_CRYPTO("ecb(kuznyechik-simd)");
MODULE_ALIAS_CRYPTO("ctr(kuznyechik-simd)");
MODULE_ALIAS_CRYPTO("cmac(kuznyechik-simd)");
