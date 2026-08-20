/*
 * GOST R 34.12-2015 (Kuznyechik) cipher.
 *
 * Copyright (c) 2018 Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#include <linux/crypto.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h>
#endif

#include <crypto/algapi.h>
#include <crypto/kuznyechik.h>

#if defined(CONFIG_ARM64)
#include <asm/cputype.h>
#endif

#include "kuztable.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
static inline void crypto_xor_cpy(u8 *dst, const u8 *src1, const u8 *src2,
				  unsigned int size)
{
	memcpy(dst, src1, size);
	crypto_xor(dst, src2, size);
}
#endif

#define KUZNYECHIK_SUBKEYS_SIZE (16 * 10)
#if defined(CONFIG_ARM64)
#define KUZ_BENCH_BLOCKS 8
#else
#define KUZ_BENCH_BLOCKS 4
#endif
#define KUZ_BENCH_SIZE (KUZ_BENCH_BLOCKS * KUZNYECHIK_BLOCK_SIZE)
#define KUZ_BENCH_RUNS 3
#define KUZ_GENERIC_VERSION "20260821.1"
#define KUZ_BENCH_CHUNKS 512

static unsigned int bench_ms;
module_param(bench_ms, uint, 0444);
MODULE_PARM_DESC(bench_ms, "benchmark duration per run in milliseconds (0 disables)");

struct crypto_kuznyechik_ctx {
	u8 key[KUZNYECHIK_SUBKEYS_SIZE];
	u8 dekey[KUZNYECHIK_SUBKEYS_SIZE];
};

static void S(u8 *a, const u8 *b)
{
	a[0] = pi[b[0]];
	a[1] = pi[b[1]];
	a[2] = pi[b[2]];
	a[3] = pi[b[3]];
	a[4] = pi[b[4]];
	a[5] = pi[b[5]];
	a[6] = pi[b[6]];
	a[7] = pi[b[7]];
	a[8] = pi[b[8]];
	a[9] = pi[b[9]];
	a[10] = pi[b[10]];
	a[11] = pi[b[11]];
	a[12] = pi[b[12]];
	a[13] = pi[b[13]];
	a[14] = pi[b[14]];
	a[15] = pi[b[15]];
}

static void Sinv(u8 *a, const u8 *b)
{
	a[0] = pi_inv[b[0]];
	a[1] = pi_inv[b[1]];
	a[2] = pi_inv[b[2]];
	a[3] = pi_inv[b[3]];
	a[4] = pi_inv[b[4]];
	a[5] = pi_inv[b[5]];
	a[6] = pi_inv[b[6]];
	a[7] = pi_inv[b[7]];
	a[8] = pi_inv[b[8]];
	a[9] = pi_inv[b[9]];
	a[10] = pi_inv[b[10]];
	a[11] = pi_inv[b[11]];
	a[12] = pi_inv[b[12]];
	a[13] = pi_inv[b[13]];
	a[14] = pi_inv[b[14]];
	a[15] = pi_inv[b[15]];
}

static void Linv(u8 *a, const u8 *b)
{
	memcpy(a, &kuz_table_inv[0][b[0] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[1][b[1] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[2][b[2] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[3][b[3] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[4][b[4] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[5][b[5] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[6][b[6] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[7][b[7] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[8][b[8] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[9][b[9] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[10][b[10] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[11][b[11] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[12][b[12] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[13][b[13] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[14][b[14] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[15][b[15] * 16], KUZNYECHIK_BLOCK_SIZE);
}

static void LSX(u8 *a, const u8 *b, const u8 *c)
{
	u8 t[16];

	memcpy(t, &kuz_table[0][(b[0] ^ c[0]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[1][(b[1] ^ c[1]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[2][(b[2] ^ c[2]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[3][(b[3] ^ c[3]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[4][(b[4] ^ c[4]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[5][(b[5] ^ c[5]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[6][(b[6] ^ c[6]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[7][(b[7] ^ c[7]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[8][(b[8] ^ c[8]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[9][(b[9] ^ c[9]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[10][(b[10] ^ c[10]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[11][(b[11] ^ c[11]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[12][(b[12] ^ c[12]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[13][(b[13] ^ c[13]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[14][(b[14] ^ c[14]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor_cpy(a, t, &kuz_table[15][(b[15] ^ c[15]) * 16], KUZNYECHIK_BLOCK_SIZE);
}

static void XLiSi(u8 *a, const u8 *b, const u8 *c)
{
	u8 t[16];

	memcpy(t, &kuz_table_inv_LS[0][b[0] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[1][b[1] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[2][b[2] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[3][b[3] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[4][b[4] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[5][b[5] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[6][b[6] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[7][b[7] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[8][b[8] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[9][b[9] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[10][b[10] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[11][b[11] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[12][b[12] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[13][b[13] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[14][b[14] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[15][b[15] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor_cpy(a, t, c, 16);
}

static void subkey(u8 *out, const u8 *key, unsigned int i)
{
	u8 test[16];

	LSX(test, key+0, kuz_key_table[i + 0]);
	crypto_xor_cpy(out+16, test, key + 16, 16);
	LSX(test, out+16, kuz_key_table[i + 1]);
	crypto_xor_cpy(out+0, test, key + 0, 16);
	LSX(test, out+0, kuz_key_table[i + 2]);
	crypto_xor(out+16, test, 16);
	LSX(test, out+16, kuz_key_table[i + 3]);
	crypto_xor(out+0, test, 16);
	LSX(test, out+0, kuz_key_table[i + 4]);
	crypto_xor(out+16, test, 16);
	LSX(test, out+16, kuz_key_table[i + 5]);
	crypto_xor(out+0, test, 16);
	LSX(test, out+0, kuz_key_table[i + 6]);
	crypto_xor(out+16, test, 16);
	LSX(test, out+16, kuz_key_table[i + 7]);
	crypto_xor(out+0, test, 16);
}

static int kuznyechik_expand_key(struct crypto_kuznyechik_ctx *ctx,
		const u8 *in_key, unsigned int key_len)
{
	unsigned int i;

	if (key_len != KUZNYECHIK_KEY_SIZE)
		return -EINVAL;

	memcpy(ctx->key, in_key, 32);
	subkey(ctx->key + 32, ctx->key, 0);
	subkey(ctx->key + 64, ctx->key + 32, 8);
	subkey(ctx->key + 96, ctx->key + 64, 16);
	subkey(ctx->key + 128, ctx->key + 96, 24);
	for (i = 0; i < 10; i++)
		Linv(ctx->dekey + 16 * i, ctx->key + 16 * i);

	return 0;
}

static int kuznyechik_set_key(struct crypto_tfm *tfm, const u8 *in_key,
		unsigned int key_len)
{
	return kuznyechik_expand_key(crypto_tfm_ctx(tfm), in_key, key_len);
}

static void kuznyechik_encrypt_ctx(const struct crypto_kuznyechik_ctx *ctx,
		u8 *out, const u8 *in)
{
	u8 temp[KUZNYECHIK_BLOCK_SIZE];

	LSX(temp, ctx->key + 16 * 0, in);
	LSX(temp, ctx->key + 16 * 1, temp);
	LSX(temp, ctx->key + 16 * 2, temp);
	LSX(temp, ctx->key + 16 * 3, temp);
	LSX(temp, ctx->key + 16 * 4, temp);
	LSX(temp, ctx->key + 16 * 5, temp);
	LSX(temp, ctx->key + 16 * 6, temp);
	LSX(temp, ctx->key + 16 * 7, temp);
	LSX(temp, ctx->key + 16 * 8, temp);
	crypto_xor_cpy(out, ctx->key + 16 * 9, temp, 16);
}

static void kuznyechik_encrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	kuznyechik_encrypt_ctx(crypto_tfm_ctx(tfm), out, in);
}

static void kuznyechik_decrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	const struct crypto_kuznyechik_ctx *ctx = crypto_tfm_ctx(tfm);
	u8 temp[KUZNYECHIK_BLOCK_SIZE];

	S(temp, in);
	XLiSi(temp, temp, ctx->dekey + 16 * 9);
	XLiSi(temp, temp, ctx->dekey + 16 * 8);
	XLiSi(temp, temp, ctx->dekey + 16 * 7);
	XLiSi(temp, temp, ctx->dekey + 16 * 6);
	XLiSi(temp, temp, ctx->dekey + 16 * 5);
	XLiSi(temp, temp, ctx->dekey + 16 * 4);
	XLiSi(temp, temp, ctx->dekey + 16 * 3);
	XLiSi(temp, temp, ctx->dekey + 16 * 2);
	XLiSi(temp, temp, ctx->dekey + 16 * 1);
	Sinv(out, temp);
	crypto_xor(out, ctx->key + 16 * 0, 16);
}


static u64 kuz_bench_rate(u64 bytes, u64 ns)
{
	if (!ns)
		return 0;
	return div64_u64(bytes * NSEC_PER_SEC, ns);
}

static void kuz_bench_print(const char *name, u64 rate)
{
	u64 mib = 1024 * 1024;
	u64 frac = div64_u64((rate % mib) * 100, mib);
	u64 ns128 = rate ? div64_u64(128ULL * NSEC_PER_SEC * 100, rate) : 0;

	pr_info("kuznyechik_generic: bench %s %llu.%02llu MiB/s, %llu.%02llu ns/128B\n",
		name, div64_u64(rate, mib), frac,
		div64_u64(ns128, 100), ns128 % 100);
}

static u64 kuz_bench_once(const struct crypto_kuznyechik_ctx *ctx,
		const u8 *src, u8 *dst, u64 ns)
{
	u64 start = ktime_get_ns();
	u64 now;
	u64 bytes = 0;
	unsigned int i;
	unsigned int j;

	do {
		for (j = 0; j < KUZ_BENCH_CHUNKS; j++) {
			for (i = 0; i < KUZ_BENCH_BLOCKS; i++)
				kuznyechik_encrypt_ctx(ctx,
					dst + i * KUZNYECHIK_BLOCK_SIZE,
					src + i * KUZNYECHIK_BLOCK_SIZE);
			bytes += KUZ_BENCH_SIZE;
			barrier();
		}
		cond_resched();
		now = ktime_get_ns();
	} while (now - start < ns);

	return kuz_bench_rate(bytes, now - start);
}

static u64 kuz_bench_median3(u64 a, u64 b, u64 c)
{
	if (a > b)
		swap(a, b);
	if (b > c)
		swap(b, c);
	if (a > b)
		swap(a, b);
	return b;
}

static int __init kuz_bench_run(void)
{
	static const u8 key[KUZNYECHIK_KEY_SIZE] = {
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	};
	static const u8 plain[KUZNYECHIK_BLOCK_SIZE] = {
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
		0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
	};
	static const u8 cipher[KUZNYECHIK_BLOCK_SIZE] = {
		0x7f, 0x67, 0x9d, 0x90, 0xbe, 0xbc, 0x24, 0x30,
		0x5a, 0x46, 0x8d, 0x42, 0xb9, 0xd4, 0xed, 0xcd,
	};
	struct crypto_kuznyechik_ctx ctx;
	u8 src[KUZ_BENCH_SIZE] __aligned(16);
	u8 out[KUZ_BENCH_SIZE] __aligned(16);
	u64 rate[KUZ_BENCH_RUNS];
	u64 ns;
	unsigned int i;
	int err;

	if (!bench_ms)
		return 0;
	if (bench_ms < 100 || bench_ms > 30000)
		return -EINVAL;

	err = kuznyechik_expand_key(&ctx, key, sizeof(key));
	if (err)
		return err;
	for (i = 0; i < KUZ_BENCH_BLOCKS; i++)
		memcpy(src + i * KUZNYECHIK_BLOCK_SIZE, plain, sizeof(plain));
	kuznyechik_encrypt_ctx(&ctx, out, src);
	if (crypto_memneq(out, cipher, sizeof(cipher))) {
		pr_err("kuznyechik_generic: bench self-test failed\n");
		err = -EBADMSG;
		goto out;
	}

	ns = (u64)bench_ms * NSEC_PER_MSEC;
	migrate_disable();
	pr_info("kuznyechik_generic: bench duration=%u ms, runs=%u, cpu=%u, bulk=%u bytes\n",
		bench_ms, KUZ_BENCH_RUNS, raw_smp_processor_id(), KUZ_BENCH_SIZE);
	(void)kuz_bench_once(&ctx, src, out, 100 * NSEC_PER_MSEC);
	for (i = 0; i < KUZ_BENCH_RUNS; i++) {
		rate[i] = kuz_bench_once(&ctx, src, out, ns);
		pr_info("kuznyechik_generic: bench run %u\n", i + 1);
		kuz_bench_print("generic", rate[i]);
	}
	kuz_bench_print("median",
		kuz_bench_median3(rate[0], rate[1], rate[2]));
	migrate_enable();
	err = 0;

out:
	memzero_explicit(&ctx, sizeof(ctx));
	memzero_explicit(src, sizeof(src));
	memzero_explicit(out, sizeof(out));
	return err;
}

static struct crypto_alg kuznyechik_alg = {
	.cra_name		=	"kuznyechik",
	.cra_driver_name	=	"kuznyechik-generic",
	.cra_priority		=	100,
	.cra_flags		=	CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize		=	KUZNYECHIK_BLOCK_SIZE,
	.cra_ctxsize		=	sizeof(struct crypto_kuznyechik_ctx),
	.cra_module		=	THIS_MODULE,
	.cra_u			=	{
		.cipher = {
			.cia_min_keysize	= KUZNYECHIK_KEY_SIZE,
			.cia_max_keysize	= KUZNYECHIK_KEY_SIZE,
			.cia_setkey		= kuznyechik_set_key,
			.cia_encrypt		= kuznyechik_encrypt,
			.cia_decrypt		= kuznyechik_decrypt
		}
	}
};

static int __init kuznyechik_init(void)
{
	int err;

	pr_info("kuznyechik_generic: version %s, bulk=%u blocks, path=ttable\n",
		KUZ_GENERIC_VERSION, KUZ_BENCH_BLOCKS);
#if defined(CONFIG_ARM64)
	{
		u32 midr = read_cpuid_id();

		pr_info("kuznyechik_generic: cpu MIDR=0x%08x implementer=0x%02x part=0x%03x variant=%u revision=%u\n",
			midr, MIDR_IMPLEMENTOR(midr), MIDR_PARTNUM(midr),
			MIDR_VARIANT(midr), MIDR_REVISION(midr));
	}
#endif
	err = kuz_bench_run();
	if (err)
		return err;
	return crypto_register_alg(&kuznyechik_alg);
}

static void __exit kuznyechik_fini(void)
{
	crypto_unregister_alg(&kuznyechik_alg);
}

module_init(kuznyechik_init);
module_exit(kuznyechik_fini);

MODULE_DESCRIPTION("GOST R 34.12-2015 (Kuznyechik) algorithm");
MODULE_VERSION(KUZ_GENERIC_VERSION);
MODULE_LICENSE("GPL v2");
MODULE_ALIAS_CRYPTO("kuznyechik");
MODULE_ALIAS_CRYPTO("kuznyechik-generic");
