/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/crypto.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/sched.h>

#include <crypto/algapi.h>
#include <crypto/kuznyechik.h>
#include <libpogost/kuznyechik.h>
#include <kuznyechik_internal.h>

#if defined(CONFIG_ARM64)
#include <asm/cputype.h>
#endif

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

static int kuznyechik_set_key(struct crypto_tfm *tfm, const u8 *key,
		unsigned int key_len)
{
	if (key_len != KUZNYECHIK_KEY_SIZE)
		return -EINVAL;
	return kuznyechik_generic_setkey(crypto_tfm_ctx(tfm), key);
}

static void kuz_encrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	kuznyechik_generic_encrypt(crypto_tfm_ctx(tfm), out, in);
}

static void kuz_decrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	kuznyechik_generic_decrypt(crypto_tfm_ctx(tfm), out, in);
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

static u64 kuz_bench_once(const struct kuznyechik_ctx *ctx,
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
				kuznyechik_generic_encrypt(ctx,
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
	struct kuznyechik_ctx ctx;
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

	err = kuznyechik_generic_setkey(&ctx, key);
	if (err)
		return err;
	for (i = 0; i < KUZ_BENCH_BLOCKS; i++)
		memcpy(src + i * KUZNYECHIK_BLOCK_SIZE, plain, sizeof(plain));
	kuznyechik_generic_encrypt(&ctx, out, src);
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
	kuz_bench_print("median", kuz_bench_median3(rate[0], rate[1], rate[2]));
	migrate_enable();
	err = 0;

out:
	memzero_explicit(&ctx, sizeof(ctx));
	memzero_explicit(src, sizeof(src));
	memzero_explicit(out, sizeof(out));
	return err;
}

static struct crypto_alg kuznyechik_alg = {
	.cra_name = "kuznyechik",
	.cra_driver_name = "kuznyechik-generic",
	.cra_priority = 100,
	.cra_flags = CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize = KUZNYECHIK_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct kuznyechik_ctx),
	.cra_module = THIS_MODULE,
	.cra_u = {
		.cipher = {
			.cia_min_keysize = KUZNYECHIK_KEY_SIZE,
			.cia_max_keysize = KUZNYECHIK_KEY_SIZE,
			.cia_setkey = kuznyechik_set_key,
			.cia_encrypt = kuz_encrypt,
			.cia_decrypt = kuz_decrypt,
		},
	},
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
