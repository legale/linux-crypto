/* SPDX-License-Identifier: GPL-2.0-or-later OR BSD-2-Clause */
#include <crypto/internal/hash.h>
#include <linux/module.h>

#include <libpogost/streebog.h>

static int streebog_shash_init(struct shash_desc *desc)
{
	struct streebog_ctx *ctx = shash_desc_ctx(desc);

	streebog_init(ctx, crypto_shash_digestsize(desc->tfm) * 8);
	return 0;
}

static int streebog_shash_update(struct shash_desc *desc, const u8 *data,
		unsigned int len)
{
	streebog_update(shash_desc_ctx(desc), data, len);
	return 0;
}

static int streebog_shash_final(struct shash_desc *desc, u8 *digest)
{
	streebog_final(shash_desc_ctx(desc), digest);
	return 0;
}

static struct shash_alg algs[2] = { {
	.digestsize = STREEBOG256_DIGEST_SIZE,
	.init = streebog_shash_init,
	.update = streebog_shash_update,
	.final = streebog_shash_final,
	.descsize = sizeof(struct streebog_ctx),
	.base = {
		.cra_name = "streebog256",
		.cra_driver_name = "streebog256-generic",
		.cra_blocksize = STREEBOG_BLOCK_SIZE,
		.cra_module = THIS_MODULE,
	},
}, {
	.digestsize = STREEBOG512_DIGEST_SIZE,
	.init = streebog_shash_init,
	.update = streebog_shash_update,
	.final = streebog_shash_final,
	.descsize = sizeof(struct streebog_ctx),
	.base = {
		.cra_name = "streebog512",
		.cra_driver_name = "streebog512-generic",
		.cra_blocksize = STREEBOG_BLOCK_SIZE,
		.cra_module = THIS_MODULE,
	},
} };

static int __init streebog_mod_init(void)
{
	return crypto_register_shashes(algs, ARRAY_SIZE(algs));
}

static void __exit streebog_mod_fini(void)
{
	crypto_unregister_shashes(algs, ARRAY_SIZE(algs));
}

module_init(streebog_mod_init);
module_exit(streebog_mod_fini);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vitaly Chikunov <vt@altlinux.org>");
MODULE_DESCRIPTION("Streebog Hash Function");
MODULE_ALIAS_CRYPTO("streebog256");
MODULE_ALIAS_CRYPTO("streebog256-generic");
MODULE_ALIAS_CRYPTO("streebog512");
MODULE_ALIAS_CRYPTO("streebog512-generic");
