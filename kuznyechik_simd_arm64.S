/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Eight/four-block ARM64 NEON core for GOST R 34.12-2015 Kuznyechik.
 *
 * The LSX tables contain 128-bit values and cannot be addressed by NEON
 * tbl/tbx.  Keep eight blocks in NEON, transpose only the lookup bytes,
 * extract eight indices at once, and accumulate 128-bit table entries in
 * NEON.  This mirrors the multi-block/transposed structure used by the
 * in-kernel ARM64 SM4 NEON core without doing one SIMD->GPR transfer per
 * byte and block.
 */

#include <linux/linkage.h>

.text

/*
 * Input: v0..v7 contain eight 16-byte blocks.
 * Output: v8..v15 contain two byte columns each:
 *
 *   v8.d[0]  = byte 0 from blocks 0..7
 *   v8.d[1]  = byte 8 from blocks 0..7
 *   v9.d[0]  = byte 4,  v9.d[1]  = byte 12
 *   v10.d[0] = byte 2,  v10.d[1] = byte 10
 *   v11.d[0] = byte 6,  v11.d[1] = byte 14
 *   v12.d[0] = byte 1,  v12.d[1] = byte 9
 *   v13.d[0] = byte 5,  v13.d[1] = byte 13
 *   v14.d[0] = byte 3,  v14.d[1] = byte 11
 *   v15.d[0] = byte 7,  v15.d[1] = byte 15
 */
.macro KUZ_TRANSPOSE8
	trn1	v8.16b, v0.16b, v1.16b
	trn2	v9.16b, v0.16b, v1.16b
	trn1	v10.16b, v2.16b, v3.16b
	trn2	v11.16b, v2.16b, v3.16b
	trn1	v12.16b, v4.16b, v5.16b
	trn2	v13.16b, v4.16b, v5.16b
	trn1	v14.16b, v6.16b, v7.16b
	trn2	v15.16b, v6.16b, v7.16b

	trn1	v16.8h, v8.8h, v10.8h
	trn2	v17.8h, v8.8h, v10.8h
	trn1	v18.8h, v9.8h, v11.8h
	trn2	v19.8h, v9.8h, v11.8h
	trn1	v20.8h, v12.8h, v14.8h
	trn2	v21.8h, v12.8h, v14.8h
	trn1	v22.8h, v13.8h, v15.8h
	trn2	v23.8h, v13.8h, v15.8h

	trn1	v8.4s, v16.4s, v20.4s
	trn2	v9.4s, v16.4s, v20.4s
	trn1	v10.4s, v17.4s, v21.4s
	trn2	v11.4s, v17.4s, v21.4s
	trn1	v12.4s, v18.4s, v22.4s
	trn2	v13.4s, v18.4s, v22.4s
	trn1	v14.4s, v19.4s, v23.4s
	trn2	v15.4s, v19.4s, v23.4s
.endm

/* x5: table for one byte position, x9: eight packed byte indices. */
.macro KUZ_LOOKUP8_ONE dst, shift
	ubfx	x10, x9, #\shift, #8
	add	x10, x5, x10, lsl #4
	ldr	q16, [x10]
	eor	\dst\().16b, \dst\().16b, v16.16b
.endm

.macro KUZ_LOOKUP8
	KUZ_LOOKUP8_ONE v0, 0
	KUZ_LOOKUP8_ONE v1, 8
	KUZ_LOOKUP8_ONE v2, 16
	KUZ_LOOKUP8_ONE v3, 24
	KUZ_LOOKUP8_ONE v4, 32
	KUZ_LOOKUP8_ONE v5, 40
	KUZ_LOOKUP8_ONE v6, 48
	KUZ_LOOKUP8_ONE v7, 56
.endm

.macro KUZ_POS8 table, reg, lane, pos
	umov	x9, \reg\().d[\lane]
	add	x5, \table, #\pos, lsl #12
	KUZ_LOOKUP8
.endm

/* v0..v7: input blocks, replaced by transformed blocks. */
.macro KUZ_TRANSFORM8 table
	KUZ_TRANSPOSE8

	movi	v0.16b, #0
	movi	v1.16b, #0
	movi	v2.16b, #0
	movi	v3.16b, #0
	movi	v4.16b, #0
	movi	v5.16b, #0
	movi	v6.16b, #0
	movi	v7.16b, #0

	KUZ_POS8 \table, v8, 0, 0
	KUZ_POS8 \table, v8, 1, 8
	KUZ_POS8 \table, v9, 0, 4
	KUZ_POS8 \table, v9, 1, 12
	KUZ_POS8 \table, v10, 0, 2
	KUZ_POS8 \table, v10, 1, 10
	KUZ_POS8 \table, v11, 0, 6
	KUZ_POS8 \table, v11, 1, 14
	KUZ_POS8 \table, v12, 0, 1
	KUZ_POS8 \table, v12, 1, 9
	KUZ_POS8 \table, v13, 0, 5
	KUZ_POS8 \table, v13, 1, 13
	KUZ_POS8 \table, v14, 0, 3
	KUZ_POS8 \table, v14, 1, 11
	KUZ_POS8 \table, v15, 0, 7
	KUZ_POS8 \table, v15, 1, 15
.endm

/* Four-block fallback matching the 8/4/tail split used by SM4. */
.macro KUZ_TRANSPOSE4
	trn1	v8.16b, v0.16b, v1.16b
	trn2	v9.16b, v0.16b, v1.16b
	trn1	v10.16b, v2.16b, v3.16b
	trn2	v11.16b, v2.16b, v3.16b

	trn1	v12.8h, v8.8h, v10.8h
	trn2	v13.8h, v8.8h, v10.8h
	trn1	v14.8h, v9.8h, v11.8h
	trn2	v15.8h, v9.8h, v11.8h
.endm

/* x5: table for one byte position, w9: four packed byte indices. */
.macro KUZ_LOOKUP4_ONE dst, shift
	ubfx	w10, w9, #\shift, #8
	add	x10, x5, x10, lsl #4
	ldr	q16, [x10]
	eor	\dst\().16b, \dst\().16b, v16.16b
.endm

.macro KUZ_LOOKUP4
	KUZ_LOOKUP4_ONE v0, 0
	KUZ_LOOKUP4_ONE v1, 8
	KUZ_LOOKUP4_ONE v2, 16
	KUZ_LOOKUP4_ONE v3, 24
.endm

.macro KUZ_POS4 table, reg, lane, pos
	umov	w9, \reg\().s[\lane]
	add	x5, \table, #\pos, lsl #12
	KUZ_LOOKUP4
.endm

.macro KUZ_TRANSFORM4 table
	KUZ_TRANSPOSE4

	movi	v0.16b, #0
	movi	v1.16b, #0
	movi	v2.16b, #0
	movi	v3.16b, #0

	KUZ_POS4 \table, v12, 0, 0
	KUZ_POS4 \table, v12, 1, 4
	KUZ_POS4 \table, v12, 2, 8
	KUZ_POS4 \table, v12, 3, 12
	KUZ_POS4 \table, v13, 0, 2
	KUZ_POS4 \table, v13, 1, 6
	KUZ_POS4 \table, v13, 2, 10
	KUZ_POS4 \table, v13, 3, 14
	KUZ_POS4 \table, v14, 0, 1
	KUZ_POS4 \table, v14, 1, 5
	KUZ_POS4 \table, v14, 2, 9
	KUZ_POS4 \table, v14, 3, 13
	KUZ_POS4 \table, v15, 0, 3
	KUZ_POS4 \table, v15, 1, 7
	KUZ_POS4 \table, v15, 2, 11
	KUZ_POS4 \table, v15, 3, 15
.endm

/*
 * void kuz_encrypt_4way(const u8 *key, u8 *dst, const u8 *src,
 *                       const u8 *table);
 */
SYM_FUNC_START(kuz_encrypt_4way)
	ldp	q0, q1, [x2]
	ldp	q2, q3, [x2, #32]
	mov	x6, x0
	mov	w7, #9

.Lkuz_enc_four_round:
	ldr	q16, [x6], #16
	eor	v0.16b, v0.16b, v16.16b
	eor	v1.16b, v1.16b, v16.16b
	eor	v2.16b, v2.16b, v16.16b
	eor	v3.16b, v3.16b, v16.16b
	KUZ_TRANSFORM4 x3
	subs	w7, w7, #1
	b.ne	.Lkuz_enc_four_round

	ldr	q16, [x6]
	eor	v0.16b, v0.16b, v16.16b
	eor	v1.16b, v1.16b, v16.16b
	eor	v2.16b, v2.16b, v16.16b
	eor	v3.16b, v3.16b, v16.16b
	stp	q0, q1, [x1]
	stp	q2, q3, [x1, #32]
	ret
SYM_FUNC_END(kuz_encrypt_4way)

/*
 * void kuz_decrypt_4way(const u8 *dekey, u8 *dst, const u8 *src,
 *                       const u8 *inv_table, const u8 *inv_ls_table);
 */
SYM_FUNC_START(kuz_decrypt_4way)
	ldp	q0, q1, [x2]
	ldp	q2, q3, [x2, #32]

	KUZ_TRANSFORM4 x3
	ldr	q16, [x0, #144]
	eor	v0.16b, v0.16b, v16.16b
	eor	v1.16b, v1.16b, v16.16b
	eor	v2.16b, v2.16b, v16.16b
	eor	v3.16b, v3.16b, v16.16b

	mov	x3, x4
	add	x6, x0, #128
	mov	w7, #8

.Lkuz_dec_four_round:
	KUZ_TRANSFORM4 x3
	ldr	q16, [x6], #-16
	eor	v0.16b, v0.16b, v16.16b
	eor	v1.16b, v1.16b, v16.16b
	eor	v2.16b, v2.16b, v16.16b
	eor	v3.16b, v3.16b, v16.16b
	subs	w7, w7, #1
	b.ne	.Lkuz_dec_four_round

	stp	q0, q1, [x1]
	stp	q2, q3, [x1, #32]
	ret
SYM_FUNC_END(kuz_decrypt_4way)

/*
 * void kuz_encrypt_8way(const u8 *key, u8 *dst, const u8 *src,
 *                       const u8 *table);
 */
SYM_FUNC_START(kuz_encrypt_8way)
	ldp	q0, q1, [x2]
	ldp	q2, q3, [x2, #32]
	ldp	q4, q5, [x2, #64]
	ldp	q6, q7, [x2, #96]
	mov	x6, x0
	mov	w7, #9

.Lkuz_enc_eight_round:
	ldr	q16, [x6], #16
	eor	v0.16b, v0.16b, v16.16b
	eor	v1.16b, v1.16b, v16.16b
	eor	v2.16b, v2.16b, v16.16b
	eor	v3.16b, v3.16b, v16.16b
	eor	v4.16b, v4.16b, v16.16b
	eor	v5.16b, v5.16b, v16.16b
	eor	v6.16b, v6.16b, v16.16b
	eor	v7.16b, v7.16b, v16.16b
	KUZ_TRANSFORM8 x3
	subs	w7, w7, #1
	b.ne	.Lkuz_enc_eight_round

	ldr	q16, [x6]
	eor	v0.16b, v0.16b, v16.16b
	eor	v1.16b, v1.16b, v16.16b
	eor	v2.16b, v2.16b, v16.16b
	eor	v3.16b, v3.16b, v16.16b
	eor	v4.16b, v4.16b, v16.16b
	eor	v5.16b, v5.16b, v16.16b
	eor	v6.16b, v6.16b, v16.16b
	eor	v7.16b, v7.16b, v16.16b
	stp	q0, q1, [x1]
	stp	q2, q3, [x1, #32]
	stp	q4, q5, [x1, #64]
	stp	q6, q7, [x1, #96]
	ret
SYM_FUNC_END(kuz_encrypt_8way)

/*
 * void kuz_decrypt_8way(const u8 *dekey, u8 *dst, const u8 *src,
 *                       const u8 *inv_table, const u8 *inv_ls_table);
 */
SYM_FUNC_START(kuz_decrypt_8way)
	ldp	q0, q1, [x2]
	ldp	q2, q3, [x2, #32]
	ldp	q4, q5, [x2, #64]
	ldp	q6, q7, [x2, #96]

	KUZ_TRANSFORM8 x3
	ldr	q16, [x0, #144]
	eor	v0.16b, v0.16b, v16.16b
	eor	v1.16b, v1.16b, v16.16b
	eor	v2.16b, v2.16b, v16.16b
	eor	v3.16b, v3.16b, v16.16b
	eor	v4.16b, v4.16b, v16.16b
	eor	v5.16b, v5.16b, v16.16b
	eor	v6.16b, v6.16b, v16.16b
	eor	v7.16b, v7.16b, v16.16b

	mov	x3, x4
	add	x6, x0, #128
	mov	w7, #8

.Lkuz_dec_eight_round:
	KUZ_TRANSFORM8 x3
	ldr	q16, [x6], #-16
	eor	v0.16b, v0.16b, v16.16b
	eor	v1.16b, v1.16b, v16.16b
	eor	v2.16b, v2.16b, v16.16b
	eor	v3.16b, v3.16b, v16.16b
	eor	v4.16b, v4.16b, v16.16b
	eor	v5.16b, v5.16b, v16.16b
	eor	v6.16b, v6.16b, v16.16b
	eor	v7.16b, v7.16b, v16.16b
	subs	w7, w7, #1
	b.ne	.Lkuz_dec_eight_round

	stp	q0, q1, [x1]
	stp	q2, q3, [x1, #32]
	stp	q4, q5, [x1, #64]
	stp	q6, q7, [x1, #96]
	ret
SYM_FUNC_END(kuz_decrypt_8way)
