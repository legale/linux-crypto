/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * ARM64 NEON core for GOST R 34.12-2015 Kuznyechik.
 *
 * Sixteen-block forward encryption uses a tableless LS hot path: pi is looked
 * up with NEON tbl/tbx and L is evaluated in registers as R^16.  The 8/4/1
 * block forward fallbacks and inverse transforms retain the compact LSX table
 * implementation.
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

/* x3: LSX table, x8/x9: packed state bytes, v1: accumulator. */
.macro KUZ_LOOKUP1_ONE packed, shift, pos
	ubfx	x10, \packed, #\shift, #8
	add	x5, x3, #\pos, lsl #12
	add	x10, x5, x10, lsl #4
	ldr	q16, [x10]
	eor	v1.16b, v1.16b, v16.16b
.endm

.macro KUZ_TRANSFORM1
	umov	x8, v0.d[0]
	umov	x9, v0.d[1]
	movi	v1.16b, #0
	KUZ_LOOKUP1_ONE x8, 0, 0
	KUZ_LOOKUP1_ONE x8, 8, 1
	KUZ_LOOKUP1_ONE x8, 16, 2
	KUZ_LOOKUP1_ONE x8, 24, 3
	KUZ_LOOKUP1_ONE x8, 32, 4
	KUZ_LOOKUP1_ONE x8, 40, 5
	KUZ_LOOKUP1_ONE x8, 48, 6
	KUZ_LOOKUP1_ONE x8, 56, 7
	KUZ_LOOKUP1_ONE x9, 0, 8
	KUZ_LOOKUP1_ONE x9, 8, 9
	KUZ_LOOKUP1_ONE x9, 16, 10
	KUZ_LOOKUP1_ONE x9, 24, 11
	KUZ_LOOKUP1_ONE x9, 32, 12
	KUZ_LOOKUP1_ONE x9, 40, 13
	KUZ_LOOKUP1_ONE x9, 48, 14
	KUZ_LOOKUP1_ONE x9, 56, 15
	mov	v0.16b, v1.16b
.endm

/*
 * void kuz_encrypt_1way(const u8 *key, u8 *dst, const u8 *src,
 *                       const u8 *table);
 */
SYM_FUNC_START(kuz_encrypt_1way)
	ldr	q0, [x2]
	mov	x6, x0
	mov	w7, #9

.Lkuz_enc_one_round:
	ldr	q16, [x6], #16
	eor	v0.16b, v0.16b, v16.16b
	KUZ_TRANSFORM1
	subs	w7, w7, #1
	b.ne	.Lkuz_enc_one_round

	ldr	q16, [x6]
	eor	v0.16b, v0.16b, v16.16b
	str	q0, [x1]
	ret
SYM_FUNC_END(kuz_encrypt_1way)

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
 * Tableless forward LS for eight blocks.
 *
 * S is evaluated with the 256-byte pi table resident in NEON registers,
 * exactly like the ARM64 SM4 NEON S-box.  L is evaluated as R^16 on
 * byte-sliced state.  The only table accesses in the hot path are fixed
 * sequential loads; no address depends on cipher state.
 */
.macro KUZ_LOAD_PI
	adrp	x5, .Lkuz_pi
	add	x5, x5, :lo12:.Lkuz_pi
	ld1	{v16.16b-v19.16b}, [x5], #64
	ld1	{v20.16b-v23.16b}, [x5], #64
	ld1	{v24.16b-v27.16b}, [x5], #64
	ld1	{v28.16b-v31.16b}, [x5]
.endm

.macro KUZ_SBOX_ONE reg
	mov	v8.16b, \reg\().16b
	tbl	\reg\().16b, {v16.16b-v19.16b}, v8.16b
	sub	v8.16b, v8.16b, v15.16b
	tbx	\reg\().16b, {v20.16b-v23.16b}, v8.16b
	sub	v8.16b, v8.16b, v15.16b
	tbx	\reg\().16b, {v24.16b-v27.16b}, v8.16b
	sub	v8.16b, v8.16b, v15.16b
	tbx	\reg\().16b, {v28.16b-v31.16b}, v8.16b
.endm

.macro KUZ_SBOX8
	KUZ_LOAD_PI
	movi	v15.16b, #64
	KUZ_SBOX_ONE v0
	KUZ_SBOX_ONE v1
	KUZ_SBOX_ONE v2
	KUZ_SBOX_ONE v3
	KUZ_SBOX_ONE v4
	KUZ_SBOX_ONE v5
	KUZ_SBOX_ONE v6
	KUZ_SBOX_ONE v7
.endm

/* v0..v7 blocks -> v0..v15 byte positions, eight bytes per position. */
.macro KUZ_PACK8
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

	trn1	v24.4s, v16.4s, v20.4s
	trn2	v25.4s, v16.4s, v20.4s
	trn1	v26.4s, v17.4s, v21.4s
	trn2	v27.4s, v17.4s, v21.4s
	trn1	v28.4s, v18.4s, v22.4s
	trn2	v29.4s, v18.4s, v22.4s
	trn1	v30.4s, v19.4s, v23.4s
	trn2	v31.4s, v19.4s, v23.4s

	mov	v0.d[0], v24.d[0]
	mov	v1.d[0], v28.d[0]
	mov	v2.d[0], v26.d[0]
	mov	v3.d[0], v30.d[0]
	mov	v4.d[0], v25.d[0]
	mov	v5.d[0], v29.d[0]
	mov	v6.d[0], v27.d[0]
	mov	v7.d[0], v31.d[0]
	mov	v8.d[0], v24.d[1]
	mov	v9.d[0], v28.d[1]
	mov	v10.d[0], v26.d[1]
	mov	v11.d[0], v30.d[1]
	mov	v12.d[0], v25.d[1]
	mov	v13.d[0], v29.d[1]
	mov	v14.d[0], v27.d[1]
	mov	v15.d[0], v31.d[1]
.endm

/* v0..v15 byte positions -> v0..v7 blocks. */
.macro KUZ_UNPACK8
	mov	v24.d[0], v0.d[0]
	mov	v24.d[1], v8.d[0]
	mov	v25.d[0], v4.d[0]
	mov	v25.d[1], v12.d[0]
	mov	v26.d[0], v2.d[0]
	mov	v26.d[1], v10.d[0]
	mov	v27.d[0], v6.d[0]
	mov	v27.d[1], v14.d[0]
	mov	v28.d[0], v1.d[0]
	mov	v28.d[1], v9.d[0]
	mov	v29.d[0], v5.d[0]
	mov	v29.d[1], v13.d[0]
	mov	v30.d[0], v3.d[0]
	mov	v30.d[1], v11.d[0]
	mov	v31.d[0], v7.d[0]
	mov	v31.d[1], v15.d[0]

	trn1	v16.4s, v24.4s, v25.4s
	trn2	v20.4s, v24.4s, v25.4s
	trn1	v17.4s, v26.4s, v27.4s
	trn2	v21.4s, v26.4s, v27.4s
	trn1	v18.4s, v28.4s, v29.4s
	trn2	v22.4s, v28.4s, v29.4s
	trn1	v19.4s, v30.4s, v31.4s
	trn2	v23.4s, v30.4s, v31.4s

	trn1	v8.8h, v16.8h, v17.8h
	trn2	v10.8h, v16.8h, v17.8h
	trn1	v9.8h, v18.8h, v19.8h
	trn2	v11.8h, v18.8h, v19.8h
	trn1	v12.8h, v20.8h, v21.8h
	trn2	v14.8h, v20.8h, v21.8h
	trn1	v13.8h, v22.8h, v23.8h
	trn2	v15.8h, v22.8h, v23.8h

	trn1	v0.16b, v8.16b, v9.16b
	trn2	v1.16b, v8.16b, v9.16b
	trn1	v2.16b, v10.16b, v11.16b
	trn2	v3.16b, v10.16b, v11.16b
	trn1	v4.16b, v12.16b, v13.16b
	trn2	v5.16b, v12.16b, v13.16b
	trn1	v6.16b, v14.16b, v15.16b
	trn2	v7.16b, v14.16b, v15.16b
.endm

/*
 * GF(2^8), p(x) = x^8 + x^7 + x^6 + x + 1 (0x1c3).
 * v24..v28: nibble multiplication tables
 * v29: 0x0f, v30: 0xc3, v16..v19: temporaries.
 */
.macro KUZ_MUL_NIB dst, src, lo, hi, tmp
	ushr	\tmp\().8b, \src\().8b, #4
	and	\dst\().8b, \src\().8b, v29.8b
	tbl	\dst\().8b, {\lo\().16b}, \dst\().8b
	tbl	\tmp\().8b, {\hi\().16b}, \tmp\().8b
	eor	\dst\().8b, \dst\().8b, \tmp\().8b
.endm

.macro KUZ_XTIME dst, src, tmp
	sshr	\tmp\().8b, \src\().8b, #7
	shl	\dst\().8b, \src\().8b, #1
	and	\tmp\().8b, \tmp\().8b, v30.8b
	eor	\dst\().8b, \dst\().8b, \tmp\().8b
.endm

/*
 * One R step.  Keep the independent GF branches separate so their tbl
 * latency can overlap with XOR/xtime work.  Commit a15 only at the end.
 * v16..v23/v31 are scratch; v24..v30 remain the fixed GF tables/constants.
 */
.macro KUZ_R8 a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15
	/* C, E, F, B, A, D and G ^ C ^ E ^ F. */
	eor	v16.8b, \a2\().8b, \a12\().8b
	eor	v17.8b, \a4\().8b, \a10\().8b
	eor	v18.8b, \a5\().8b, \a9\().8b
	eor	v19.8b, \a1\().8b, \a13\().8b
	eor	v20.8b, \a0\().8b, \a14\().8b
	eor	v21.8b, \a3\().8b, \a11\().8b
	eor	v22.8b, \a15\().8b, \a6\().8b
	eor	v23.8b, v17.8b, v18.8b
	eor	v22.8b, v22.8b, \a8\().8b
	eor	v22.8b, v22.8b, v16.8b
	eor	v22.8b, v22.8b, v23.8b

	/* Start 195 * (E ^ F), then fill tbl latency with 2*F and 2*B. */
	ushr	v31.8b, v23.8b, #4
	and	v23.8b, v23.8b, v29.8b
	tbl	v23.8b, {v25.16b}, v23.8b

	sshr	v17.8b, v18.8b, #7
	shl	v18.8b, v18.8b, #1
	and	v17.8b, v17.8b, v30.8b
	eor	v18.8b, v18.8b, v17.8b

	sshr	v17.8b, v19.8b, #7
	shl	v19.8b, v19.8b, #1
	and	v17.8b, v17.8b, v30.8b
	eor	v19.8b, v19.8b, v17.8b

	tbl	v31.8b, {v28.16b}, v31.8b

	/* Prepare the 16 * branch while the second 195 lookup completes. */
	eor	v19.8b, v19.8b, v16.8b
	eor	v19.8b, v19.8b, v21.8b
	eor	v19.8b, v19.8b, \a7\().8b
	eor	v23.8b, v23.8b, v31.8b

	ushr	v31.8b, v19.8b, #4
	and	v19.8b, v19.8b, v29.8b
	tbl	v19.8b, {v24.16b}, v19.8b

	/* Prepare 148 * (A ^ C ^ 2*H) while the 16 lookup is in flight. */
	sshr	v17.8b, \a7\().8b, #7
	shl	v21.8b, \a7\().8b, #1
	and	v17.8b, v17.8b, v30.8b
	eor	v21.8b, v21.8b, v17.8b
	eor	v20.8b, v20.8b, v16.8b
	eor	v20.8b, v20.8b, v21.8b
	eor	v18.8b, v18.8b, v23.8b

	tbl	v31.8b, {v25.16b}, v31.8b
	eor	v19.8b, v19.8b, v31.8b

	/* 148 * branch. */
	ushr	v31.8b, v20.8b, #4
	and	v20.8b, v20.8b, v29.8b
	tbl	v20.8b, {v26.16b}, v20.8b
	eor	v22.8b, v22.8b, v18.8b
	tbl	v31.8b, {v27.16b}, v31.8b
	eor	v20.8b, v20.8b, v31.8b

	/* Balanced final reduction, then overwrite the dropped byte position. */
	eor	v19.8b, v19.8b, v20.8b
	eor	\a15\().8b, v22.8b, v19.8b
.endm


.macro KUZ_L8
	adrp	x5, .Lkuz_lmul
	add	x5, x5, :lo12:.Lkuz_lmul
	ld1	{v24.16b-v27.16b}, [x5], #64
	ldr	q28, [x5]
	movi	v29.16b, #0x0f
	movi	v30.16b, #0xc3

	KUZ_R8 v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15
	KUZ_R8 v15, v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14
	KUZ_R8 v14, v15, v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13
	KUZ_R8 v13, v14, v15, v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12
	KUZ_R8 v12, v13, v14, v15, v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11
	KUZ_R8 v11, v12, v13, v14, v15, v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10
	KUZ_R8 v10, v11, v12, v13, v14, v15, v0, v1, v2, v3, v4, v5, v6, v7, v8, v9
	KUZ_R8 v9, v10, v11, v12, v13, v14, v15, v0, v1, v2, v3, v4, v5, v6, v7, v8
	KUZ_R8 v8, v9, v10, v11, v12, v13, v14, v15, v0, v1, v2, v3, v4, v5, v6, v7
	KUZ_R8 v7, v8, v9, v10, v11, v12, v13, v14, v15, v0, v1, v2, v3, v4, v5, v6
	KUZ_R8 v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v0, v1, v2, v3, v4, v5
	KUZ_R8 v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v0, v1, v2, v3, v4
	KUZ_R8 v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v0, v1, v2, v3
	KUZ_R8 v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v0, v1, v2
	KUZ_R8 v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v0, v1
	KUZ_R8 v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v0
.endm

.macro KUZ_TRANSFORM8_TABLELESS
	KUZ_SBOX8
	KUZ_PACK8
	KUZ_L8
	KUZ_UNPACK8
.endm

/*
 * void kuz_encrypt_8way(const u8 *key, u8 *dst, const u8 *src);
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
	KUZ_TRANSFORM8_TABLELESS
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

/* Benchmark-only primitives for isolating the tableless S and L costs. */
SYM_FUNC_START(kuz_sbox_8way)
	ldp	q0, q1, [x1]
	ldp	q2, q3, [x1, #32]
	ldp	q4, q5, [x1, #64]
	ldp	q6, q7, [x1, #96]
	KUZ_SBOX8
	stp	q0, q1, [x0]
	stp	q2, q3, [x0, #32]
	stp	q4, q5, [x0, #64]
	stp	q6, q7, [x0, #96]
	ret
SYM_FUNC_END(kuz_sbox_8way)

SYM_FUNC_START(kuz_l_8way)
	ldp	q0, q1, [x1]
	ldp	q2, q3, [x1, #32]
	ldp	q4, q5, [x1, #64]
	ldp	q6, q7, [x1, #96]
	KUZ_PACK8
	KUZ_L8
	KUZ_UNPACK8
	stp	q0, q1, [x0]
	stp	q2, q3, [x0, #32]
	stp	q4, q5, [x0, #64]
	stp	q6, q7, [x0, #96]
	ret
SYM_FUNC_END(kuz_l_8way)




/* x9: big-endian low counter, x8: big-endian high counter. */
.macro KUZ_CTR_BLOCK reg, inc
	adds	x10, x9, #\inc
	adc	x11, x8, xzr
	rev	x10, x10
	rev	x11, x11
	fmov	d\reg, x11
	ins	v\reg\().d[1], x10
.endm

/*
 * void kuz_ctr_8way(const u8 *key, u8 *dst, const u8 *src, u8 *ctr);
 */
SYM_FUNC_START(kuz_ctr_8way)
	ldr	x8, [x3]
	ldr	x9, [x3, #8]
	rev	x8, x8
	rev	x9, x9

	KUZ_CTR_BLOCK 0, 0
	KUZ_CTR_BLOCK 1, 1
	KUZ_CTR_BLOCK 2, 2
	KUZ_CTR_BLOCK 3, 3
	KUZ_CTR_BLOCK 4, 4
	KUZ_CTR_BLOCK 5, 5
	KUZ_CTR_BLOCK 6, 6
	KUZ_CTR_BLOCK 7, 7

	adds	x10, x9, #8
	adc	x11, x8, xzr
	rev	x10, x10
	rev	x11, x11
	str	x11, [x3]
	str	x10, [x3, #8]

	mov	x6, x0
	mov	w7, #9
.Lkuz_ctr_eight_round:
	ldr	q16, [x6], #16
	eor	v0.16b, v0.16b, v16.16b
	eor	v1.16b, v1.16b, v16.16b
	eor	v2.16b, v2.16b, v16.16b
	eor	v3.16b, v3.16b, v16.16b
	eor	v4.16b, v4.16b, v16.16b
	eor	v5.16b, v5.16b, v16.16b
	eor	v6.16b, v6.16b, v16.16b
	eor	v7.16b, v7.16b, v16.16b
	KUZ_TRANSFORM8_TABLELESS
	subs	w7, w7, #1
	b.ne	.Lkuz_ctr_eight_round

	ldr	q16, [x6]
	eor	v0.16b, v0.16b, v16.16b
	eor	v1.16b, v1.16b, v16.16b
	eor	v2.16b, v2.16b, v16.16b
	eor	v3.16b, v3.16b, v16.16b
	eor	v4.16b, v4.16b, v16.16b
	eor	v5.16b, v5.16b, v16.16b
	eor	v6.16b, v6.16b, v16.16b
	eor	v7.16b, v7.16b, v16.16b

	ldp	q8, q9, [x2]
	ldp	q10, q11, [x2, #32]
	ldp	q12, q13, [x2, #64]
	ldp	q14, q15, [x2, #96]
	eor	v0.16b, v0.16b, v8.16b
	eor	v1.16b, v1.16b, v9.16b
	eor	v2.16b, v2.16b, v10.16b
	eor	v3.16b, v3.16b, v11.16b
	eor	v4.16b, v4.16b, v12.16b
	eor	v5.16b, v5.16b, v13.16b
	eor	v6.16b, v6.16b, v14.16b
	eor	v7.16b, v7.16b, v15.16b
	stp	q0, q1, [x1]
	stp	q2, q3, [x1, #32]
	stp	q4, q5, [x1, #64]
	stp	q6, q7, [x1, #96]
	ret
SYM_FUNC_END(kuz_ctr_8way)

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


/*
 * Tableless forward LS for sixteen blocks.
 * S uses the resident pi table; L evaluates R^16 at full .16b width.
 */

.macro KUZ_SBOX16_GROUP r0, r1, r2, r3, r4, r5, r6, r7
	adrp	x5, .Lkuz_pi
	add	x5, x5, :lo12:.Lkuz_pi
	movi	v28.16b, #64

	ld1	{v24.16b-v27.16b}, [x5], #64
	tbl	v16.16b, {v24.16b-v27.16b}, \r0\().16b
	tbl	v17.16b, {v24.16b-v27.16b}, \r1\().16b
	tbl	v18.16b, {v24.16b-v27.16b}, \r2\().16b
	tbl	v19.16b, {v24.16b-v27.16b}, \r3\().16b
	tbl	v20.16b, {v24.16b-v27.16b}, \r4\().16b
	tbl	v21.16b, {v24.16b-v27.16b}, \r5\().16b
	tbl	v22.16b, {v24.16b-v27.16b}, \r6\().16b
	tbl	v23.16b, {v24.16b-v27.16b}, \r7\().16b

	sub	\r0\().16b, \r0\().16b, v28.16b
	sub	\r1\().16b, \r1\().16b, v28.16b
	sub	\r2\().16b, \r2\().16b, v28.16b
	sub	\r3\().16b, \r3\().16b, v28.16b
	sub	\r4\().16b, \r4\().16b, v28.16b
	sub	\r5\().16b, \r5\().16b, v28.16b
	sub	\r6\().16b, \r6\().16b, v28.16b
	sub	\r7\().16b, \r7\().16b, v28.16b
	ld1	{v24.16b-v27.16b}, [x5], #64
	tbx	v16.16b, {v24.16b-v27.16b}, \r0\().16b
	tbx	v17.16b, {v24.16b-v27.16b}, \r1\().16b
	tbx	v18.16b, {v24.16b-v27.16b}, \r2\().16b
	tbx	v19.16b, {v24.16b-v27.16b}, \r3\().16b
	tbx	v20.16b, {v24.16b-v27.16b}, \r4\().16b
	tbx	v21.16b, {v24.16b-v27.16b}, \r5\().16b
	tbx	v22.16b, {v24.16b-v27.16b}, \r6\().16b
	tbx	v23.16b, {v24.16b-v27.16b}, \r7\().16b

	sub	\r0\().16b, \r0\().16b, v28.16b
	sub	\r1\().16b, \r1\().16b, v28.16b
	sub	\r2\().16b, \r2\().16b, v28.16b
	sub	\r3\().16b, \r3\().16b, v28.16b
	sub	\r4\().16b, \r4\().16b, v28.16b
	sub	\r5\().16b, \r5\().16b, v28.16b
	sub	\r6\().16b, \r6\().16b, v28.16b
	sub	\r7\().16b, \r7\().16b, v28.16b
	ld1	{v24.16b-v27.16b}, [x5], #64
	tbx	v16.16b, {v24.16b-v27.16b}, \r0\().16b
	tbx	v17.16b, {v24.16b-v27.16b}, \r1\().16b
	tbx	v18.16b, {v24.16b-v27.16b}, \r2\().16b
	tbx	v19.16b, {v24.16b-v27.16b}, \r3\().16b
	tbx	v20.16b, {v24.16b-v27.16b}, \r4\().16b
	tbx	v21.16b, {v24.16b-v27.16b}, \r5\().16b
	tbx	v22.16b, {v24.16b-v27.16b}, \r6\().16b
	tbx	v23.16b, {v24.16b-v27.16b}, \r7\().16b

	sub	\r0\().16b, \r0\().16b, v28.16b
	sub	\r1\().16b, \r1\().16b, v28.16b
	sub	\r2\().16b, \r2\().16b, v28.16b
	sub	\r3\().16b, \r3\().16b, v28.16b
	sub	\r4\().16b, \r4\().16b, v28.16b
	sub	\r5\().16b, \r5\().16b, v28.16b
	sub	\r6\().16b, \r6\().16b, v28.16b
	sub	\r7\().16b, \r7\().16b, v28.16b
	ld1	{v24.16b-v27.16b}, [x5]
	tbx	v16.16b, {v24.16b-v27.16b}, \r0\().16b
	tbx	v17.16b, {v24.16b-v27.16b}, \r1\().16b
	tbx	v18.16b, {v24.16b-v27.16b}, \r2\().16b
	tbx	v19.16b, {v24.16b-v27.16b}, \r3\().16b
	tbx	v20.16b, {v24.16b-v27.16b}, \r4\().16b
	tbx	v21.16b, {v24.16b-v27.16b}, \r5\().16b
	tbx	v22.16b, {v24.16b-v27.16b}, \r6\().16b
	tbx	v23.16b, {v24.16b-v27.16b}, \r7\().16b

	mov	\r0\().16b, v16.16b
	mov	\r1\().16b, v17.16b
	mov	\r2\().16b, v18.16b
	mov	\r3\().16b, v19.16b
	mov	\r4\().16b, v20.16b
	mov	\r5\().16b, v21.16b
	mov	\r6\().16b, v22.16b
	mov	\r7\().16b, v23.16b
.endm

.macro KUZ_SBOX16
	KUZ_SBOX16_GROUP v0, v1, v2, v3, v4, v5, v6, v7
	KUZ_SBOX16_GROUP v8, v9, v10, v11, v12, v13, v14, v15
.endm

/* Transpose 16 blocks (16x16 bytes) in place */
.macro KUZ_PACK16
	trn1	v16.16b, v0.16b, v1.16b
	trn2	v17.16b, v0.16b, v1.16b
	trn1	v18.16b, v2.16b, v3.16b
	trn2	v19.16b, v2.16b, v3.16b
	trn1	v20.16b, v4.16b, v5.16b
	trn2	v21.16b, v4.16b, v5.16b
	trn1	v22.16b, v6.16b, v7.16b
	trn2	v23.16b, v6.16b, v7.16b
	trn1	v24.16b, v8.16b, v9.16b
	trn2	v25.16b, v8.16b, v9.16b
	trn1	v26.16b, v10.16b, v11.16b
	trn2	v27.16b, v10.16b, v11.16b
	trn1	v28.16b, v12.16b, v13.16b
	trn2	v29.16b, v12.16b, v13.16b
	trn1	v30.16b, v14.16b, v15.16b
	trn2	v31.16b, v14.16b, v15.16b

	trn1	v0.8h, v16.8h, v18.8h
	trn2	v2.8h, v16.8h, v18.8h
	trn1	v1.8h, v17.8h, v19.8h
	trn2	v3.8h, v17.8h, v19.8h
	trn1	v4.8h, v20.8h, v22.8h
	trn2	v6.8h, v20.8h, v22.8h
	trn1	v5.8h, v21.8h, v23.8h
	trn2	v7.8h, v21.8h, v23.8h
	trn1	v8.8h, v24.8h, v26.8h
	trn2	v10.8h, v24.8h, v26.8h
	trn1	v9.8h, v25.8h, v27.8h
	trn2	v11.8h, v25.8h, v27.8h
	trn1	v12.8h, v28.8h, v30.8h
	trn2	v14.8h, v28.8h, v30.8h
	trn1	v13.8h, v29.8h, v31.8h
	trn2	v15.8h, v29.8h, v31.8h

	trn1	v16.4s, v0.4s, v4.4s
	trn2	v20.4s, v0.4s, v4.4s
	trn1	v18.4s, v2.4s, v6.4s
	trn2	v22.4s, v2.4s, v6.4s
	trn1	v17.4s, v1.4s, v5.4s
	trn2	v21.4s, v1.4s, v5.4s
	trn1	v19.4s, v3.4s, v7.4s
	trn2	v23.4s, v3.4s, v7.4s
	trn1	v24.4s, v8.4s, v12.4s
	trn2	v28.4s, v8.4s, v12.4s
	trn1	v26.4s, v10.4s, v14.4s
	trn2	v30.4s, v10.4s, v14.4s
	trn1	v25.4s, v9.4s, v13.4s
	trn2	v29.4s, v9.4s, v13.4s
	trn1	v27.4s, v11.4s, v15.4s
	trn2	v31.4s, v11.4s, v15.4s

	trn1	v0.2d, v16.2d, v24.2d
	trn2	v8.2d, v16.2d, v24.2d
	trn1	v4.2d, v20.2d, v28.2d
	trn2	v12.2d, v20.2d, v28.2d
	trn1	v2.2d, v18.2d, v26.2d
	trn2	v10.2d, v18.2d, v26.2d
	trn1	v6.2d, v22.2d, v30.2d
	trn2	v14.2d, v22.2d, v30.2d
	trn1	v1.2d, v17.2d, v25.2d
	trn2	v9.2d, v17.2d, v25.2d
	trn1	v5.2d, v21.2d, v29.2d
	trn2	v13.2d, v21.2d, v29.2d
	trn1	v3.2d, v19.2d, v27.2d
	trn2	v11.2d, v19.2d, v27.2d
	trn1	v7.2d, v23.2d, v31.2d
	trn2	v15.2d, v23.2d, v31.2d
.endm

/*
 * GF(2^8), p(x) = x^8 + x^7 + x^6 + x + 1 (0x1c3).
 * Full 16-way width using .16b instructions.
 */


/* One R step (16-way width). */
.macro KUZ_R16 a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15
	/* C, E, F, B, A, D and G ^ C ^ E ^ F. */
	eor	v16.16b, \a2\().16b, \a12\().16b
	eor	v17.16b, \a4\().16b, \a10\().16b
	eor	v18.16b, \a5\().16b, \a9\().16b
	eor	v19.16b, \a1\().16b, \a13\().16b
	eor	v20.16b, \a0\().16b, \a14\().16b
	eor	v21.16b, \a3\().16b, \a11\().16b
	eor	v22.16b, \a15\().16b, \a6\().16b
	eor	v23.16b, v17.16b, v18.16b
	eor	v22.16b, v22.16b, \a8\().16b
	eor	v22.16b, v22.16b, v16.16b
	eor	v22.16b, v22.16b, v23.16b

	/* Start 195 * (E ^ F), then fill tbl latency with 2*F and 2*B. */
	ushr	v31.16b, v23.16b, #4
	and	v23.16b, v23.16b, v29.16b
	tbl	v23.16b, {v25.16b}, v23.16b

	sshr	v17.16b, v18.16b, #7
	shl	v18.16b, v18.16b, #1
	and	v17.16b, v17.16b, v30.16b
	eor	v18.16b, v18.16b, v17.16b

	sshr	v17.16b, v19.16b, #7
	shl	v19.16b, v19.16b, #1
	and	v17.16b, v17.16b, v30.16b
	eor	v19.16b, v19.16b, v17.16b

	tbl	v31.16b, {v28.16b}, v31.16b

	/* Prepare the 16 * branch while the second 195 lookup completes. */
	eor	v19.16b, v19.16b, v16.16b
	eor	v19.16b, v19.16b, v21.16b
	eor	v19.16b, v19.16b, \a7\().16b
	eor	v23.16b, v23.16b, v31.16b

	ushr	v31.16b, v19.16b, #4
	and	v19.16b, v19.16b, v29.16b
	tbl	v19.16b, {v24.16b}, v19.16b

	/* Prepare 148 * (A ^ C ^ 2*H) while the 16 lookup is in flight. */
	sshr	v17.16b, \a7\().16b, #7
	shl	v21.16b, \a7\().16b, #1
	and	v17.16b, v17.16b, v30.16b
	eor	v21.16b, v21.16b, v17.16b
	eor	v20.16b, v20.16b, v16.16b
	eor	v20.16b, v20.16b, v21.16b
	eor	v18.16b, v18.16b, v23.16b

	tbl	v31.16b, {v25.16b}, v31.16b
	eor	v19.16b, v19.16b, v31.16b

	/* 148 * branch. */
	ushr	v31.16b, v20.16b, #4
	and	v20.16b, v20.16b, v29.16b
	tbl	v20.16b, {v26.16b}, v20.16b
	eor	v22.16b, v22.16b, v18.16b
	tbl	v31.16b, {v27.16b}, v31.16b
	eor	v20.16b, v20.16b, v31.16b

	/* Balanced final reduction, then overwrite the dropped byte position. */
	eor	v19.16b, v19.16b, v20.16b
	eor	\a15\().16b, v22.16b, v19.16b
.endm

.macro KUZ_L16
	adrp	x5, .Lkuz_lmul
	add	x5, x5, :lo12:.Lkuz_lmul
	ld1	{v24.16b-v27.16b}, [x5], #64
	ldr	q28, [x5]
	movi	v29.16b, #0x0f
	movi	v30.16b, #0xc3

	KUZ_R16 v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15
	KUZ_R16 v15, v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14
	KUZ_R16 v14, v15, v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13
	KUZ_R16 v13, v14, v15, v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12
	KUZ_R16 v12, v13, v14, v15, v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11
	KUZ_R16 v11, v12, v13, v14, v15, v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10
	KUZ_R16 v10, v11, v12, v13, v14, v15, v0, v1, v2, v3, v4, v5, v6, v7, v8, v9
	KUZ_R16 v9, v10, v11, v12, v13, v14, v15, v0, v1, v2, v3, v4, v5, v6, v7, v8
	KUZ_R16 v8, v9, v10, v11, v12, v13, v14, v15, v0, v1, v2, v3, v4, v5, v6, v7
	KUZ_R16 v7, v8, v9, v10, v11, v12, v13, v14, v15, v0, v1, v2, v3, v4, v5, v6
	KUZ_R16 v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v0, v1, v2, v3, v4, v5
	KUZ_R16 v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v0, v1, v2, v3, v4
	KUZ_R16 v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v0, v1, v2, v3
	KUZ_R16 v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v0, v1, v2
	KUZ_R16 v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v0, v1
	KUZ_R16 v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v0
.endm

.macro KUZ_TRANSFORM16_TABLELESS
	KUZ_SBOX16
	KUZ_PACK16
	KUZ_L16
	KUZ_PACK16 /* 16x16 trn unpacking is identical */
.endm

/*
 * void kuz_encrypt_16way(const u8 *key, u8 *dst, const u8 *src);
 */
SYM_FUNC_START(kuz_encrypt_16way)
	ldp	q0, q1, [x2]
	ldp	q2, q3, [x2, #32]
	ldp	q4, q5, [x2, #64]
	ldp	q6, q7, [x2, #96]
	ldp	q8, q9, [x2, #128]
	ldp	q10, q11, [x2, #160]
	ldp	q12, q13, [x2, #192]
	ldp	q14, q15, [x2, #224]
	mov	x6, x0
	mov	w7, #9

.Lkuz_enc_sixteen_round:
	ldr	q16, [x6], #16
	eor	v0.16b, v0.16b, v16.16b
	eor	v1.16b, v1.16b, v16.16b
	eor	v2.16b, v2.16b, v16.16b
	eor	v3.16b, v3.16b, v16.16b
	eor	v4.16b, v4.16b, v16.16b
	eor	v5.16b, v5.16b, v16.16b
	eor	v6.16b, v6.16b, v16.16b
	eor	v7.16b, v7.16b, v16.16b
	eor	v8.16b, v8.16b, v16.16b
	eor	v9.16b, v9.16b, v16.16b
	eor	v10.16b, v10.16b, v16.16b
	eor	v11.16b, v11.16b, v16.16b
	eor	v12.16b, v12.16b, v16.16b
	eor	v13.16b, v13.16b, v16.16b
	eor	v14.16b, v14.16b, v16.16b
	eor	v15.16b, v15.16b, v16.16b
	KUZ_TRANSFORM16_TABLELESS
	subs	w7, w7, #1
	b.ne	.Lkuz_enc_sixteen_round

	ldr	q16, [x6]
	eor	v0.16b, v0.16b, v16.16b
	eor	v1.16b, v1.16b, v16.16b
	eor	v2.16b, v2.16b, v16.16b
	eor	v3.16b, v3.16b, v16.16b
	eor	v4.16b, v4.16b, v16.16b
	eor	v5.16b, v5.16b, v16.16b
	eor	v6.16b, v6.16b, v16.16b
	eor	v7.16b, v7.16b, v16.16b
	eor	v8.16b, v8.16b, v16.16b
	eor	v9.16b, v9.16b, v16.16b
	eor	v10.16b, v10.16b, v16.16b
	eor	v11.16b, v11.16b, v16.16b
	eor	v12.16b, v12.16b, v16.16b
	eor	v13.16b, v13.16b, v16.16b
	eor	v14.16b, v14.16b, v16.16b
	eor	v15.16b, v15.16b, v16.16b

	stp	q0, q1, [x1]
	stp	q2, q3, [x1, #32]
	stp	q4, q5, [x1, #64]
	stp	q6, q7, [x1, #96]
	stp	q8, q9, [x1, #128]
	stp	q10, q11, [x1, #160]
	stp	q12, q13, [x1, #192]
	stp	q14, q15, [x1, #224]
	ret
SYM_FUNC_END(kuz_encrypt_16way)

/* Benchmark-only primitives */
SYM_FUNC_START(kuz_sbox_16way)
	ldp	q0, q1, [x1]
	ldp	q2, q3, [x1, #32]
	ldp	q4, q5, [x1, #64]
	ldp	q6, q7, [x1, #96]
	ldp	q8, q9, [x1, #128]
	ldp	q10, q11, [x1, #160]
	ldp	q12, q13, [x1, #192]
	ldp	q14, q15, [x1, #224]
	KUZ_SBOX16
	stp	q0, q1, [x0]
	stp	q2, q3, [x0, #32]
	stp	q4, q5, [x0, #64]
	stp	q6, q7, [x0, #96]
	stp	q8, q9, [x0, #128]
	stp	q10, q11, [x0, #160]
	stp	q12, q13, [x0, #192]
	stp	q14, q15, [x0, #224]
	ret
SYM_FUNC_END(kuz_sbox_16way)

SYM_FUNC_START(kuz_l_16way)
	ldp	q0, q1, [x1]
	ldp	q2, q3, [x1, #32]
	ldp	q4, q5, [x1, #64]
	ldp	q6, q7, [x1, #96]
	ldp	q8, q9, [x1, #128]
	ldp	q10, q11, [x1, #160]
	ldp	q12, q13, [x1, #192]
	ldp	q14, q15, [x1, #224]
	KUZ_PACK16
	KUZ_L16
	KUZ_PACK16
	stp	q0, q1, [x0]
	stp	q2, q3, [x0, #32]
	stp	q4, q5, [x0, #64]
	stp	q6, q7, [x0, #96]
	stp	q8, q9, [x0, #128]
	stp	q10, q11, [x0, #160]
	stp	q12, q13, [x0, #192]
	stp	q14, q15, [x0, #224]
	ret
SYM_FUNC_END(kuz_l_16way)


/*
 * void kuz_ctr_16way(const u8 *key, u8 *dst, const u8 *src, u8 *ctr);
 */
SYM_FUNC_START(kuz_ctr_16way)
	ldr	x8, [x3]
	ldr	x9, [x3, #8]
	rev	x8, x8
	rev	x9, x9

	KUZ_CTR_BLOCK 0, 0
	KUZ_CTR_BLOCK 1, 1
	KUZ_CTR_BLOCK 2, 2
	KUZ_CTR_BLOCK 3, 3
	KUZ_CTR_BLOCK 4, 4
	KUZ_CTR_BLOCK 5, 5
	KUZ_CTR_BLOCK 6, 6
	KUZ_CTR_BLOCK 7, 7
	KUZ_CTR_BLOCK 8, 8
	KUZ_CTR_BLOCK 9, 9
	KUZ_CTR_BLOCK 10, 10
	KUZ_CTR_BLOCK 11, 11
	KUZ_CTR_BLOCK 12, 12
	KUZ_CTR_BLOCK 13, 13
	KUZ_CTR_BLOCK 14, 14
	KUZ_CTR_BLOCK 15, 15

	adds	x10, x9, #16
	adc	x11, x8, xzr
	rev	x10, x10
	rev	x11, x11
	str	x11, [x3]
	str	x10, [x3, #8]

	mov	x6, x0
	mov	w7, #9
.Lkuz_ctr_sixteen_round:
	ldr	q16, [x6], #16
	eor	v0.16b, v0.16b, v16.16b
	eor	v1.16b, v1.16b, v16.16b
	eor	v2.16b, v2.16b, v16.16b
	eor	v3.16b, v3.16b, v16.16b
	eor	v4.16b, v4.16b, v16.16b
	eor	v5.16b, v5.16b, v16.16b
	eor	v6.16b, v6.16b, v16.16b
	eor	v7.16b, v7.16b, v16.16b
	eor	v8.16b, v8.16b, v16.16b
	eor	v9.16b, v9.16b, v16.16b
	eor	v10.16b, v10.16b, v16.16b
	eor	v11.16b, v11.16b, v16.16b
	eor	v12.16b, v12.16b, v16.16b
	eor	v13.16b, v13.16b, v16.16b
	eor	v14.16b, v14.16b, v16.16b
	eor	v15.16b, v15.16b, v16.16b
	KUZ_TRANSFORM16_TABLELESS
	subs	w7, w7, #1
	b.ne	.Lkuz_ctr_sixteen_round

	ldr	q16, [x6]
	eor	v0.16b, v0.16b, v16.16b
	eor	v1.16b, v1.16b, v16.16b
	eor	v2.16b, v2.16b, v16.16b
	eor	v3.16b, v3.16b, v16.16b
	eor	v4.16b, v4.16b, v16.16b
	eor	v5.16b, v5.16b, v16.16b
	eor	v6.16b, v6.16b, v16.16b
	eor	v7.16b, v7.16b, v16.16b
	eor	v8.16b, v8.16b, v16.16b
	eor	v9.16b, v9.16b, v16.16b
	eor	v10.16b, v10.16b, v16.16b
	eor	v11.16b, v11.16b, v16.16b
	eor	v12.16b, v12.16b, v16.16b
	eor	v13.16b, v13.16b, v16.16b
	eor	v14.16b, v14.16b, v16.16b
	eor	v15.16b, v15.16b, v16.16b

	ldp	q16, q17, [x2]
	eor	v0.16b, v0.16b, v16.16b
	eor	v1.16b, v1.16b, v17.16b
	stp	q0, q1, [x1]

	ldp	q16, q17, [x2, #32]
	eor	v2.16b, v2.16b, v16.16b
	eor	v3.16b, v3.16b, v17.16b
	stp	q2, q3, [x1, #32]

	ldp	q16, q17, [x2, #64]
	eor	v4.16b, v4.16b, v16.16b
	eor	v5.16b, v5.16b, v17.16b
	stp	q4, q5, [x1, #64]

	ldp	q16, q17, [x2, #96]
	eor	v6.16b, v6.16b, v16.16b
	eor	v7.16b, v7.16b, v17.16b
	stp	q6, q7, [x1, #96]

	ldp	q16, q17, [x2, #128]
	eor	v8.16b, v8.16b, v16.16b
	eor	v9.16b, v9.16b, v17.16b
	stp	q8, q9, [x1, #128]

	ldp	q16, q17, [x2, #160]
	eor	v10.16b, v10.16b, v16.16b
	eor	v11.16b, v11.16b, v17.16b
	stp	q10, q11, [x1, #160]

	ldp	q16, q17, [x2, #192]
	eor	v12.16b, v12.16b, v16.16b
	eor	v13.16b, v13.16b, v17.16b
	stp	q12, q13, [x1, #192]

	ldp	q16, q17, [x2, #224]
	eor	v14.16b, v14.16b, v16.16b
	eor	v15.16b, v15.16b, v17.16b
	stp	q14, q15, [x1, #224]
	ret
SYM_FUNC_END(kuz_ctr_16way)

.macro KUZ_LOOKUP16_ONE dst, shift, reg_val
	ubfx	x10, \reg_val, #\shift, #8
	add	x10, x5, x10, lsl #4
	ldr	q16, [x10]
	eor	\dst\().16b, \dst\().16b, v16.16b
.endm

.macro KUZ_POS16 table, sp_offset, pos
	ldp	x8, x9, [sp, #\sp_offset]
	add	x5, \table, #\pos, lsl #12
	KUZ_LOOKUP16_ONE v0, 0, x8
	KUZ_LOOKUP16_ONE v1, 8, x8
	KUZ_LOOKUP16_ONE v2, 16, x8
	KUZ_LOOKUP16_ONE v3, 24, x8
	KUZ_LOOKUP16_ONE v4, 32, x8
	KUZ_LOOKUP16_ONE v5, 40, x8
	KUZ_LOOKUP16_ONE v6, 48, x8
	KUZ_LOOKUP16_ONE v7, 56, x8
	KUZ_LOOKUP16_ONE v8, 0, x9
	KUZ_LOOKUP16_ONE v9, 8, x9
	KUZ_LOOKUP16_ONE v10, 16, x9
	KUZ_LOOKUP16_ONE v11, 24, x9
	KUZ_LOOKUP16_ONE v12, 32, x9
	KUZ_LOOKUP16_ONE v13, 40, x9
	KUZ_LOOKUP16_ONE v14, 48, x9
	KUZ_LOOKUP16_ONE v15, 56, x9
.endm

.macro KUZ_TRANSFORM16 table
	KUZ_PACK16

	sub	sp, sp, #256
	stp	q0, q1, [sp]
	stp	q2, q3, [sp, #32]
	stp	q4, q5, [sp, #64]
	stp	q6, q7, [sp, #96]
	stp	q8, q9, [sp, #128]
	stp	q10, q11, [sp, #160]
	stp	q12, q13, [sp, #192]
	stp	q14, q15, [sp, #224]

	movi	v0.16b, #0
	movi	v1.16b, #0
	movi	v2.16b, #0
	movi	v3.16b, #0
	movi	v4.16b, #0
	movi	v5.16b, #0
	movi	v6.16b, #0
	movi	v7.16b, #0
	movi	v8.16b, #0
	movi	v9.16b, #0
	movi	v10.16b, #0
	movi	v11.16b, #0
	movi	v12.16b, #0
	movi	v13.16b, #0
	movi	v14.16b, #0
	movi	v15.16b, #0

	KUZ_POS16 \table, 0, 0
	KUZ_POS16 \table, 16, 1
	KUZ_POS16 \table, 32, 2
	KUZ_POS16 \table, 48, 3
	KUZ_POS16 \table, 64, 4
	KUZ_POS16 \table, 80, 5
	KUZ_POS16 \table, 96, 6
	KUZ_POS16 \table, 112, 7
	KUZ_POS16 \table, 128, 8
	KUZ_POS16 \table, 144, 9
	KUZ_POS16 \table, 160, 10
	KUZ_POS16 \table, 176, 11
	KUZ_POS16 \table, 192, 12
	KUZ_POS16 \table, 208, 13
	KUZ_POS16 \table, 224, 14
	KUZ_POS16 \table, 240, 15

	add	sp, sp, #256
.endm

/*
 * void kuz_decrypt_16way(const u8 *dekey, u8 *dst, const u8 *src,
 *                        const u8 *inv_table, const u8 *inv_ls_table);
 */
SYM_FUNC_START(kuz_decrypt_16way)
	ldp	q0, q1, [x2]
	ldp	q2, q3, [x2, #32]
	ldp	q4, q5, [x2, #64]
	ldp	q6, q7, [x2, #96]
	ldp	q8, q9, [x2, #128]
	ldp	q10, q11, [x2, #160]
	ldp	q12, q13, [x2, #192]
	ldp	q14, q15, [x2, #224]

	KUZ_TRANSFORM16 x3
	ldr	q16, [x0, #144]
	eor	v0.16b, v0.16b, v16.16b
	eor	v1.16b, v1.16b, v16.16b
	eor	v2.16b, v2.16b, v16.16b
	eor	v3.16b, v3.16b, v16.16b
	eor	v4.16b, v4.16b, v16.16b
	eor	v5.16b, v5.16b, v16.16b
	eor	v6.16b, v6.16b, v16.16b
	eor	v7.16b, v7.16b, v16.16b
	eor	v8.16b, v8.16b, v16.16b
	eor	v9.16b, v9.16b, v16.16b
	eor	v10.16b, v10.16b, v16.16b
	eor	v11.16b, v11.16b, v16.16b
	eor	v12.16b, v12.16b, v16.16b
	eor	v13.16b, v13.16b, v16.16b
	eor	v14.16b, v14.16b, v16.16b
	eor	v15.16b, v15.16b, v16.16b

	mov	x3, x4
	add	x6, x0, #128
	mov	w7, #8

.Lkuz_dec_sixteen_round:
	KUZ_TRANSFORM16 x3
	ldr	q16, [x6], #-16
	eor	v0.16b, v0.16b, v16.16b
	eor	v1.16b, v1.16b, v16.16b
	eor	v2.16b, v2.16b, v16.16b
	eor	v3.16b, v3.16b, v16.16b
	eor	v4.16b, v4.16b, v16.16b
	eor	v5.16b, v5.16b, v16.16b
	eor	v6.16b, v6.16b, v16.16b
	eor	v7.16b, v7.16b, v16.16b
	eor	v8.16b, v8.16b, v16.16b
	eor	v9.16b, v9.16b, v16.16b
	eor	v10.16b, v10.16b, v16.16b
	eor	v11.16b, v11.16b, v16.16b
	eor	v12.16b, v12.16b, v16.16b
	eor	v13.16b, v13.16b, v16.16b
	eor	v14.16b, v14.16b, v16.16b
	eor	v15.16b, v15.16b, v16.16b
	subs	w7, w7, #1
	b.ne	.Lkuz_dec_sixteen_round

	stp	q0, q1, [x1]
	stp	q2, q3, [x1, #32]
	stp	q4, q5, [x1, #64]
	stp	q6, q7, [x1, #96]
	stp	q8, q9, [x1, #128]
	stp	q10, q11, [x1, #160]
	stp	q12, q13, [x1, #192]
	stp	q14, q15, [x1, #224]
	ret
SYM_FUNC_END(kuz_decrypt_16way)


.pushsection .rodata
.align 4
.Lkuz_pi:
	.byte 0xfc, 0xee, 0xdd, 0x11, 0xcf, 0x6e, 0x31, 0x16
	.byte 0xfb, 0xc4, 0xfa, 0xda, 0x23, 0xc5, 0x04, 0x4d
	.byte 0xe9, 0x77, 0xf0, 0xdb, 0x93, 0x2e, 0x99, 0xba
	.byte 0x17, 0x36, 0xf1, 0xbb, 0x14, 0xcd, 0x5f, 0xc1
	.byte 0xf9, 0x18, 0x65, 0x5a, 0xe2, 0x5c, 0xef, 0x21
	.byte 0x81, 0x1c, 0x3c, 0x42, 0x8b, 0x01, 0x8e, 0x4f
	.byte 0x05, 0x84, 0x02, 0xae, 0xe3, 0x6a, 0x8f, 0xa0
	.byte 0x06, 0x0b, 0xed, 0x98, 0x7f, 0xd4, 0xd3, 0x1f
	.byte 0xeb, 0x34, 0x2c, 0x51, 0xea, 0xc8, 0x48, 0xab
	.byte 0xf2, 0x2a, 0x68, 0xa2, 0xfd, 0x3a, 0xce, 0xcc
	.byte 0xb5, 0x70, 0x0e, 0x56, 0x08, 0x0c, 0x76, 0x12
	.byte 0xbf, 0x72, 0x13, 0x47, 0x9c, 0xb7, 0x5d, 0x87
	.byte 0x15, 0xa1, 0x96, 0x29, 0x10, 0x7b, 0x9a, 0xc7
	.byte 0xf3, 0x91, 0x78, 0x6f, 0x9d, 0x9e, 0xb2, 0xb1
	.byte 0x32, 0x75, 0x19, 0x3d, 0xff, 0x35, 0x8a, 0x7e
	.byte 0x6d, 0x54, 0xc6, 0x80, 0xc3, 0xbd, 0x0d, 0x57
	.byte 0xdf, 0xf5, 0x24, 0xa9, 0x3e, 0xa8, 0x43, 0xc9
	.byte 0xd7, 0x79, 0xd6, 0xf6, 0x7c, 0x22, 0xb9, 0x03
	.byte 0xe0, 0x0f, 0xec, 0xde, 0x7a, 0x94, 0xb0, 0xbc
	.byte 0xdc, 0xe8, 0x28, 0x50, 0x4e, 0x33, 0x0a, 0x4a
	.byte 0xa7, 0x97, 0x60, 0x73, 0x1e, 0x00, 0x62, 0x44
	.byte 0x1a, 0xb8, 0x38, 0x82, 0x64, 0x9f, 0x26, 0x41
	.byte 0xad, 0x45, 0x46, 0x92, 0x27, 0x5e, 0x55, 0x2f
	.byte 0x8c, 0xa3, 0xa5, 0x7d, 0x69, 0xd5, 0x95, 0x3b
	.byte 0x07, 0x58, 0xb3, 0x40, 0x86, 0xac, 0x1d, 0xf7
	.byte 0x30, 0x37, 0x6b, 0xe4, 0x88, 0xd9, 0xe7, 0x89
	.byte 0xe1, 0x1b, 0x83, 0x49, 0x4c, 0x3f, 0xf8, 0xfe
	.byte 0x8d, 0x53, 0xaa, 0x90, 0xca, 0xd8, 0x85, 0x61
	.byte 0x20, 0x71, 0x67, 0xa4, 0x2d, 0x2b, 0x09, 0x5b
	.byte 0xcb, 0x9b, 0x25, 0xd0, 0xbe, 0xe5, 0x6c, 0x52
	.byte 0x59, 0xa6, 0x74, 0xd2, 0xe6, 0xf4, 0xb4, 0xc0
	.byte 0xd1, 0x66, 0xaf, 0xc2, 0x39, 0x4b, 0x63, 0xb6

.align 4
.Lkuz_lmul:
	/* mul16 low, mul16 high == mul195 low */
	.byte 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70
	.byte 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0
	.byte 0x00, 0xc3, 0x45, 0x86, 0x8a, 0x49, 0xcf, 0x0c
	.byte 0xd7, 0x14, 0x92, 0x51, 0x5d, 0x9e, 0x18, 0xdb
	/* mul148 low/high */
	.byte 0x00, 0x94, 0xeb, 0x7f, 0x15, 0x81, 0xfe, 0x6a
	.byte 0x2a, 0xbe, 0xc1, 0x55, 0x3f, 0xab, 0xd4, 0x40
	.byte 0x00, 0x54, 0xa8, 0xfc, 0x93, 0xc7, 0x3b, 0x6f
	.byte 0xe5, 0xb1, 0x4d, 0x19, 0x76, 0x22, 0xde, 0x8a
	/* mul195 high */
	.byte 0x00, 0x6d, 0xda, 0xb7, 0x77, 0x1a, 0xad, 0xc0
	.byte 0xee, 0x83, 0x34, 0x59, 0x99, 0xf4, 0x43, 0x2e
.popsection
