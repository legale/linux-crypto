/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Four-block ARM64 NEON core for GOST R 34.12-2015 Kuznyechik.
 */

#include <linux/linkage.h>

.text

.macro KUZ_LOOKUP4 lane
  umov w9, v0.b[\lane]
  umov w10, v1.b[\lane]
  umov w11, v2.b[\lane]
  umov w12, v3.b[\lane]

  add x9, x5, x9, lsl #4
  ldr q16, [x9]
  eor v4.16b, v4.16b, v16.16b

  add x10, x5, x10, lsl #4
  ldr q16, [x10]
  eor v5.16b, v5.16b, v16.16b

  add x11, x5, x11, lsl #4
  ldr q16, [x11]
  eor v6.16b, v6.16b, v16.16b

  add x12, x5, x12, lsl #4
  ldr q16, [x12]
  eor v7.16b, v7.16b, v16.16b

  add x5, x5, #1, lsl #12
.endm

.macro KUZ_TRANSFORM4 table
  mov x5, \table
  movi v4.16b, #0
  movi v5.16b, #0
  movi v6.16b, #0
  movi v7.16b, #0

  KUZ_LOOKUP4 0
  KUZ_LOOKUP4 1
  KUZ_LOOKUP4 2
  KUZ_LOOKUP4 3
  KUZ_LOOKUP4 4
  KUZ_LOOKUP4 5
  KUZ_LOOKUP4 6
  KUZ_LOOKUP4 7
  KUZ_LOOKUP4 8
  KUZ_LOOKUP4 9
  KUZ_LOOKUP4 10
  KUZ_LOOKUP4 11
  KUZ_LOOKUP4 12
  KUZ_LOOKUP4 13
  KUZ_LOOKUP4 14
  KUZ_LOOKUP4 15

  mov v0.16b, v4.16b
  mov v1.16b, v5.16b
  mov v2.16b, v6.16b
  mov v3.16b, v7.16b
.endm

/*
 * void kuz_encrypt_4way(const u8 *key, u8 *dst, const u8 *src,
 *                       const u8 *table);
 */
SYM_FUNC_START(kuz_encrypt_4way)
  ldp q0, q1, [x2]
  ldp q2, q3, [x2, #32]
  mov x6, x0
  mov w7, #9

.Lkuz_enc_four_round:
  ldr q16, [x6], #16
  eor v0.16b, v0.16b, v16.16b
  eor v1.16b, v1.16b, v16.16b
  eor v2.16b, v2.16b, v16.16b
  eor v3.16b, v3.16b, v16.16b
  KUZ_TRANSFORM4 x3
  subs w7, w7, #1
  b.ne .Lkuz_enc_four_round

  ldr q16, [x6]
  eor v0.16b, v0.16b, v16.16b
  eor v1.16b, v1.16b, v16.16b
  eor v2.16b, v2.16b, v16.16b
  eor v3.16b, v3.16b, v16.16b
  stp q0, q1, [x1]
  stp q2, q3, [x1, #32]
  ret
SYM_FUNC_END(kuz_encrypt_4way)

/*
 * void kuz_decrypt_4way(const u8 *dekey, u8 *dst, const u8 *src,
 *                       const u8 *inv_table, const u8 *inv_ls_table);
 */
SYM_FUNC_START(kuz_decrypt_4way)
  ldp q0, q1, [x2]
  ldp q2, q3, [x2, #32]

  KUZ_TRANSFORM4 x3
  ldr q16, [x0, #144]
  eor v0.16b, v0.16b, v16.16b
  eor v1.16b, v1.16b, v16.16b
  eor v2.16b, v2.16b, v16.16b
  eor v3.16b, v3.16b, v16.16b

  mov x3, x4
  add x6, x0, #128
  mov w7, #8

.Lkuz_dec_four_round:
  KUZ_TRANSFORM4 x3
  ldr q16, [x6], #-16
  eor v0.16b, v0.16b, v16.16b
  eor v1.16b, v1.16b, v16.16b
  eor v2.16b, v2.16b, v16.16b
  eor v3.16b, v3.16b, v16.16b
  subs w7, w7, #1
  b.ne .Lkuz_dec_four_round

  stp q0, q1, [x1]
  stp q2, q3, [x1, #32]
  ret
SYM_FUNC_END(kuz_decrypt_4way)
