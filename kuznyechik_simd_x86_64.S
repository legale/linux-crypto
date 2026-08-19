/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Four-block x86-64 SSE2 core for GOST R 34.12-2015 Kuznyechik.
 */

#include <linux/linkage.h>

.text

.macro KUZ_LOOKUP pos, b0, b1, b2, b3
  pextrw $\pos, \b0, %eax
  pextrw $\pos, \b1, %r9d
  pextrw $\pos, \b2, %r10d
  pextrw $\pos, \b3, %r11d
  movdqu (%rcx,%rax), %xmm13
  pxor %xmm13, %xmm8
  movdqu (%rcx,%r9), %xmm13
  pxor %xmm13, %xmm9
  movdqu (%rcx,%r10), %xmm13
  pxor %xmm13, %xmm10
  movdqu (%rcx,%r11), %xmm13
  pxor %xmm13, %xmm11
.endm

.macro KUZ_LOOKUP_ONE pos, block
  pextrw $\pos, \block, %eax
  movdqu (%rcx,%rax), %xmm13
  pxor %xmm13, %xmm8
.endm

/*
 * Apply one fused table round to one block.
 *
 * Input/output: xmm0
 * Table:        rcx
 */
SYM_FUNC_START_LOCAL(kuz_transform1)
  movdqa %xmm0, %xmm4
  movdqa .Lkuz_byte_pos(%rip), %xmm12
  punpcklbw %xmm12, %xmm4
  psllw $4, %xmm4
  punpckhbw %xmm12, %xmm0
  psllw $4, %xmm0
  pxor %xmm8, %xmm8

  KUZ_LOOKUP_ONE 0, %xmm4
  KUZ_LOOKUP_ONE 1, %xmm4
  KUZ_LOOKUP_ONE 2, %xmm4
  KUZ_LOOKUP_ONE 3, %xmm4
  KUZ_LOOKUP_ONE 4, %xmm4
  KUZ_LOOKUP_ONE 5, %xmm4
  KUZ_LOOKUP_ONE 6, %xmm4
  KUZ_LOOKUP_ONE 7, %xmm4
  KUZ_LOOKUP_ONE 0, %xmm0
  KUZ_LOOKUP_ONE 1, %xmm0
  KUZ_LOOKUP_ONE 2, %xmm0
  KUZ_LOOKUP_ONE 3, %xmm0
  KUZ_LOOKUP_ONE 4, %xmm0
  KUZ_LOOKUP_ONE 5, %xmm0
  KUZ_LOOKUP_ONE 6, %xmm0
  KUZ_LOOKUP_ONE 7, %xmm0

  movdqa %xmm8, %xmm0
  RET
SYM_FUNC_END(kuz_transform1)

/*
 * Apply one fused table round to four independent blocks.
 *
 * Input:  xmm0..xmm3
 * Output: xmm0..xmm3
 * Table:  rcx
 */
SYM_FUNC_START_LOCAL(kuz_transform4)
  movdqa %xmm0, %xmm4
  movdqa %xmm1, %xmm5
  movdqa %xmm2, %xmm6
  movdqa %xmm3, %xmm7

  movdqa .Lkuz_byte_pos(%rip), %xmm12
  punpcklbw %xmm12, %xmm4
  punpcklbw %xmm12, %xmm5
  punpcklbw %xmm12, %xmm6
  punpcklbw %xmm12, %xmm7
  psllw $4, %xmm4
  psllw $4, %xmm5
  psllw $4, %xmm6
  psllw $4, %xmm7
  punpckhbw %xmm12, %xmm0
  punpckhbw %xmm12, %xmm1
  punpckhbw %xmm12, %xmm2
  punpckhbw %xmm12, %xmm3
  psllw $4, %xmm0
  psllw $4, %xmm1
  psllw $4, %xmm2
  psllw $4, %xmm3

  pxor %xmm8, %xmm8
  pxor %xmm9, %xmm9
  pxor %xmm10, %xmm10
  pxor %xmm11, %xmm11

  KUZ_LOOKUP 0, %xmm4, %xmm5, %xmm6, %xmm7
  KUZ_LOOKUP 1, %xmm4, %xmm5, %xmm6, %xmm7
  KUZ_LOOKUP 2, %xmm4, %xmm5, %xmm6, %xmm7
  KUZ_LOOKUP 3, %xmm4, %xmm5, %xmm6, %xmm7
  KUZ_LOOKUP 4, %xmm4, %xmm5, %xmm6, %xmm7
  KUZ_LOOKUP 5, %xmm4, %xmm5, %xmm6, %xmm7
  KUZ_LOOKUP 6, %xmm4, %xmm5, %xmm6, %xmm7
  KUZ_LOOKUP 7, %xmm4, %xmm5, %xmm6, %xmm7
  KUZ_LOOKUP 0, %xmm0, %xmm1, %xmm2, %xmm3
  KUZ_LOOKUP 1, %xmm0, %xmm1, %xmm2, %xmm3
  KUZ_LOOKUP 2, %xmm0, %xmm1, %xmm2, %xmm3
  KUZ_LOOKUP 3, %xmm0, %xmm1, %xmm2, %xmm3
  KUZ_LOOKUP 4, %xmm0, %xmm1, %xmm2, %xmm3
  KUZ_LOOKUP 5, %xmm0, %xmm1, %xmm2, %xmm3
  KUZ_LOOKUP 6, %xmm0, %xmm1, %xmm2, %xmm3
  KUZ_LOOKUP 7, %xmm0, %xmm1, %xmm2, %xmm3

  movdqa %xmm8, %xmm0
  movdqa %xmm9, %xmm1
  movdqa %xmm10, %xmm2
  movdqa %xmm11, %xmm3
  RET
SYM_FUNC_END(kuz_transform4)

SYM_FUNC_START(kuz_encrypt_4way)
  movdqu 0(%rdx), %xmm0
  movdqu 16(%rdx), %xmm1
  movdqu 32(%rdx), %xmm2
  movdqu 48(%rdx), %xmm3
  xor %edx, %edx

.Lkuz_enc_round:
  movdqu (%rdi,%rdx), %xmm13
  pxor %xmm13, %xmm0
  pxor %xmm13, %xmm1
  pxor %xmm13, %xmm2
  pxor %xmm13, %xmm3
  call kuz_transform4
  add $16, %edx
  cmp $144, %edx
  jne .Lkuz_enc_round

  movdqu 144(%rdi), %xmm13
  pxor %xmm13, %xmm0
  pxor %xmm13, %xmm1
  pxor %xmm13, %xmm2
  pxor %xmm13, %xmm3
  movdqu %xmm0, 0(%rsi)
  movdqu %xmm1, 16(%rsi)
  movdqu %xmm2, 32(%rsi)
  movdqu %xmm3, 48(%rsi)
  RET
SYM_FUNC_END(kuz_encrypt_4way)

SYM_FUNC_START(kuz_encrypt_1way)
  movdqu 0(%rdx), %xmm0
  xor %edx, %edx

.Lkuz_enc_one_round:
  movdqu (%rdi,%rdx), %xmm13
  pxor %xmm13, %xmm0
  call kuz_transform1
  add $16, %edx
  cmp $144, %edx
  jne .Lkuz_enc_one_round

  movdqu 144(%rdi), %xmm13
  pxor %xmm13, %xmm0
  movdqu %xmm0, 0(%rsi)
  RET
SYM_FUNC_END(kuz_encrypt_1way)

SYM_FUNC_START(kuz_decrypt_4way)
  movdqu 0(%rdx), %xmm0
  movdqu 16(%rdx), %xmm1
  movdqu 32(%rdx), %xmm2
  movdqu 48(%rdx), %xmm3

  call kuz_transform4
  movdqu 144(%rdi), %xmm13
  pxor %xmm13, %xmm0
  pxor %xmm13, %xmm1
  pxor %xmm13, %xmm2
  pxor %xmm13, %xmm3

  mov %r8, %rcx
  mov $128, %edx
.Lkuz_dec_round:
  call kuz_transform4
  movdqu (%rdi,%rdx), %xmm13
  pxor %xmm13, %xmm0
  pxor %xmm13, %xmm1
  pxor %xmm13, %xmm2
  pxor %xmm13, %xmm3
  sub $16, %edx
  jne .Lkuz_dec_round

  movdqu %xmm0, 0(%rsi)
  movdqu %xmm1, 16(%rsi)
  movdqu %xmm2, 32(%rsi)
  movdqu %xmm3, 48(%rsi)
  RET
SYM_FUNC_END(kuz_decrypt_4way)

.section .rodata.cst16, "aM", @progbits, 16
.align 16
.Lkuz_byte_pos:
  .byte 0, 1, 2, 3, 4, 5, 6, 7
  .byte 8, 9, 10, 11, 12, 13, 14, 15
