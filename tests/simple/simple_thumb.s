  .arch armv7-a
  .fpu vfpv3-d16
  .section .text.startup,"ax",%progbits
  .align 1
  .global _start
  .global _exit
  .syntax unified
  .thumb
  .thumb_func
_start:
  @ args = 0, pretend = 0, frame = 104
  @ frame_needed = 0, uses_anonymous_args = 0
  push  {r4, lr}
  sub   sp, sp, #4096
  mov   r3, sp
  movs  r2, #0
.L2:
  strb  r3, [sp, r2]
  adds  r2, r2, #1
  cmp   r2, #4096
  bne   .L2

  movs  r0, #0
  blx   _exit
