    .section .text
    .align 1

    .global _start

_start:
    /* Wait for WRAM reset */
    movea 0x2000, r0, r1
wait_for_wram_loop:
    add -1, r1
    bnz wait_for_wram_loop

    /* Clear PSW */
    ldsr r0, psw

    /* Disable cache */
    ldsr r0, chcw

    /* Load starting reg values */
    movhi hi(_reg_start_values), r0, r31
    movea lo(_reg_start_values), r31, r31

    /* Special handling for r31's initial value */
    ld.w 124[r31], r1
    ldsr r1, fepc

    ld.w 0[r31], r0
    ld.w 4[r31], r1
    ld.w 8[r31], r2
    ld.w 12[r31], r3
    ld.w 16[r31], r4
    ld.w 20[r31], r5
    ld.w 24[r31], r6
    ld.w 28[r31], r7
    ld.w 32[r31], r8
    ld.w 36[r31], r9
    ld.w 40[r31], r10
    ld.w 44[r31], r11
    ld.w 48[r31], r12
    ld.w 52[r31], r13
    ld.w 56[r31], r14
    ld.w 60[r31], r15
    ld.w 64[r31], r16
    ld.w 68[r31], r17
    ld.w 72[r31], r18
    ld.w 76[r31], r19
    ld.w 80[r31], r20
    ld.w 84[r31], r21
    ld.w 88[r31], r22
    ld.w 92[r31], r23
    ld.w 96[r31], r24
    ld.w 100[r31], r25
    ld.w 104[r31], r26
    ld.w 108[r31], r27
    ld.w 112[r31], r28
    ld.w 116[r31], r29
    ld.w 120[r31], r30

    stsr fepc, r31

    /* Clear PSW */
    /*ldsr r0, psw*/
    movea 0x0001, r0, r1
    ldsr r1, psw

    /* TODO: Actual test stuff :) */
    movea 0xffff, r0, r1
    add 1, r1

    /* Output result reg values */
    results = 0x0001e000

    /* Special handling for r31's result and psw */
    ldsr r31, fepc

    stsr psw, r31
    ldsr r31, fepsw

    movhi hi(results), r0, r31
    movea lo(results), r31, r31

    st.w r0, 0[r31]
    st.w r1, 4[r31]
    st.w r2, 8[r31]
    st.w r3, 12[r31]
    st.w r4, 16[r31]
    st.w r5, 20[r31]
    st.w r6, 24[r31]
    st.w r7, 28[r31]
    st.w r8, 32[r31]
    st.w r9, 36[r31]
    st.w r10, 40[r31]
    st.w r11, 44[r31]
    st.w r12, 48[r31]
    st.w r13, 52[r31]
    st.w r14, 56[r31]
    st.w r15, 60[r31]
    st.w r16, 64[r31]
    st.w r17, 68[r31]
    st.w r18, 72[r31]
    st.w r19, 76[r31]
    st.w r20, 80[r31]
    st.w r21, 84[r31]
    st.w r22, 88[r31]
    st.w r23, 92[r31]
    st.w r24, 96[r31]
    st.w r25, 100[r31]
    st.w r26, 104[r31]
    st.w r27, 108[r31]
    st.w r28, 112[r31]
    st.w r29, 116[r31]
    st.w r30, 120[r31]

    stsr fepc, r1
    st.w r1, 124[r31]

    stsr fepsw, r1
    st.w r1, 128[r31]

    /* initiallize .data section */
    movhi   hi(__data_start), r0, r7
    movea   lo(__data_start), r7, r7
    movhi   hi(__data_end),   r0, r1
    movea   lo(__data_end),   r1, r1
    movhi   hi(__data_vma),   r0, r6
    movea   lo(__data_vma),   r6, r6
    jr      end_init_data

top_init_data:
    ld.b    0[r7], r8
    st.b    r8,    0[r6]
    add     1,     r7
    add     1,     r6
end_init_data:
    cmp     r1,    r6
    blt     top_init_data

/* clear .bss section and unintialized RAM */
    movhi   hi(__bss_start), r0, r1
    movea   lo(__bss_start), r1, r1
    movhi   hi(__bss_end),   r0, r7
    movea   lo(__bss_end),   r7, r7
    jr      end_init_bss
top_init_bss:
    st.h    r0, 0[r1]
    add     1,  r1
end_init_bss:
    cmp     r7, r1
    blt     top_init_bss

/* clear .sram section and unintialized SRAM */
    movhi   hi(__sram_start),   r0, r1
    movea   lo(__sram_start),   r1, r1
    movhi   hi(__sram_end),     r0, r7
    movea   lo(__sram_end),     r7, r7
    jr      end_init_sram
top_init_sram:
    st.b    r0, 0[r1]
    add     1,  r1
end_init_sram:
    cmp     r7, r1
    blt     top_init_sram

    /* Clear PSW */
    ldsr r0, psw

    /* Disable cache */
    ldsr r0, chcw

    /* Setup sp, fp, gp, and tp */
    movhi hi(__stack), r0, sp
    movea lo(__stack), sp, sp

    movhi hi(__gp), r0, gp
    movea lo(__gp), gp, gp

    movhi hi(__tp), r0, tp
    movea lo(__tp), tp, tp

    /* Jump to c main */
    movhi hi(_main), r0, r1
    movea lo(_main), r1, r1
    jmp [r1]

    /* Fun stuff happens if main returns.. :D */

    .section ".vbvectors", "ax"
    .align 1

.global _rom_title

/* Rom info table (07FFFDE0h) */
_rom_title:
    .ascii "change this title   "     /* Game Title          */
    .byte 0x00,0x00,0x00,0x00,0x00    /* Reserved            */
    .ascii "MFGMID"                   /* Manufacture/Game ID */
    .byte 0x01                        /* Rom Version         */

/* Hardware Interupt Vectors */
interrupt_table:

    /* INTKEY (7FFFE00h) - Controller Interrupt */
    reti
    .fill   0x0E

    /* INTTIM (7FFFE10h) - Timer Interrupt */
    reti
    .fill   0x0E

    /* INTCRO (7FFFE20h) - Expansion Port Interrupt */
    reti
    .fill   0x0E

    /* INTCOM (7FFFE30h) - Link Port Interrupt */
    reti
    .fill   0x0E

    /* INTVPU (7FFFE40h) - Video Retrace Interrupt */
    reti
    .fill   0x0E

    /* Unused vectors (7FFFE50h-7FFFF5Fh) */
    .fill   0x010F

    /* (7FFFF60h) - Float exception */
    reti
    .fill   0x0E

    /* Unused vector */
    .fill   0x10

    /* (7FFFF80h) - Divide by zero exception */
    reti
    .fill   0x0E

    /* (7FFFF90h) - Invalid Opcode exception */
    reti
    .fill   0x0E

    /* (7FFFFA0h) - Trap 0 exception */
    reti
    .fill   0x0E

    /* (7FFFFB0h) - Trap 1 exception */
    reti
    .fill   0x0E

    /* (7FFFFC0h) - Trap Address exception */
    reti
    .fill   0x0E

    /* (7FFFFD0h) - NMI/Duplex exception */
    reti
    .fill   0x0F

    /* Unused vector */
    .fill   0x10

    /* Reset Vector (7FFFFF0h) - This is how the ROM boots */
    movhi   hi(_start), r0, r1
    movea   lo(_start), r1, r1
    jmp     [r1]
    .fill   0x06
