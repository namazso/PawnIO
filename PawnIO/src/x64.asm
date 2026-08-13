; PawnIO - Input-output driver
; Copyright (C) 2026  namazso <admin@namazso.eu>
; 
; This program is free software; you can redistribute it and/or modify
; it under the terms of the GNU General Public License as published by
; the Free Software Foundation; either version 2 of the License, or
; (at your option) any later version.
; 
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.
; 
; You should have received a copy of the GNU General Public License along
; with this program; if not, write to the Free Software Foundation, Inc.,
; 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
; 
; Linking PawnIO statically or dynamically with other modules is making a
; combined work based on PawnIO. Thus, the terms and conditions of the GNU
; General Public License cover the whole combination.
; 
; In addition, as a special exception, the copyright holders of PawnIO give
; you permission to combine PawnIO program with free software programs or
; libraries that are released under the GNU LGPL and with independent modules
; that communicate with PawnIO solely through the device IO control
; interface. You may copy and distribute such a system following the terms of
; the GNU GPL for PawnIO and the licenses of the other code concerned,
; provided that you include the source code of that other code when and as
; the GNU GPL requires distribution of source code.
; 
; Note that this exception does not include programs that communicate with
; PawnIO over the Pawn interface. This means that all modules loaded into
; PawnIO must be compatible with this licence, including the earlier
; exception clause. We recommend using the GNU Lesser General Public License
; version 2.1 to fulfill this requirement.
; 
; For alternative licensing options, please contact the copyright holder at
; admin@namazso.eu.
; 
; Note that people who make modified versions of PawnIO are not obligated to
; grant this special exception for their modified versions; it is their
; choice whether to do so. The GNU General Public License gives permission
; to release a modified version without this exception; this exception also
; makes it possible to release a modified version which carries forward this
; exception.

.code

PUBLIC _smi

getflags PROC FRAME
    pushfq
    .pushreg rax
    .endprolog
    .beginepilog
    pop rax
    ret
getflags ENDP

setflags PROC FRAME
    push rcx
    .allocstack 8
    .endprolog
    popfq
    ret
setflags ENDP

_smi PROC FRAME
    push rbx
    .pushreg rbx
    push rbp
    .pushreg rbp
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp, 58h
    .allocstack 58h
    .endprolog

    mov [rsp+28h], rcx
    mov [rsp+30h], rdx
    mov [rsp+38h], r8

    call getflags
    and rax, qword ptr [rsp+30h]
    or rax, qword ptr [rsp+38h]
    mov rcx, rax
    call setflags

    mov r12, qword ptr [rsp+28h]
    mov rax, [r12]
    mov rcx, [r12+8]
    mov rdx, [r12+10h]
    mov rbx, [r12+18h]
    mov rbp, [r12+28h]
    mov rsi, [r12+30h]
    mov rdi, [r12+38h]
    mov r8, [r12+40h]
    mov r9, [r12+48h]
    mov r10, [r12+50h]
    mov r11, [r12+58h]
    mov r13, [r12+68h]
    mov r14, [r12+70h]
    mov r15, [r12+78h]
    mov r12, [r12+60h]

    out 0b2h, al
    out 0ebh, al
    out 0ebh, al

    mov [rsp+40h], r12
    mov r12, qword ptr [rsp+28h]
    mov [r12], rax
    mov [r12+8], rcx
    mov [r12+10h], rdx
    mov [r12+18h], rbx
    mov [r12+28h], rbp
    mov [r12+30h], rsi
    mov [r12+38h], rdi
    mov [r12+40h], r8
    mov [r12+48h], r9
    mov [r12+50h], r10
    mov [r12+58h], r11
    mov rax, qword ptr [rsp+40h]
    mov [r12+60h], rax
    mov [r12+68h], r13
    mov [r12+70h], r14
    mov [r12+78h], r15

    call getflags
    add rsp, 58h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret
_smi ENDP

PUBLIC _dell

_dell PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    .endprolog

    mov r8, rcx

    mov eax, [r8]
    mov ecx, [r8+4]
    mov edx, [r8+8]
    mov ebx, [r8+12]
    mov esi, [r8+16]
    mov edi, [r8+20]

    out 0b2h, al
    out 084h, al

    mov [r8], eax
    mov [r8+4], ecx
    mov [r8+8], edx
    mov [r8+12], ebx
    mov [r8+16], esi
    mov [r8+20], edi

    setb al
    movzx eax, al

    pop rdi
    pop rsi
    pop rbx

    ret
_dell ENDP

_crdr PROC
    lea rax, begin
    and rcx, 1f8h
    add rax, rcx
    jmp rax
ALIGN 8
begin:
    ; mov rax, dr[0-7]
    DB 0fh, 21h, 0c0h
    ret
    ALIGN 8
    DB 0fh, 21h, 0c8h
    ret
    ALIGN 8
    DB 0fh, 21h, 0d0h
    ret
    ALIGN 8
    DB 0fh, 21h, 0d8h
    ret
    ALIGN 8
    DB 0fh, 21h, 0e0h
    ret
    ALIGN 8
    DB 0fh, 21h, 0e8h
    ret
    ALIGN 8
    DB 0fh, 21h, 0f0h
    ret
    ALIGN 8
    DB 0fh, 21h, 0f8h
    ret
    ALIGN 8
    
    ; mov rax, dr[8-15]
    DB 44h, 0fh, 21h, 0c0h
    ret
    ALIGN 8
    DB 44h, 0fh, 21h, 0c8h
    ret
    ALIGN 8
    DB 44h, 0fh, 21h, 0d0h
    ret
    ALIGN 8
    DB 44h, 0fh, 21h, 0d8h
    ret
    ALIGN 8
    DB 44h, 0fh, 21h, 0e0h
    ret
    ALIGN 8
    DB 44h, 0fh, 21h, 0e8h
    ret
    ALIGN 8
    DB 44h, 0fh, 21h, 0f0h
    ret
    ALIGN 8
    DB 44h, 0fh, 21h, 0f8h
    ret
    ALIGN 8
    
    ; mov rax, cr[0-7]
    DB 0fh, 20h, 0c0h
    ret
    ALIGN 8
    DB 0fh, 20h, 0c8h
    ret
    ALIGN 8
    DB 0fh, 20h, 0d0h
    ret
    ALIGN 8
    DB 0fh, 20h, 0d8h
    ret
    ALIGN 8
    DB 0fh, 20h, 0e0h
    ret
    ALIGN 8
    DB 0fh, 20h, 0e8h
    ret
    ALIGN 8
    DB 0fh, 20h, 0f0h
    ret
    ALIGN 8
    DB 0fh, 20h, 0f8h
    ret
    ALIGN 8
    
    ; mov rax, cr[8-15]
    DB 44h, 0fh, 20h, 0c0h
    ret
    ALIGN 8
    DB 44h, 0fh, 20h, 0c8h
    ret
    ALIGN 8
    DB 44h, 0fh, 20h, 0d0h
    ret
    ALIGN 8
    DB 44h, 0fh, 20h, 0d8h
    ret
    ALIGN 8
    DB 44h, 0fh, 20h, 0e0h
    ret
    ALIGN 8
    DB 44h, 0fh, 20h, 0e8h
    ret
    ALIGN 8
    DB 44h, 0fh, 20h, 0f0h
    ret
    ALIGN 8
    DB 44h, 0fh, 20h, 0f8h
    ret
    ALIGN 8
    
    ; mov dr[0-7], rdx
    DB 0fh, 23h, 0c2h
    ret
    ALIGN 8
    DB 0fh, 23h, 0cah
    ret
    ALIGN 8
    DB 0fh, 23h, 0d2h
    ret
    ALIGN 8
    DB 0fh, 23h, 0dah
    ret
    ALIGN 8
    DB 0fh, 23h, 0e2h
    ret
    ALIGN 8
    DB 0fh, 23h, 0eah
    ret
    ALIGN 8
    DB 0fh, 23h, 0f2h
    ret
    ALIGN 8
    DB 0fh, 23h, 0fah
    ret
    ALIGN 8
    
    ; mov dr[8-15], rdx
    DB 44h, 0fh, 23h, 0c2h
    ret
    ALIGN 8
    DB 44h, 0fh, 23h, 0cah
    ret
    ALIGN 8
    DB 44h, 0fh, 23h, 0d2h
    ret
    ALIGN 8
    DB 44h, 0fh, 23h, 0dah
    ret
    ALIGN 8
    DB 44h, 0fh, 23h, 0e2h
    ret
    ALIGN 8
    DB 44h, 0fh, 23h, 0eah
    ret
    ALIGN 8
    DB 44h, 0fh, 23h, 0f2h
    ret
    ALIGN 8
    DB 44h, 0fh, 23h, 0fah
    ret
    ALIGN 8
    
    ; mov cr[0-7], rdx
    DB 0fh, 22h, 0c2h
    ret
    ALIGN 8
    DB 0fh, 22h, 0cah
    ret
    ALIGN 8
    DB 0fh, 22h, 0d2h
    ret
    ALIGN 8
    DB 0fh, 22h, 0dah
    ret
    ALIGN 8
    DB 0fh, 22h, 0e2h
    ret
    ALIGN 8
    DB 0fh, 22h, 0eah
    ret
    ALIGN 8
    DB 0fh, 22h, 0f2h
    ret
    ALIGN 8
    DB 0fh, 22h, 0fah
    ret
    ALIGN 8
    
    ; mov cr[8-15], rdx
    DB 44h, 0fh, 22h, 0c2h
    ret
    ALIGN 8
    DB 44h, 0fh, 22h, 0cah
    ret
    ALIGN 8
    DB 44h, 0fh, 22h, 0d2h
    ret
    ALIGN 8
    DB 44h, 0fh, 22h, 0dah
    ret
    ALIGN 8
    DB 44h, 0fh, 22h, 0e2h
    ret
    ALIGN 8
    DB 44h, 0fh, 22h, 0eah
    ret
    ALIGN 8
    DB 44h, 0fh, 22h, 0f2h
    ret
    ALIGN 8
    DB 44h, 0fh, 22h, 0fah
    ret
    ALIGN 8
_crdr ENDP

END