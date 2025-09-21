; PawnIO - Input-output driver
; Copyright (C) 2023  namazso <admin@namazso.eu>
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