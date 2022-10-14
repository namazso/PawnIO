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

	pop rdi
	pop rsi
	pop rbx

	setb al
	movzx eax, al

	ret
_dell ENDP

_crdr PROC
	lea rax, begin
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