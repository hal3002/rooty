
section.text

global _start
_start:
	pushfq
	push rax
	push rsi
	push rdi
	push rbx
	push rcx
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15

	xor rax,rax
	mov rax,57
	xor rdi,rdi
	syscall
	
	test rax,rax
	je child

	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rcx
	pop rbx
	pop rdi
	pop rsi
	pop rax
	popfq

	sub rsp,8
	mov dword [rsp+4],0x41424344
	mov dword [rsp],0x45464748
	ret
child:
	nop
	nop
	nop
	nop
