.data

CONFIG STRUCT

    JumpAddress                     DQ 1
    ReturnAddress                   DQ 1
    Nargs                           DQ 1
    Arg01                           DQ 1
    Arg02                           DQ 1
    Arg03                           DQ 1
    Arg04                           DQ 1
    Arg05                           DQ 1
    Arg06                           DQ 1
    Arg07                           DQ 1
    Arg08                           DQ 1
    Arg09                           DQ 1
    Arg10                           DQ 1
    Arg11                           DQ 1
    SysId                           DD 0

CONFIG ENDS

.code

run_indirect_syscall proc

    mov		[rsp+08h], rbp
	mov		[rsp+10h], rbx
	mov		rbp, rsp
    add     rsp, 58h
    push    [rcx].CONFIG.ReturnAddress

	cmp		[rcx].CONFIG.Nargs, 11
	je		handle_eleven
	cmp		[rcx].CONFIG.Nargs, 10
	je		handle_ten
	cmp		[rcx].CONFIG.Nargs, 9
	je		handle_nine
	cmp		[rcx].CONFIG.Nargs, 8
	je		handle_eight
	cmp		[rcx].CONFIG.Nargs, 7
	je		handle_seven
	cmp		[rcx].CONFIG.Nargs, 6
	je		handle_six
	cmp		[rcx].CONFIG.Nargs, 5
	je		handle_five
	cmp		[rcx].CONFIG.Nargs, 4
	je		handle_four
	cmp		[rcx].CONFIG.Nargs, 3
	je		handle_three
	cmp		[rcx].CONFIG.Nargs, 2
	je		handle_two
	cmp		[rcx].CONFIG.Nargs, 1
	je		execute_syscall
	cmp		[rcx].CONFIG.Nargs, 0
	je		execute_syscall
run_indirect_syscall endp

restore proc
	mov		rsp, rbp
	mov		rbp, [rsp+08h]
	mov		rbx, [rsp+10h]
	ret
restore endp

handle_eleven proc
	push	r15
	mov		r15, [rcx].CONFIG.Arg11
	mov		[rsp+60h], r15
	pop		r15
	jmp		handle_ten
handle_eleven endp
handle_ten proc
	push	r15
	mov		r15, [rcx].CONFIG.Arg10
	mov		[rsp+58h], r15
	pop		r15
	jmp		handle_nine
handle_ten endp
handle_nine proc
	push	r15
	mov		r15, [rcx].CONFIG.Arg09
	mov		[rsp+50h], r15
	pop		r15
	jmp		handle_eight
handle_nine endp
handle_eight proc
	push	r15
	mov		r15, [rcx].CONFIG.Arg08
	mov		[rsp+48h], r15
	pop		r15
	jmp		handle_seven
handle_eight endp
handle_seven proc
	push	r15
	mov		r15, [rcx].CONFIG.Arg07
	mov		[rsp+40h], r15
	pop		r15
	jmp		handle_six
handle_seven endp
handle_six proc
	push	r15
	mov		r15, [rcx].CONFIG.Arg06
	mov		[rsp+38h], r15
	pop		r15
	jmp		handle_five
handle_six endp
handle_five proc
	push	r15
	mov		r15, [rcx].CONFIG.Arg05
	mov		[rsp+30h], r15
	pop		r15
	jmp		handle_four
handle_five endp
handle_four proc
	mov		r9, [rcx].CONFIG.Arg04
	jmp		handle_three
handle_four endp
handle_three proc
	mov		r8, [rcx].CONFIG.Arg03
	jmp		handle_two
handle_three endp
handle_two proc
	mov		rdx, [rcx].CONFIG.Arg02
	jmp		execute_syscall
handle_two endp

execute_syscall proc
	mov 	r10, [rcx].CONFIG.Arg01
    mov		r11, [rcx].CONFIG.JumpAddress
	mov 	eax, [rcx].CONFIG.SysId
	mov 	rcx, [rcx].CONFIG.Arg01
	jmp 	qword ptr r11
execute_syscall endp

end