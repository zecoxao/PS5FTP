# Coded by John Törnblom + SiSTRo
.intel_syntax noprefix

.extern ptr_syscall

.global f_syscall
.type f_syscall @function

f_syscall:
  mov rax, rdi
  mov rdi, rsi
  mov rsi, rdx
  mov rdx, rcx
  mov r10, r8
  mov r8,  r9
  mov r9,  qword ptr [rsp + 8]
  jmp qword ptr [rip + ptr_syscall]
  ret