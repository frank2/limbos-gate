section .data
limbo_callback:
   dd 0

limbo_syscall:
   dd 0

section .text
[BITS 32]

   ; I really hate msvc function decoration even in C, fucking lol
global @limbo_hell@4
@limbo_hell@4:
   mov [limbo_callback], ecx
   ret

global @limbos_gate@4
@limbos_gate@4:
   mov [limbo_syscall], ecx
   ret

global _limbo_descent
_limbo_descent:
   mov eax, [limbo_syscall]
   mov edx, [limbo_callback]
   call edx
   ret
