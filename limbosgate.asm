section .data
limbo_callback:
   dd 0

limbo_syscall:
   dd 0

section .text
[BITS 32]

global limbo_hell
limbo_hell:
   mov [limbo_callback], ecx
   ret

global limbos_gate
limbos_gate:
   mov [limbo_syscall], ecx
   ret

global limbo_descent
limbo_descent:
   mov eax, [limbo_syscall]
   mov edx, [limbo_callback]
   call edx
   ret
