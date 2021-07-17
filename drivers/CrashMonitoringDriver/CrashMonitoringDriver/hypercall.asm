PUBLIC kAFL_Hypercall
.code _text
 
kAFL_Hypercall PROC PUBLIC

mov rax, 23h
mov rbx, rcx
mov rcx, rdx
vmcall

ret
kAFL_Hypercall ENDP
 
 
END        