
    .code


    ;普通的vmcall，参数由rcx、rdx、r8和r9传递
    ShvVmCall PROC
    mov rax,40534883EC20488Dh
    vmcall
    ret
    ShvVmCall ENDP

    ;拓展的vmcall，参数由rcx、rdx、r8、r9、r10、r11、r12、r13、r14和r15传递
    ShvVmCallEx PROC
        mov rax,40534883EC20488Dh
        sub rsp, 30h
        mov qword ptr [rsp],       r10
        mov qword ptr [rsp + 8h],  r11
        mov qword ptr [rsp + 10h], r12
        mov qword ptr [rsp + 18h], r13
        mov qword ptr [rsp + 20h], r14
        mov qword ptr [rsp + 28h], r15

        mov r10, qword ptr [rsp + 58h]
        mov r11, qword ptr [rsp + 60h]
        mov r12, qword ptr [rsp + 68h]
        mov r13, qword ptr [rsp + 70h]
        mov r14, qword ptr [rsp + 78h]
        mov r15, qword ptr [rsp + 80h]

        vmcall
        mov r10, qword ptr [rsp]
        mov r11, qword ptr [rsp + 8h]
        mov r12, qword ptr [rsp + 10h]
        mov r13, qword ptr [rsp + 18h]
        mov r14, qword ptr [rsp + 20h]
        mov r15, qword ptr [rsp + 28h]
        add rsp, 30h

        ret
    ShvVmCallEx ENDP

    end


