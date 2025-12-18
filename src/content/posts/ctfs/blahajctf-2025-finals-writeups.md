---
title: BlahajCTF 2025 Finals Writeups
published: 2025-12-18
description: 'The interesting ones'
image: ''
tags: ["Ctf", "Forensics"]
category: 'CTF Writeups'
draft: false 
lang: ''
---

# forens - sleep-to-dream

_This challenge was solved in collaboration with abyts, where credit for this writeup also belongs to him._

In this challenge, we are provided a disk image, alongside a memdump. The challenge mentions something about the computer being backdoored, so lets begin by looking for _wierd and suspicious_ files and binaries.

## The sane part

Putting the disk image into autopsy reveals that the user "fiona" has a few text files containing lyrics in her home directory.

![autopsy interface](/images/ctf/blahaj_autopsy1.png)

Suspiciously, the text fiile `4 - Criminal.txt` is empty. Maybe the backdoor did something to this file?

![autopsy interface](/images/ctf/blahaj_autopsy2.png)

We also observe that there is a shell script that iterates over all the lyrics and runs `cat` on them.

![autopsy interface](/images/ctf/blahaj_autopsy3.png)

Hmm, maybe the `cat` binary has something to do with this. Let us take a deeper look into what the `cat` binary actually entails.

After extracting the `cat` binary from autopsy, we throw the binary into ghidra for further analysis. After some cursory glances, we come across this function whith this decompilation:

![ghidra interface](/images/ctf/blahaj_ghidra1.png)

```c
undefined8 initialize(char *param_1)

{
  long lVar1;
  undefined8 uVar2;
  int iVar3;
  uint __pid;
  long lVar4;
  undefined8 *puVar5;
  undefined8 *puVar6;
  undefined8 *puVar7;
  undefined8 uVar8;
  int local_6ec;
  char *local_6e8;
  undefined8 uStack_6e0;
  undefined8 local_6d8 [213];
  undefined8 local_30;
  
  uVar8 = 0;
  puVar5 = local_6d8;
  puVar6 = &DAT_00108a40;
  puVar7 = puVar5;
  for (lVar4 = 0xd5; lVar4 != 0; lVar4 = lVar4 + -1) {
    *puVar7 = *puVar6;
    puVar6 = puVar6 + 1;
    puVar7 = puVar7 + 1;
  }
  iVar3 = strcmp(param_1,`4 - Criminal.txt`);
  if (iVar3 == 0) {
    uVar8 = 0;
    puts("\n\n\n\n");
    __pid = fork();
    local_6e8 = "/usr/bin/mpd";
    uStack_6e0 = 0;
    if (__pid == 0) {
      uVar8 = 0xffffffff;
      lVar4 = ptrace(PTRACE_TRACEME,0,0,0);
      if (lVar4 != -1) {
        uVar8 = 1;
        execve("/usr/bin/mpd",&local_6e8,(char **)0x0);
      }
    }
    else {
      waitpid(__pid,&local_6ec,0);
      lVar4 = get_entry_point(__pid);
      lVar4 = lVar4 - (long)puVar5;
      do {
        uVar2 = *puVar5;
        lVar1 = lVar4 + (long)puVar5;
        puVar5 = puVar5 + 1;
        ptrace(PTRACE_POKETEXT,(ulong)__pid,lVar1,uVar2);
      } while (puVar5 != &local_30);
      ptrace(PTRACE_DETACH,(ulong)__pid,0,0);
    }
  }
  return uVar8;
}
```

Looking through the decompiled C code, it appears that the `cat` binary is attempting to inject some sort of shellcode into the `mpd` binary. The backdoor checks if the file name is `4 - Criminal.txt`, and if such, copies some shellcode from DAT_00108a40 to local_6d8.

Skipping down to the data below the DAT_00108a40 section, it appears that the shell code is doing some sort of RC4 encryption is happening with the key "fetchboltcutters". Maybe the contents of `4 - Criminal.txt` was encrypted using RC4, and that the original contents contain the flag?

![ghidra interface](/images/ctf/blahaj_ghidra2.png)

But where could the ciphertext be? As previously mentioned, `4 - Criminal.txt` appears to only consist of 128 bytes of 0x0. Maybe that is what the memdump is for? After all, the ciphertext must be stored *somewhere* in memory.

In order to interact with this memdump, we will be using Volatility 3.

## The less sane part

Using `vol -f mem.dmp banners.Banner`, we can observe that the memdump was created on a system running Debian 13, kernel version 6.12.57.

![term interface](/images/ctf/blahaj_term1.png)

After acquiring the correct volatility 3 symbols for this distribution and kernel, we can now use `vol -f mem.dmp linux.pslist | grep "mpd"` to take a look at the mpd process when this memdump was taken.

![term interface](/images/ctf/blahaj_term2.png)

From here, we can see that the process `mpd` is running with pid 764. Now, we need to figure out which area in memory is the shellcode injected too. Because the shellcode injected must be executable, we are looking for an area in memory for this process with rwx permissions. We can do this using the command `vol -f mem.dmp linux.proc.Maps --pid 764 | grep "rwx"`.

![term interface](/images/ctf/blahaj_term3.png)

Now we know that the memory area 0x564f5bc47000 to 0x564f5bc4b000 is the rwx region where the shellcoce is inejcted to. Let us extract the memory regions of the `mpd` binary using `vol -f mem.dmp linux.elfs --pid 764 --dump`.

![term interface](/images/ctf/blahaj_term4.png)

Note that only the first dump is of interest to us, as the other 329 dumps are just dumps of the libraries, of which are unrelated to the shellcode injection. Inspecting `pid.764.mpd.0x564f5bbe5000.dmp` in ghidra (yes ghidra because why not), we jump to offset 0x62000, which is the start of the rwx segment of the memory. Scrolling down, we notice a reference to the filename at 0x00163182, with some what seems to be giberrish asembly after forcing ghidra to disassemble this memory region (in a futile atttempt to locate the exact place where the ciphertext is by rev-ing the shellcode).

![ghidra interface](/images/ctf/blahaj_ghidra3.png)

Using some inutition, the ciphertext cant be _that_ far off from the file name, can it? Upon further observation, we notice this segment:

![ghidra interface](/images/ctf/blahaj_ghidra4.png)

`66 65 74 63 68 62 6f 6c 74 63 75 74 74 65 72 73`... Hmm... Sounds like "fetchboltcutters"! Could the ciphertext be located between the key and the filename? After all, it cant be assembly, since it is gibberish. Using Claude, we whip up a python script to decode the data between the key and filename:

```python
RC4_KEY = b"fetchboltcutters"

# Ciphertext bytes from Ghidra disassembly at LAB_00163103
# (Ghidra shows them as instructions but they're actually encrypted data)
CIPHERTEXT_HEX = """
2e a2 74 f7 99 0e c0 bf da 79 6c 58 00 dc 73 bc
cb 48 25 5e d1 70 a1 0c 42 e2 73 80 29 0a 23 bd
22 af 9b 2f d7 80 c3 f6 d6 ba ca f2 23 ae 71 50
a0 b9 65 82 6e d7 a8 56 63 2b 1c 4e 49 f9 df 42
8e 6e e4 29 bc 6e 8f 03 ed ff 22 c8 c3 0d f4 17
31 a0 e1 ff c8 62 80 ce 26 aa 08 2d f0 75 51 28
fd 41 41 f7 ae 89 1f 70 97 12 8b 15 ad 2c 06 82
b4 a1 b1 e1 aa 4b af 29 aa 51 b8 72 98 7f 9c
"""


def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) % 256])
    return bytes(out)


def main():
    # Parse hex bytes
    ciphertext = bytes.fromhex(CIPHERTEXT_HEX.replace('\n', '').replace(' ', ''))
    
    print(f"Ciphertext length: {len(ciphertext)} bytes")
    print(f"RC4 key: {RC4_KEY.decode()}")
    print("=" * 60)
    
    plaintext = rc4(RC4_KEY, ciphertext)
    
    print("\nDecrypted plaintext:")
    print(plaintext.decode("utf-8", errors="replace"))
    print("\n" + "=" * 60)
    
    with open("flag.txt", "wb") as f:
        f.write(plaintext)
    print("Saved to flag.txt")


if __name__ == "__main__":
    main()
```

Running the script, we get:

![term interface](/images/ctf/blahaj_term5.png)

Unfortunately, our team was unable to solve this during the ctf (despite having 2 people spend almost 4 hours on this challenge). Nontheless, this challenge was a really fun one to upsolve, and if we had a proper forensics setup with volatility with symbols set up, this could have been much less time-consuming.

# web - command runner