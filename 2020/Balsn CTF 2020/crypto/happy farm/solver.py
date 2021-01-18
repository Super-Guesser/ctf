from pwn import *
from Crypto.Util.number import *

context.log_level = 'DEBUG'

r = remote('happy-farm.balsnctf.com', 4001)
# r = process(['python3', './chal.py'])

def get_onion():
    s = ''
    for _ in range(22):
        s += r.recvuntil('\n').decode()
    s = s.replace(' ', '').replace('\n', '').replace('x', '')
    return bytearray.fromhex(s)

def get_eaten_onion():
    s = ''
    for _ in range(22):
        s += r.recvuntil('\n').decode()
    s = s.replace(' ', '').replace('\n', '').replace('x', '')
    s = s[:173] + '0' + s[173:173+8]
    return bytearray.fromhex(s)

# Level 1
r.recvuntil('My seed:\n')
seed = get_onion()
r.recvuntil('My start date: ')
date = bytearray.fromhex(r.recv(32).decode())

seed[0] ^= 1
date[0] ^= 1
r.recvuntil('start date: ')
r.sendline(date.hex())
r.recvuntil('seed: ')
r.sendline(seed.hex())
r.recvuntil('layer: ')
r.sendline('1')

r.recvuntil('Your onion\n')
seed = get_onion()
print(seed)

date = seed[-16:]
r.recvuntil('start date: ')
r.sendline(date.hex())
r.recvuntil('seed: ')
r.sendline(seed.hex())
r.recvuntil('layer: ')
r.sendline('8999')

r.recvuntil('Your onion\n')
output = get_onion()

r.recvuntil('How would my onion looks like? ')
r.sendline(output.hex())

# Level 2
r.recvuntil('My seed is\n')
seed = get_onion()

n1 = 2 ** (1023 * 3) - bytes_to_long(seed)

r.recvuntil("layer: ")
r.sendline('8999')
r.recvuntil("your onion\n")
onion1 = get_onion()

n2 = bytes_to_long(onion1)
for _ in range(8998):
    n2 = pow(n2, 3, n1)

n = GCD(n2 - 2 ** 1023, n1)

r.recvuntil('seed: ')
r.sendline(onion1.hex())
r.recvuntil('layer: ')
r.sendline('1')
r.recvuntil('Here you go\n')
onion2 = get_eaten_onion()

# f = (x + ((onion2 + (i << 32)) << 296)) ^ 3 - onion1

sage = process(['sage', './solver.sage', str(n), onion1.hex(), onion2.hex()])
onion2 = long_to_bytes(int(sage.recvline().decode().strip()))

r.recvuntil('How would my onion looks like? ')
r.sendline(onion2.hex())

# Level 3
for _ in range(4):
    r.recvuntil('layer: ')
    r.sendline(str(9000 ** 3 % 192))
    r.recvuntil('your onion\n')
    output = get_onion()

r.recvuntil('How would my onion looks like? ')
r.sendline(output.hex())

r.interactive()
