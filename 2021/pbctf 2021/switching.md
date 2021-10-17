# switching
We can disassemble this pyc with python 3.10.
```python
import dis
import marshal

with open('challenge.cpython-310.pyc', 'rb') as f:
    f.seek(16)
    code = marshal.load(f)
```

Sorry to author, but I didn't fully analyzed this because of lazyness.
```
BBB = bytes(e ^ 1337 for e in (1385, 1403, 1402, 1389, 1407))
BBBBBB = hashlib.md5
l = input("flag? ")
BBBB = lambda x: hashlib.md5(x).hexdigest()
BBBBB = list(l)
BB = {}
BBBBBBB = -1

while BBBBB:
	t = BBBBB.pop(0)
	if not (isinstance(t, list) and len(t) >= 7):
		break
	...?
	if x == 1:
		if BBBB(BBB * x)[x] == y:
			BB[x] = y
if len(BB) == 0:
	correct
```
B is blank character. BB should empty so we can try guessing for this.
```
for i in range(n):
	if hashlib.md5(b"PBCTF" * i).hexdigest()[i] != flag[i]:
		wrong
correct
```
and solver for this is,
```python
v = b"PBCTF"
flag = "pbctf{"

import hashlib
for i in range(32):
    flag += hashlib.md5(v * i).hexdigest()[i]

print(flag + "}")
```
`pbctf{dece0227383ca2ac793545ee989ce386}`

