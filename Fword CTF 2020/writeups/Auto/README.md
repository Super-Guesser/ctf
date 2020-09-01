# Auto - 28 Solves

## Analysis
This compressed 7z file consists of more than hundreds files, there are 400 binaries in file.  
Each file in 7z compressed file internal codes just like this.  

```c
    v9 = 10 * (v5[v8 - 2] - 48) + v7;
    LODWORD(v10) = sub_10C0(v5);
    sub_10F0(v13, "./out%03d %s", (unsigned int)(v9 + v5[v10 - 1] - 48 + 1), v12 + 2);
    if ( (*v12 + 496 + v12[1]) >> 1 != 331 || *v12 + (char)(*v12 ^ v12[1]) != 92 || *v12 * v12[1] != 6880 )
    {
      sub_10B0("NOOOOOOOOOOOOOOOOOOOO");
      result = 0;
    }
    else
    {
      LODWORD(v11) = sub_10C0(v12);
```

sub_10F0 is just for sprintf function, this code generates the name of next file of this current executed binary, and there is almost same codes in 400 binaries.  
Thus, if we can extract the calculated variables of each files, such as 406. 1. 331. 02. 6880 based on above code snippets.  
We can calculate the password key which used for executing next corrected binaries without angr framework.  

For solve these equations, i just use the SMT Solver library like 'z3'. I extracted values for these equations from all binaries.  

```python
import struct
from z3 import *

u32 = lambda x: struct.unpack("<L", x)[0]
u8 = lambda x: struct.unpack("<B", x)[0]

def parse_from_file(filename):
    with open(filename, "rb") as f:
        buf = f.read()
        start_index = buf.find("\xe8\xfd\xfd\xff\xff\xc7\x45") + 8
        addition_value = u32(buf[start_index:start_index+4])
        next_index = start_index + 37
        shift_value = u8(buf[next_index:next_index+1])
        next_index = next_index + 2
        cmp_value = u32(buf[next_index:next_index+4])
        next_index = next_index + 46
        cmp_value_2 = u32(buf[next_index:next_index+4])
        next_index = next_index + 38
        cmp_value_3 = u32(buf[next_index:next_index+4])

    print("addition : %x, shift : %x, cmp : %x, %x, %x" % (addition_value, shift_value, cmp_value, cmp_value_2, cmp_value_3))
    x = BitVec('x', 32)
    y = BitVec('y', 32)
    s = Solver()
    s.add(((x + addition_value + y) >> shift_value) == cmp_value)
    s.add(((x + (x ^ y)) & 0xff) == cmp_value_2)
    s.add((x * y) == cmp_value_3)
    s.add(x >= 0x30)
    s.add(x <= 0x122)
    s.add(y >= 0x30)
    s.add(y <= 0x122)
    s.check()
    m = s.model()
    return chr(m[x].as_long()) + chr(m[y].as_long())

result = ""
for i in range(0, 400):
    filename = "./out{0:03d}".format(i)
    result_ = parse_from_file(filename)
    print("%s => %s" % (filename, result_))
    result += result_
print(result)
```

Flag : FwordCTF{4r3_Y0u_4_r0b0t}