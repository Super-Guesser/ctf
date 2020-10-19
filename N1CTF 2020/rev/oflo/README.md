## oflo

There are several anit-reversing logic, so I just patched with `\x90` (nop instruction) to avoid them. After this process, it was able to figure out the logic of the program.

1. Use `/bin/cat` to something to get a string
2. XOR the prologue of a function by the first 5 bytes of the given input.
3. XOR the given input and the string from 1., then check the result is right.

The part 2. is easy to patch, because the first 5 bytes of the given input is always `n1ctf`. 

Then, I found out that 1. give us the string starts with `Linux version` with gdb. so it was able to get flag like this:

```
>>> arr
[53, 45, 17, 26, 73, 125, 17, 20, 43, 59, 62, 61, 60, 95]
>>> arr2
[76, 105, 110, 117, 120, 32, 118, 101, 114, 115, 105, 111, 110, 32]
>>> s = ''
>>> for i in range(len(arr)):
...     s += chr(arr[i] ^ (arr2[i] + 2))
...
>>> s
'{Fam3_is_NULL}'
```