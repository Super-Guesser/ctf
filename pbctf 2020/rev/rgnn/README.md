# Challenge

* **Points**: 255
* **Solves**: 20
* **Files**: [binary](https://storage.googleapis.com/pbctf-2020-ctfd/ad7d6173353d0b33478b91b450a02bd4/binary)

```
Reversing, Great. Nunnu Nanna

By: rbtree
```

# Solution

Once run without arguments, binary writes the following message:

```
How to use: ./binary <input>
```

Reversed binary content is quite easy to read, though, it wasn't so easy to understand what it does. In `sub_90A()`, it is clear that the given argument `<input>` is actually a filename of a file containing 50 lines by 50 characters, where each character must be one of `0123`:

```c
    ...
    fd = open(file, 0);
    if ( fd >= 0 )
    {
      for ( i = 0; i <= 49; ++i )
      {
        for ( j = 0; j <= 49; ++j )
        {
          if ( read(fd, &buf, 1uLL) != 1 || buf <= 47 || buf > 51 )
            return __readfsqword(0x28u) ^ v5;
          byte_203FA0[50 * i + j] = buf - 48;
        }
        if ( read(fd, &buf, 1uLL) != 1 )
          return __readfsqword(0x28u) ^ v5;
      }
      close(fd);
    }
    ...
```

After one of our members throughly analysed functions `sub_A41()` and `sub_C42()`, which clearly check the chars of a given file, horizontally by lines and vertically by columns, with "condensed" table content(s) located at `unk_202040` and `unk_202FE0`, he concluded that this must be a ["multicolor nonogram"](https://en.grandgames.net/nonograms/color), where each input digit (i.e. one of `0123`) actually represents one of possible colors for the solution.

```c
__int64 sub_A41()
{
  __int64 result; // rax
  signed int i; // [rsp+0h] [rbp-10h]
  signed int j; // [rsp+4h] [rbp-Ch]
  signed int v3; // [rsp+8h] [rbp-8h]
  signed int v4; // [rsp+Ch] [rbp-4h]

  result = (unsigned __int8)byte_202020;
  if ( byte_202020 != -1 )
  {
    for ( i = 0; i <= 49; ++i )
    {
      v3 = 0;
      for ( j = 0; j <= 39; ++j )
      {
        result = *((unsigned __int8 *)&unk_202040 + 2 * (j + 40LL * i));
        if ( (_BYTE)result == 5 )
          break;
        while ( v3 <= 49 )
        {
          result = (unsigned __int8)byte_203FA0[50 * i + v3];
          if ( (_BYTE)result )
            break;
          ++v3;
        }
        if ( v3 == 50
          || (result = *((unsigned __int8 *)&unk_202040 + 2 * (j + 40LL * i)), byte_203FA0[50 * i + v3] != (_BYTE)result) )
        {
          byte_202020 = 0;
          return result;
        }
        v4 = v3;
        while ( v3 <= 49 && byte_203FA0[50 * i + v3] == *((_BYTE *)&unk_202040 + 2 * (j + 40LL * i)) )
          ++v3;
        result = (unsigned int)byte_202041[2 * (j + 40LL * i)];
        if ( v3 - v4 != (_DWORD)result )
        {
          byte_202020 = 0;
          return result;
        }
      }
    }
  }
  return result;
}
```

So, in this case, program expects us to give a solution to the puzzle, which it checks against the embedded nonogram data, where `sub_A41()` is used for checking if the given solution is correct going through all rows, while `sub_C42()` is used for checking of all columns.

To solve this puzzle, we decided to use [pynogram](https://pypi.org/project/pynogram/), as it also supports the multicolor nonograms. We prepared the "board" input file (`nonogram.txt`) as follows (Note: arbitrary characters `abcd` were used instead of `0123` for color definitions, as `pynogram` expects non-digit color names):

```
[colors]
a = (a) a
b = (b) b
c = (c) c
d = (d) d

[clues]
columns =
	2a 2a 1c 1b 2a 1b 1c 3a 1b 1a 1c 1b 1a 2b 1c 2a 4b 1c 3a 1c 6a 1b 1c 2a 1b 1c
	5a 1c 2b 1c 1b 1c 1a 1a 1c 4b 2c 1a 3b 1c 1b 6a 2c 5a 4b 1b
	2a 3b 1a 2b 1a 1b 2a 1b 1c 1b 1a 1c 4a 1b 1c 1a 1b 3c 1a 2b 8a 1c 1b
	1a 1c 2a 1b 2c 1a 1c 1b 2c 1b 1a 2b 1c 1b 2c 1b 3a 1b 2a 3b 3c 1a 5a 1a 1b 1a 1b 2a
	1c 1b 1c 1a 1c 1b 2c 2c 1b 4c 1b 1b 2a 1a 1c 1b 3c 3a 1c 1a 2b 1c 1a 1b 1a 1b 3a 1b 1a
	4a 4b 1c 2a 1c 1b 1c 6a 1b 1c 1b 1c 2a 1c 2a 1a 1b 4c 3a 1c 1b 1c
	4a 1b 1a 1c 1b 3a 2c 1b 1a 1a 3c 2a 1b 5c 1c 1a 1c 2a 1c 2a 1c 1b 1b 1c 1b 1c
	1a 1b 1b 1c 1b 1a 1c 2a 3c 1b 1a 1b 4c 1a 1a 1b 1c 1b 2c 1a 1c 2b 1b 1a 1b 1c 1a 1b 1c 2b 1c
	2a 2b 1c 1c 1a 2b 2c 1c 2b 2a 1b 2c 1b 2a 1b 1a 1b 1a 2b 2b 3c 2b 3c 1b 1c 1a 1b 1c
	1b 2a 2b 3a 1b 1a 3c 2a 1b 2c 1c 1a 1c 1b 2b 5a 1b 1c 1b 1a 2c 3c 1a 1b
	1b 3a 1a 1c 1b 2c 1b 2c 2a 3b 1a 1b 1a 1b 1c 1a 1b 3a 1c 1a 2b 1c 2a 2b 1c 1a 1c 2c
	2b 1a 2b 2b 3c 2b 2a 1a 1b 3a 1c 1b 2b 4b 1c 1c 2b 1a 2b 1b 4a 1c
	2b 1a 1c 1b 1a 2b 1a 1c 1a 1c 1b 1a 1c 1b 1a 1c 1a 2b 2b 1a 3c 1b 1a 1c 2b 1b 1a 1c 1a 5a
	1c 1a 2b 1a 1b 1b 1c 1a 1b 1a 1b 1c 1a 1c 2b 2a 2c 1b 2c 4a 1b 1a 1c 2b 1a 1a 2c 2b 1b
	3a 1c 1b 2c 1a 1a 2c 1a 1b 1a 1b 1a 1b 3a 1b 1c 3a 1b 1a 1b 2a 5c 1b 2c 1c 1a
	1a 2b 3c 1b 1a 4b 1b 1c 1b 1a 2b 1a 1a 1b 1c 1a 1b 2a 3b 2a 1a 2b 3a 2c 1a 3c 2b 1c
	1b 1c 2a 1c 1b 1a 1a 6a 1a 3c 1b 2b 2a 1b 1a 1b 4a 1c 1b 1a 1c 5a 2c
	1a 1b 1a 3a 2c 1a 2b 1a 1b 1b 5a 2b 2c 3a 1c 1a 1b 2c 4a 1c 3a 1a 1c
	2a 1b 1b 1c 1a 1b 1c 2c 1b 7a 1c 2b 2c 1b 1a 2b 3a 1c 2a 1b 2a 1c 1b 2c 1b 1c 1c
	1a 1b 1c 2a 1c 1a 1b 1a 1b 1c 1c 2b 1c 1a 1b 2a 3b 1c 1b 1c 2b 2c 1a 1b 1c 3b 1a 1b 1b 1a 2c 1b 2a
	1a 1c 5a 1c 1a 1b 1c 1b 1c 2a 4b 1a 3b 1a 1c 1a 1b 2a 1c 1a 1c 1b 1a 3b 1c 1b
	4c 2a 1b 4c 1b 2b 1c 3a 1b 1c 1b 2a 1c 1a 1b 1b 3a 1c 1b 3a 1c 1b 1a 3b 1a 1b
	1c 1a 1c 2b 1a 1b 1b 1c 3a 1c 3a 1a 1b 1c 1a 1a 1b 1a 1b 2a 1c 1a 1c 2c 1b 2a 3c 1a 1a
	1c 1b 1a 2c 1a 1a 1b 3a 4b 3a 1b 1a 1b 1a 2b 1a 2c 2a 1b 1a 1b 1c 1c 1b 1b 3c 3a
	2a 1b 1c 1a 2c 3a 1b 3a 3b 1b 6a 1b 1a 2b 1a 1b 1a 1c 2a 2c 3c 1c 1a 2b
	1c 1a 2b 1a 1b 2a 1c 1b 1c 3a 1c 3a 1a 1b 2c 1a 1b 1b 3a 1c 2a 1c 3b 2c 1a 1c 1a 5c
	1c 1a 2c 1c 5a 1c 1a 1c 3b 1a 1c 1a 1b 1a 1c 1a 2b 1a 1b 1a 1a 4b 1c 4a 1c 1b 1a 1c 1a
	1c 2b 1c 2a 3b 1a 1c 1b 1c 1c 2a 1c 1b 1c 2c 3a 1c 1b 3b 3c 1b 2a 1c 2a 1b
	7a 1b 2a 2b 3c 1b 2a 1c 1a 1c 1b 3c 1a 1c 2a 1b 3b 4a 1c 1a 3c 3b
	1b 1c 4a 1b 2c 3c 1a 2b 2a 1c 3b 1b 2a 2b 2a 1b 2b 1a 1c 1b 2a 4a
	1c 3a 1b 1a 2c 1a 4b 2a 1b 1c 2b 1b 2c 1a 1b 2c 1b 1a 2c 1a 1c 1a 1c 1c 1a
	1a 1a 1c 1b 1c 1b 2c 1a 2c 2a 4b 2a 2b 3c 2a 1c 2a 3b 2c 1a 2b 1a 2b
	1a 1b 1a 1b 1a 1c 1b 1c 1c 2a 2c 1b 2a 2c 1a 1c 2b 2c 5a 2c 1a 1b 1b 2c 2b 1b 1c
	1a 3c 1a 1c 2b 2c 2a 1b 1a 1b 1a 2c 1b 1a 1b 1a 1b 1a 1a 1b 2a 3c 2c 2b 2c 1a 1b 1c 1a 1c
	2a 1c 1a 1b 1c 1b 2c 2a 1c 1b 1a 1b 3a 3a 1c 1b 1a 1c 1b 1a 1b 1a 1c 1b 1c 4b 1c 1b 1c 3a 1c
	3a 1b 2a 1b 1c 4a 3b 1a 1c 1b 2a 1c 3b 1a 1b 2c 2b 1c 1b 1a 1b 2c 1a 1c 1b 1a 1b 2a
	2c 1b 1a 1b 2a 3c 1a 1c 1a 1b 2c 1a 1c 5b 1c 2a 1c 1a 1c 1b 2c 5a
	2c 7a 2c 1b 1a 2b 1c 1a 1b 1c 2a 1c 2b 1a 3b 3c 1b 4a 2c 1a
	2c 3a 2a 1c 1c 1a 1a 2c 2a 2c 1a 2c 1a 1b 2c 1b 1a 1c 1b 1a 3c 1a 3a 2c 2b 1a
	1c 1c 1b 1a 2b 2b 2c 3a 3b 1c 1a 2b 1a 3c 1c 1b 1a 2c 3a 1c 1a 2b 2a 2b 1a
	1c 1a 1b 2a 1b 3a 1c 1b 3a 1c 1b 1a 2b 1a 3c 1c 1b 1c 1b 3a 3c 2a 1a 1b 2c 1b 1c
	1b 1c 1b 1c 3c 3b 1a 1c 1b 2c 2b 2a 5c 3c 1b 1a 3b 1a 1b 2a 1c 1b 1c 2b 1a
	1b 2c 2a 1b 2b 4b 1a 2b 3a 2b 2a 5c 2a 1a 1b 1a 1c 1a 1a 1c 2a
	2a 2c 1a 1b 1a 4b 1c 2b 2c 3a 1b 3a 1c 1a 2b 1c 3a 1b 1c 1a 1b 3a 3c 1a 1b 1c
	2a 1c 1a 3b 2b 3a 1b 1b 6a 1b 2a 1c 1b 2b 2b 1c 2a 1b 1a 2b 3c 1b 1a
	2a 1b 2c 2b 2a 4c 1c 1b 1c 2a 2c 3c 4b 3a 1b 1a 1b 4c 1c 1b 2a 1b
	3a 2a 1b 2c 1a 1a 3c 2b 2c 1c 1b 1c 1c 1b 2a 1b 1a 2b 1a 1c 1a 3c 1b 2a 1b
	4a 1c 2a 2b 5a 3c 2c 1b 5c 1b 5b 1a 2c 1b 2c 2c 1c 1b 1c
	1a 1b 2c 1a 1c 2b 2a 2a 1b 1a 2c 1b 1c 2c 1a 1c 3b 1a 2b 1c 1c 1a 1c 1a 1c 1b 1c 1b
	1a 1a 1b 2a 2b 1c 2b 2a 1c 1a 3b 3b 1c 1b 1c 1b 1c 3a 2c 1b 1c 5a 2c 1b 3c

rows =
	4a 1c 4a 4b 2a 1b 1a 2a 1c 1a 3c 1a 1b 4a 5c 2b 2a 4a
	3a 1c 1b 2a 1b 3a 2b 1c 1a 1b 1b 1a 4c 3a 1b 1a 1c 1a 1c 2a 3c 1a 2c 5a 1b
	1a 1a 1c 2a 1b 6a 1b 1c 2a 1b 1c 1a 3b 1c 1b 2a 2c 1a 1b 1a 1c 3c 3a 1a
	2a 1b 4a 3b 1a 1b 1c 1b 2c 1a 1b 1c 1c 1a 1c 1b 1c 2a 1c 1b 1c 1a 1b 3a 2b 1c 1a 1b 1a 1c 1b
	2a 2b 2b 1c 1b 3b 1c 1a 2a 2c 2a 1c 6a 1b 4a 1b 1a 1c 1a 2c
	1c 1b 2c 1b 1a 1c 2a 2a 1b 2c 1a 2a 1b 2c 1b 1c 4a 2c 2a 1b 1a 1c 2a 1b 1c 4a
	1b 1c 1c 1b 1c 1b 1c 1a 1c 3b 2b 1a 1c 2a 1b 1a 1c 4a 1a 1c 1b 1a 2b 5b 1a 1c 1a
	1a 1b 2a 2b 3a 2b 1c 3a 1b 4a 3a 3b 2b 1a 1b 2a 1a 1c 1a 2b 1c 3b
	1a 2b 2c 1b 1c 2b 1c 1c 1b 2c 1b 1a 2b 1a 1c 1a 1b 1c 3b 2c 1a 2a 1b 1a 1c 2b 1a 1c 3b
	1b 1b 2c 3a 1b 2c 1a 1b 1a 1b 1c 2a 2c 2a 1a 1b 1a 1c 1a 2c 1b 2c 1b 1a 1c 3b 4a
	2c 1b 3a 1b 1a 4c 1b 2a 2b 1a 1c 4b 3a 1a 2c 1a 1c 1c 1c 1b 2b 2a 1c
	1a 1b 1a 3c 1a 3c 2b 2a 1b 1b 2c 1b 2c 2a 3c 1b 1c 2b 4a 1c 4b 1a 1c 1a 1b
	1a 1c 1b 2c 4c 1b 1c 1a 1b 1c 5a 2b 4c 1a 1c 2a 1b 2c 2b 1c 1a 1c 3a 1b
	3a 3b 2c 2c 2b 1c 1b 1a 2c 1b 4a 6c 2b 1a 2a 2a 1b 1a 1c 2a
	1b 2a 3c 1c 2a 1a 2c 2a 1c 1b 1c 1a 2b 1a 1c 2a 1c 3a 1c 1b 1a 1c 1b 1b 3c
	2a 1b 1c 1a 3b 4a 1b 1b 1a 5b 2b 1c 1b 2c 1a 1c 1a 3b 1c 1b 3a 1b 1b 2c 1a
	1c 2b 1c 3a 1b 1a 1b 2c 3a 1a 2c 1b 2b 1a 1b 2b 1c 3a 1b 1c 1c 1a 2c 1a 2b 3c 1a
	1b 4c 1a 1b 1a 1b 1a 1a 2b 1a 1b 1a 2c 1b 1a 1b 1a 3b 1a 2c 1a 1b 1a 2c 1a 1b 1c 1b 1c 1a 1b 1b 1c
	4b 2a 1c 1a 4b 1c 1a 1b 3a 4a 1b 4a 1b 1a 2c 2a 1b 1a 1b 1c 1a 2b 1c 1a
	1a 1b 1a 1c 1a 1c 1b 1c 2a 2b 1a 8a 2c 2a 4b 2c 2a 1b 1b 3a 3c 1a 1b
	2b 2c 1b 1a 4c 2a 1c 1b 1a 2a 2b 6a 1c 2a 1b 3a 1b 1a 1a 3b 4a 1c 1c 1b
	2b 1a 1b 1a 1b 3c 1b 3a 1b 5a 2b 1a 1b 1a 1c 1a 1b 1a 1b 2a 2b 2c 1b 5a 1c 1b
	1c 1a 1a 2c 1a 1b 1c 2a 1b 1c 3a 1b 1c 1a 1b 1a 1c 2b 1c 3b 1c 2a 3c 2a 2b 1a 1c
	2c 2a 1a 3a 1c 1b 1c 1a 2c 1c 4b 1a 1c 2b 1a 1c 2c 3a 1c 1b 1a 1b 1c 3b
	5a 1b 3a 3b 1c 2a 1c 3b 1a 1c 2a 2c 1b 1c 1a 1a 1c 2a 1c 1b 2c 3a 3c 1b
	1a 1b 1a 2c 1b 1b 7b 3a 2b 2a 1c 1b 1a 3b 3c 1b 2c 3a 1c 1b 1c 1b
	1b 2b 1a 1c 1b 1a 1c 2b 2c 1a 3c 1c 2a 1b 2c 2b 1c 2a 3b 2a 10c
	3b 1a 1c 1a 2c 2b 1c 2b 1c 2a 2c 2a 2b 2c 1a 1b 2b 1c 4b 1c 2c 1a 1b 1c 2c 1b
	1b 2c 1a 1c 1c 1b 1a 1a 3a 2b 1a 4b 3b 2a 1c 1a 1b 1c 1b 1a 1b 1a 1b 1a 3c 1c 2c 1a
	1b 4c 4b 1c 2a 2b 1a 1c 1b 1b 2a 1b 1a 1a 3c 1b 1a 3b 2c 1b 2c 1b 2c
	2b 1a 1b 1a 2c 2b 1a 1b 1c 1a 2b 3a 3b 2a 1a 1b 2a 1b 3c 1a 1c 3b 3c 4b 2b
	1c 1a 1b 2a 1a 2a 1b 1c 4a 2b 1a 1b 1c 2a 1a 1b 2a 1b 2c 1b 1a 1b 1c 1a 3b 2b 1c
	2a 2b 2a 2c 2a 4b 1a 1b 1c 1b 1c 3a 1c 1b 1c 1b 1c 1b 4a 1a 1b 1a 3c 1b 1a 1c 1b 1a 2b 1a
	2a 3c 1a 2b 1a 1c 1a 1a 3a 2c 6a 1b 1a 1b 2a 2c 1b 1a 1c 2b 2a 1a 2b 1a 1b 2a
	2a 2c 1a 1c 2b 1a 1c 1c 3a 2b 3a 2c 1a 1a 1a 1c 1b 3c 3a 1a 1b 1a 3b 1a
	1c 1a 2c 2a 2a 1c 1b 2c 1b 1a 1c 1a 2b 1a 1b 2c 1a 3b 2c 1a 2c 1b 1c 1a 1b 2a 1c 2a 2b 1c
	3a 1b 1a 1c 5b 1c 1b 1a 3c 1a 1b 1c 2a 4b 1c 1a 1c 1b 2a 3c 2b 2a 1b 1a 2c
	1c 1b 1b 1c 1c 2b 1b 1c 4a 1b 2a 1b 1a 6b 1a 2c 1b 1c 3c 1b 1b 1a 2b 1c 1b
	1a 1c 1b 1a 1c 1b 3c 1a 1c 4a 1b 1a 3c 2b 1c 1a 1b 1a 1b 1a 1c 1b 1b 2a 1c 2a 1c 1b 2a 3c
	5a 1c 1a 3b 2a 1b 1c 1a 1c 1a 2b 1c 1a 1c 2c 1b 1c 2a 1c 5b 2a 1b 1c 1a 1b 1c 1b 2a
	4a 1b 1c 2a 1b 2a 1b 4a 1c 1c 3c 1a 2c 1b 1b 2c 1b 6a 1b 1c 1c 1a
	5a 2c 1b 2c 1b 2a 1b 1c 1a 1c 1a 1b 1c 3b 1c 2a 1b 1a 1a 1c 1b 1b 1c 2a 1c 1a 2a 1c 1a 2c 1a
	4a 1b 1c 1b 2c 2b 5c 1c 1b 1a 2c 1a 1c 1b 2c 4a 1c 1a 1b 2c 1a
	3a 2a 2c 1b 1a 2c 3a 2b 3a 1b 1c 5a 1c 2c 1a 1c 1a 1b 2a 1b 3c 2a
	2b 4a 1a 1b 2c 1b 1b 1c 2a 1c 1a 1b 2c 2a 1c 3a 1b 4c 1c 3b 2c 4c
	1c 1b 1a 1b 2a 2b 1c 3a 1b 2c 2a 2c 2b 7c 2b 1a 1b 1a 2c 1a 4c 1b 1c
	1a 1b 2a 1b 5c 2a 1a 1c 1a 1b 1c 2b 2c 1c 1b 1a 1c 1a 1c 1b 1b 3a 1c 1a 2c 2c 1b 1c 2b
	1a 1b 1c 1b 1c 1b 2a 2a 1b 2a 1c 1b 1b 3a 1c 2a 1b 1a 1a 1b 1c 1a 1b 2a 2b 1c 1b 1a 1b 2a 1b 2c
	1b 1b 1a 5b 1c 2a 1b 1b 2c 1a 1c 1a 1a 1b 2c 1b 1a 1c 1b 1c 4a 4b 1a 1b 3a 1c 1b 1c
	1c 1b 2a 4c 2c 1a 2c 1c 1a 2b 2a 1b 1c 1a 2b 2a 1b 2c 2a 2a 1c 2a 1c 2b 1c
```

We ran `pynogram -b nonogram.txt`, did some filtering of output (i.e. removed column and row definitions), replaced arbitrary color values `abcd` to expected `0123`, and came to the following `solution.txt` acceptable by the challenges binary:

```
11113111122220112101130013331200111133333221101111
11132112111223120210333311121301031133301331111120
01013110211111123112031222321100033121030033311101
11211112221232331023030132301130231211122003120132
11220220320222031001103311031111112001111210031330
30233213011011233101102332311110033001121311231111
23030232313222022103112131111013020001022022222131
12112201110220311121111011122200022121101301223222
12203323022300320332122013120322233101121322013222
20233111203312120311330110121300133203321322211110
33020111213333021122132222111013301303003202200113
12133313332211020233233113332302211110032222130102
13233003333230100200031111122333313112330223131112
11122233033022321033021111333333022101101120130110
20113330301101331132301221003011311132001320233300
11023122211112021222220223233103122232111202003301
30223111212033111013320221200223111230313312233301
23333102102101221210033201212221331213312323102023
02222113122223121110111121111021331100021023122301
12130103230112210111111110331122220331120211133312
22332133331132100112211111103112111210122211113032
22121233302111211111220012001312121122332111110032
03101331230001123111231213223222301133301122130000
33110010111323133032222013002201300331110321230222
11111211102223113222013110033231013011323311103332
12013320200002222222111221103020122233323311132302
02022132130223310333030112033022311222113333333333
22213133223223110330011220331202203222230331230332
23313032101011122122220222113123212121333030003310
20003333222231122103202011210133321222332330000233
22121033221231221112221101211233310322203332222022
31021101011231111022012301101200112332102312220223
11221133011222212323111323232111101213330213021221
11333012210310101113311111120121133213221101221211
11331032213031112211133101000000132333111001212221
31330110011323321312201233122233133200301211311223
01112010322222321333123112222031302110333220112133
03202030302202311112110212222221332030333202122302
13213200333001311112013332231212132002113113211333
11111312221120313122313033231132222200011231023211
11112311211000002111130303331332023321111112030301
11111332330211231312322231121013202301130101131331
11112320332233333030201033103203300001111301233001
11101103302013311122111231111130330131020011233311
22111101233202031131203300113111233330322203303333
32121122031112331133223333333002210213310033332003
12112033333110131023223303213132021113013303320322
12320302110110021132021113112101231211223201211233
20210222223112023301310123302132311110222212111323
32011333303310033031221123122112033110113113022003
```

Finally we ran challenge's binary to get the flag:

```
./binary solution.txt 
pbctf{ebbebebtebeertbebbrbbrebbetbttetebrtbbbeeettbbtbbbbteetbrrrbbttb}
```
