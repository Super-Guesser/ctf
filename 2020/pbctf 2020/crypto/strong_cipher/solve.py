#!/usr/bin/python2
import re
def gf2(src1, src2):
    ret = 0
    for i in range(0, 8):
        if src2 & (1 << i):
            ret = ret ^ (src1 << i)
    for i in range(14, 7, -1):
        p = 0x11B << (i - 8)
        if ret & (1 << i):
            ret = ret ^ p
    return ret

ct = open("ciphertext", "rb").read()

key_len = 12
ct_len = len(ct)
pt = bytearray(ct_len)
key = 0

for j in range(key_len):
    max_printable = -1
    for k in range(256):
        printable = 0
        for i in range(j, ct_len, key_len):
            if (32 <= gf2(ord(ct[i]), k) <= 126):
                printable += 1
        if printable > max_printable:
            key = k
            max_printable = printable
    for i in range(j, ct_len, key_len):
        pt[i] = gf2(ord(ct[i]), key)

print(re.findall(r'pbctf{.*}', pt)[0])
