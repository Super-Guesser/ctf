# Binary Tree
Each input's bit, it select the xor table offset and add corresponding value to r9. With xor table offset, it xor to address 0x4000AD itself and choose next child node.
We can parse this graph by traveling all nodes.

```python

# how input change to bits.
"""
a = b"pbctf{"
ll = []
for i in a:
    while i:
        ll.append(i & 1)
        i >>= 1
"""

addr = 0xAD
xor_addr = 0x176
sz = 0x20

f = open("binarytree.elf", "rb").read()

from capstone import *
code = f[addr:addr + 0x20]
xor_off = 0

def xor_l(cd, off):
    xor_tbl = f[xor_addr + off: xor_addr + off + 0x20]
    res = []
    for i, j in zip(cd, xor_tbl):
        res.append(i ^ j)
    return bytes(res)

def code_to_node(code):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    l = []
    for i in md.disasm(code, 0x4000AD):
        if i.mnemonic == "lea":
            l.append(int(i.op_str.split(" + ")[1][:-1], 16))
        if i.mnemonic == "add":
            l.append(int(i.op_str.split(", ")[1], 16))
    return l

G = dict()

q = []
def b_ga():
    global q
    dc = dict()

    G[-1] = {"from":set(), "to":set()}

    while len(q) != 0:
        code, before, off, way, cost = q[0]

        if off not in G:
            G[off] = {"from":set(), "to":set()}
        l = code_to_node(code)
        G[before]["to"].add((off, way, cost))
        G[off]["from"].add(before)
        q = q[1:]


        if len(l) != 0 and off not in dc:
            dc[off] = 1
            
            code2 = xor_l(code, l[0])
            q = q + [(code2, off, l[0], 1, l[1])]
            
            code2 = xor_l(code, l[2])
            q = q + [(code2, off, l[2], 0, l[3])]
            
        elif len(l) != 0 and off in dc:
            G[before]["to"].add((off, way, cost))
            G[off]["from"].add(before)

            
code = xor_l(code, xor_off)
q.append((code, -1, 0, 0, 0))
b_ga()

# saved to G
```

With this graph, we used dijkstra to find the shortest path from head to tails.
`pbctf{!!finding_the_shortest_path_in_self-modifying_code!!_e74c30e30bb22a478ac513c9017f1b2608abfee7}`

