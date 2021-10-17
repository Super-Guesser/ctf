# BTLE (misc)

In this challenge we are given PCAP file with captured packets from Bluetooth communication. After lots of different approaches, we figured it out that those `Write Request` packets have a field `Offset` along with the `Value`. Thus, different write attempts were made, where one has been (potentially) overwriting the parts of the current state buffer at the recipient side.

We extracted those two fields with the usage of `tshark` like `tshark -r btle.pcap -Tfields -e btatt.offset -e btatt.value "btatt.opcode == 0x16"`. Later, we just had to script it. Final flag was `pbctf{b1Ue_te3Th_is_ba4d_4_y0u_jUs7_4sk_HAr0lD_b1U3tO07h}` (Note: letter `b` from `pbctf` has been missing for whatever reason, thus, we just inserted it manually).

## solve.py

```py
#!/usr/bin/env python2

# tshark -r btle.pcap -Tfields -e btatt.offset -e btatt.value "btatt.opcode == 0x16"

content = """
1	316b6f5a50703972655f564a7a45555f444e6e73537635786a3851554f5774644c33666a645f6c4c4a434c5562634d633443514879416c4648
11	53737447325433564f65427a58756637766265355a5948666d675a5f455676695248364c626b67566643554b6e44
11	4c6a554c684c6b6850494c4658425233467463734f5778764b6e317072745a66643067
48	315539307a4454306d5a
16	5731476d30414e615951546c30753954566c724e7874747765565138423676
30	486f5542526167794d79364259373878
16	3643304449624964506d5f
33	4871726749744d6b5164646c445f
30	5f
1	7063544e72576f
11	78467054
33	6837783034664f34437274
50	3053703037743070
11	696533
16	7551595f4937677835
16	5f4a
17	6973
20	626175525736
22	44385f
35	6251433272327a68306c
50	6b654f
3	74317a5567
55	687d71
35	67757734514874
41	7272
50	3374
4	667b6a7445
31	6a
6	6f31
6	62
50	33
57	0a
35	5f534541
27	79
25	34
22	34
41	41
11	74
23	64
8	55
33	73
36	34736970
38	6b
39	5f
""".strip()

result = [" "] * 100

for line in content.split("\n"):
    index, content = line.split("\t")
    index = int(index)
    content = content.decode("hex")
    for char in content:
        result[index] = char
        index += 1

print "".join(result).strip()
```
