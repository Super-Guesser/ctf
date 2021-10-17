# Is that your packet? (misc)

This challenge was quite "challenging". By just listening to the given `sus.flac`, we were sure that it was a FSK - most possibly the 1200 baud rate, because of its common usage. By experimenting with different programs, we succeeded in extracting the following text with the usage of `multimon-ng`:

```
$ sox -v 0.97 -t wav sus.wav -esigned-integer -b16 -r 22050 -t raw sus.raw  # sus.wav is a mono channel from sus.flac
$ multimon-ng -q -t raw -a AFSK1200 sus.raw | grep -v AFSK1200
RMS Packet. Visit www.sc4arc.org for information.
[WL2K-5.0-B2FWIHJM$]
;PQ: 05422286
CMS via W6SCF >
;PM: W6ELA PRJYZ2QE1NTD 536 wsmith9752548@gmail.com So what is this?
FC EM PRJYZ2QE1NTD 702 536 0
F> 53
..So what is this?.0...........z.mgs................@>8X7{.....-]j.Tx...ki..~.4.w.m.!....l>.x|.%(x.........=!.&..k....sb....}...
..0...\...N....Y..~z.\H......d......z.....\..B..Jyx..#.0...2..'....K.#.E.bf._.L.IA.....q....G~(.....O..b.o._..!Q....3.........6.
.6>.~@......T..e.....9x..1.1........-...?]..u...w..*..
`l....
.Ev.KJ.........Q.."._T.v.N)..V....H..f..w.7*...a......gC.f........
...>...s.....`X.(^.6....sh...O......'..=}!y7q.m+s.FA..&{..z/......9*..S....D.'y..&.tb._...X<5V....A.X....VM..T..s..((.i....e...
$Rr....E..m|..$.M(N..I./..j^.WW....w...=...(].N.....}
FQ
```

After short Google search, we found that this was a capture of RMS/Winlink transmission, where it was not obvious how to decode it. By installing different programs, most promising "combo" seemed to be `Winlink Express` in combination with `Soundmodem`. After hours and hours of a struggle, we figured out that it was not feasible to do it that way, or maybe we did something wrong. While `Winlink Express` expected the two-way communication (while we have only a sound recording of a single way), another problem was that the `Winlink Express` doesn't like the usage of arbitrary receiver station code.

Thus, we had to do some more "dirty" work. We had to modify the source code of `multimon-ng` to be able to get the binary data in a non-dotted form (e.g. hexadecimal). Additionally, we did a research on the format, and found out that custom compression algorithm is used in Winlink, called `lzhuf`. We found a usable implementation at https://web.archive.org/web/20210126231515/https://people.cs.umu.se/isak/Snippets/lzhuf.c. Now, after lots and lots of try-outs, it was obvious that we are missing some pieces of the puzzle, as there are some frame-alike bytes, making the whole decompression quite problematic.

To find the problematic bytes, we used the following approach. We assumed that those extra "frame" bytes are 1-2 bytes long, and that they are somewhere inside the binary data we already have. Thus, we manually tried to remove pairs of bytes at arbitrary places, and compared to the existing data we already had. If it appeared as better, then we were sure that we had hit the "sweet" spot. At the end, with this approach, we removed two places with those problematic bytes, resulting with the script given at the end (Note: places with multiple places have are actually those manually found and removed frame bytes, while the `lzhuf` is the compiled version of the previously mentioned `lzhuf.c`).

Final message has been:

```
MID: PRJYZ2QE1NTD
Date: 2021/09/29 04:21
From: SMTP:wsmith9752548@gmail.com
To: W6ELA
Subject: So what is this?
Mbo: SMTP
Body: 561
Yes, there is a worldwide system out there that can be used for sending
email over radio waves called "Winlink". A bit old school but hey, it
actually works great. Iridium and other satellite technologies have
replaced it to a large extent with the sailing crowd who used
to be a big user group, but it is still there.
... and in case of emergency, nothing beats HF or VHF, if you are a HAM
radio operator.
Glad you made it all the way here and maybe learned something new today.
Here is what you came for: cGJjdGZ7OTA4MjNqc2RnaGtfODAxM2tzNzIzNH0=
```

Thus, the flag `pbctf{90823jsdghk_8013ks7234}` was the Base64 decoded form of the message found at the end (`cGJjdGZ7OTA4MjNqc2RnaGtfODAxM2tzNzIzNH0=`).

## solve.py

```py
#!/usr/bin/env python2

import subprocess

def shell(cmd):
    content = ""

    try:
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        content, _ = process.communicate()
    except Exception as ex:
        content = str(ex)

    return content or ""

_content = """be020000ecf57a1c6d6773bdd6f2f9b7ddde8ef7b5e0c3cce5acfb403e3858377bca971bbaee2d5d6aaa547814a6a36b69d2ff7eff34aa77f16db02103ffcefd6c3e92787c192528789ccf9c1b199fc6ebdf3d21bc26ed9f6bc7c2b9ec7362c49c01f77dabe31bdc06309a9b985cf9b5d34ea0a9c9fe59e8af7e7a135c488491e71ff00564a9e09013ebad7a8dbee1808d5cf8cd42c7844a7978e68523143081aa8c32029127f3be01f44b12230145186266105fc84c9a49418bfcf3e8fd71ebadfa03477e28bff9bfa1824fc30062816ff05ffe0c2151ba0c92bd33e4e7198ddc06ceed9736f4


1f 36 3e e3 7e 40 ee a1 ca 1c c1 f9 54 ee fa 65 89       19 f4 39 78 cb ef 31 90 31 9f be 00 05 da f1 f9 10 2d c5 eb 07 3f 5dbebf75a4edfe77ab112af39c0d606cdbdbaafb0dde4576dd4b4aebaa8b0befe1b9c3c951bffe22b85f54fa76884e29efae568ac7de994883fa669dde77b2372a9ab08a6116aeb98ca89167439f66f4a2da98b2b7d9c1

8f 9d 17 3e ae a9 ef 73 b0 c9 0a a5 bb 60 58 b2 28 5e 93 36 dc be 15 06 73 68 94 b4 ef 4f 05 9c 0b e1 17 87 27 94 05 3d 7d 21 79 37 71 bc 6d 2b 73 b6 46 41 13 09 26 7b 0b ad 7a 2f cbd9f6b0d29f392aea1453b304c6c544df2779df8426ca7462a85fa2d1ac7f583c3556ef8ed4b9 41 d5 58 f3 be 8e b2 56 4d f3 8a 54 da 16 73 d2 db 28 28 1d 69 88 bb be ab 65 b8 e6 9f

245272f48da2ff459eb8 6d 7c ca       f8 4d 28 4e d6 ea 49 8b 2f 1f 01 6a 5e 1e 57 57 1b 1a b5 c2 77 b0 c6 aa 3d e6 0a 83 28 5d 1a 4e fe 15 a6 80 04 7d""".replace("\n", "").replace(" ", "").decode("hex")

open("file1", "w+b").write(_content)
shell("./lzhuf d file1 file2")
result = shell("strings file2")
print(result)
```
