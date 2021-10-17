# Cosmo (rev)

This was a fun challenge. Given executable seems to be runnable on multiple architectures. Though, to make it easier to analyze, we needed the Linux version. Have run the executable once, spotted that the executable has been modified to pure ELF, though, with wrong architecture (FreeBSD), making it impossible to run it with `gdb`. Used `elfedit --output-osabi Linux hello.com` to correct that.

Once able to debug it, spotted at location `0x4030c4` a main comparison mechanism, checking expected "checksum" alike values for 2-per-2 bytes of flag, with a table located at `0x40c000`. Now, there was an option to either reverse the function and rewrite it in python (e.g. for z3 solving), or to play dumb and brute it. We chose the second approach, at least in a "smart dumb" way. Used parallel cracking of 2-per-2 character combinations by abusing the `gdb` scripting. Solving script (used in parallel run) has been used, where once the current pair has been found, all instances have been killed and the `known` variable has been updated accordingly. Final flag has been `pbctf{acKshuaLLy_p0rtable_3x3cutAbLe?}`.

## solve.py

```py
#!/usr/bin/env python3

import beepy
import itertools
import os
import random
import re
import string
import subprocess

ALPHABET = string.ascii_lowercase + string.ascii_uppercase + string.digits + '{_}'

def shell(cmd):
    content = ""

    try:
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        content, _ = process.communicate()
    except Exception as ex:
        content = str(ex)

    return content or ""

gdb = """
file ./hello
b *0x4030cc
r %s
%k
p $eflags
p $rdi
quit
"""

script = "/var/run/shm/%s.gdb" % os.getpid()
known = ""
while len(known) < 38:
    combinations = ["".join(_) for _ in itertools.product(ALPHABET, repeat=2)]
    random.shuffle(combinations)
    for combination in combinations:
        combination = "".join(combination)
        candidate = "%s%s" % (known, combination)
        candidate += "_" * (38 - len(candidate))
        open(script, "w+").write(gdb.replace("%s", candidate).replace("%k", "c\n" * (len(known) // 2)))
        result = shell("gdb -x %s" % script).decode()
        flags = re.search(r"\$1 = (.+)", result).group(1)
        rdi = re.search(r"\$2 = (.+)", result).group(1)
        if "ZF" in flags:
            print("[o] %s: %s" % (candidate, rdi))
            beepy.beep(sound=1)
            known += combination
            break
        else:
            print("[i] %s: %s" % (candidate, rdi))
```

