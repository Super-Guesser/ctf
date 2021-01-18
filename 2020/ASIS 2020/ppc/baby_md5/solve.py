from hashlib import md5
import random
import string
from sys import argv

def _md5(x, n):
    for i in range(n):
        x = md5(x).hexdigest()
    return x

def brute(x, m, n):
    assert(m > n)
    while 1:
        rand = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(10))
        z = _md5(x + rand, m-n)
        if z.startswith('dead'):
            print x + rand
            print z

print brute(argv[1], int(argv[2]), int(argv[3]))
