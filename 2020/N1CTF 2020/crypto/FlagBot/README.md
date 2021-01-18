## FlagBot

```python
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.Padding import pad, unpad
import base64
from secret import flag
 
RECEIVER_NUM = 7
 
def generate_safecurve():
    while True:
        p = random_prime(2 ^ 256-1, False, 2 ^ 255)
        a = randint(-p, p)
        b = randint(-p, p)
 
        if 4*a^3 + 27*b^2 == 0:
            continue
 
        E = EllipticCurve(GF(p), [a, b])
 
        fac = list(factor(E.order()))
 
        # Prevent rho method
        if fac[-1][0] < 1 << 80:
            continue
 
        # Prevent transfer
        for k in range(1, 20):
            if (p ^ k - 1) % fac[-1][0] == 0:
                break
        else:
            return E
 
class Sender:
    def __init__(self, curves, receivers):
        self.secret = randint(1 << 254, 1 << 255)
        self.curves = curves
        self.receivers = receivers
        self.shared_secrets = [None for _ in range(len(receivers))]
 
    def setup_connections(self):
        for idx, receiver in enumerate(self.receivers):
            curve = self.curves[idx]
            print(f"curves[{idx}] : {curve}")
            g = self.curves[idx].gens()[0]
            print(f"g[{idx}] = {g.xy()}")
            receiver.set_curve(curve, g)
            public = self.secret * g
            print(f"S_pub[{idx}] = {public.xy()}")
            yours = receiver.key_exchange(public)
            print(f"R_pub[{idx}] = {yours.xy()}")
            self.shared_secrets[idx] = yours * self.secret
 
    def send_secret(self):
        msg = b'Hi, here is your flag: ' + flag
        for idx, receiver in enumerate(self.receivers):
            px = self.shared_secrets[idx].xy()[0]
            _hash = sha256(long_to_bytes(px)).digest()
            key = _hash[:16]
            iv = _hash[16:]
            encrypted_msg = base64.b64encode(AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg, 16)))
            print(f"encrypted_msg[{idx}] = {encrypted_msg}")
            receiver.receive(encrypted_msg)
 
 
class Receiver:
    def __init__(self):
        self.secret = randint(1 << 254, 1 << 255)
        self.curve = None
        self.g = None
        self.shared_secret = None
 
    def set_curve(self, curve, g):
        self.curve = curve
        self.g = g
 
    def key_exchange(self, yours):
        self.shared_secret = yours * self.secret
        return self.g * self.secret
 
    def receive(self, encrypted_msg):
        px = self.shared_secret.xy()[0]
        _hash = sha256(long_to_bytes(px)).digest()
        key = _hash[:16]
        iv = _hash[16:]
        msg = AES.new(key, AES.MODE_CBC, iv).decrypt(base64.b64decode(encrypted_msg))
        msg = unpad(msg, 16)
        assert msg.startswith(b'Hi, here is your flag: ')
 
 
receivers = [Receiver() for _ in range(RECEIVER_NUM)]
curves = [generate_safecurve() for _ in range(RECEIVER_NUM)]
 
A = Sender(curves, receivers)
A.setup_connections()
A.send_secret()
```

This problem was solved by me, so I can give you a brief look inside my brain.

- You can't really do anything with AES-CBC in this challenge
- You can't really do anything with SHA256 anywhere
- That means that we have to break the DH style shared secret generation
- The secret key is reused every time, so that's the vulnerability
- The curve generation only checks the existence of large primes, so small primes can exist

At this point, the solution was straightforward. For each small prime pp that divides the order of the elliptic curve used, we can find the value of the secret key (modp)(modp) by using Pohlig-Hellman approach. Combining these with CRT, we can recover dd since it is at most 22552255. 

Since we do need to deal with primes of size around 10121012, Baby-Step-Giant-Step is required. Just use Sage.



The below code finds all the shared secrets. The remaining parts of the problem are straightforward.

```python
cur_mod = 1
cur_val = 0
 
for i in range(0, 7):
    a = S[i][0]
    b = S[i][1]
    p = S[i][2]
    E = EllipticCurve(GF(p), [a, b])
    Ord = E.order()
    L = list(factor(Ord))
    GG = E(g[i])
    SS = E(S_pub[i])
    for pp, dd in L:
        if pp <= 10 ** 12 and dd == 1:
            Gp = (Ord // pp) * GG
            Sp = (Ord // pp) * SS
            tt = discrete_log(Sp, Gp, operation='+')
            cur_val = crt(cur_val, tt, cur_mod, pp)
            cur_mod = (cur_mod * pp) // gcd(pp, cur_mod)
    print("Done ", i)
    
print("[+] Secret: ", cur_val)
 
for i in range(0, 7):
    a = S[i][0]
    b = S[i][1]
    p = S[i][2]
    E = EllipticCurve(GF(p), [a, b])
    RR = E(R_pub[i])
    RES = RR * cur_val
    print(RES.xy()[0])
```

