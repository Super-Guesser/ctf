## Curve

```python
#!/usr/bin/env sage
 
import signal, hashlib, string, random, os 
 
os.chdir(os.path.dirname(os.path.abspath(__file__)))
FLAG = open("./flag.txt", 'r').read()
ROUNDS = 30
 
def PoW():
  s = ''.join([random.choice(string.ascii_letters + string.digits) for _ in range(20)])
  h = hashlib.sha256(s.encode()).hexdigest()
  prefix = s[:16]
  print("sha256(%s+XXXX) == %s" % (prefix, h))
  c = input("Give me XXXX: ")
  if hashlib.sha256((prefix + c).encode()).hexdigest() == h:
    return True 
  return False
 
def chall():
  p = ZZ(input("P: "))  # of course we are using sage >= 9
  a = ZZ(input("A: "))
  b = ZZ(input("B: "))
 
  if not is_prime(p) or p.nbits() < 512:
    print("No bad parameters.")
    return
 
  E = EllipticCurve(GF(p), [a, b])
  if E.is_supersingular():
    print("No this is not good enough.")
    return
 
  q = E.order()
  x1 = ZZ(input("X1: "))
  y1 = ZZ(input("Y1: "))
  x2 = ZZ(input("X2: "))
  y2 = ZZ(input("Y2: "))
  G1 = E((x1, y1))
  G2 = E((x2, y2))
 
  for _ in range(ROUNDS):
    a0 = randint(1, q - 1)
    a1 = randint(1, q - 1)
 
    c = -1
    while c == -1 or c == a0 * a1:
      c = randint(1, q - 1)
 
    g0, g1 = G1 * a0, G2 * a1 
    c0, c1 = G1 * (a0 * a1), G1 * c
    b = randint(0, 1)
 
    if b == 0:
      print(g0, g1, c0)
    else:
      print(g0, g1, c1)
 
    choice = ZZ(input("Choice: "))
    if choice != b:
      print("Wrong choice.")
      return
 
  print(f"Thank you! Here's your reward: {FLAG}")
  return 
 
if __name__ == '__main__':
  if not PoW():
    print("Invalid PoW.")
    exit()
  signal.alarm(90)
 
  try:
    chall()
  except:
    print("oof...")
    exit()
```

We struggled greatly on this challenge, despite finding the solution quite immediately. Here's the process.

- EE is a large elliptic curve over a prime field, not supersingular
- We select two points G1,G2G1,G2 on the curve, and play a sort of Decisional Diffie-Hellman game.
- Let's just fix G=G1=G2G=G1=G2 and see what we can do!
- If the order of GG is small, say tt - we can recover a0,a1(modt)a0,a1(modt) easily. 
- Therefore, we can directly calculate a0a1Ga0a1G as well!
- Check if this is equal to the third point given. If so, check b=0b=0 and otherwise check b=1b=1.

Now we do some analysis. 

- If b=0b=0 was chosen, this will give the correct answer with probability 1
- If b=1b=1 was chosen, we fail if c≡a0a1(modt)c≡a0a1(modt), so we succeed with probability 1−1/t1−1/t
- We do 3030 rounds, so tt shouldn't be too small (we want, say, t>50t>50)
- Obviously we do need to solve the discrete logarithm on a group of order tt, so we want small tt

This leads to the following goal.

- Find an elliptic curve that satisfies the server's desired conditions, with the order of the curve having a prime between 5050 and 400400

I think I took about 5 minutes until here, but the journey towards the flag for several reasons.

- First, my initial code used random p,a,bp,a,b, generate the curve, find the order, then check for small primes.
- Seems good right? However, I tried to find GG using E.gens()[0] * (Order // small_prime)
- This obviously takes infinite time, and my computer was on the verge of dying because of it
- I realized the problem and replaced it by generating any point with Tonelli-Shanks and multiplying it by Order // small_prime

So I thought I was done here. After sending the parameters, I realized that I was not done here. Why?

- The server calculates the order of the elliptic curve as well
- While order calculation is done in polynomial time, it's still slow with 512 bit curve parameters
- Therefore, the server times out, and I can't solve the problem

So I thought I was done here, in a different meaning. After solving the remaining challs, I tried the following.

- Simply try the curves of the form y2=x3+by2=x3+b.

This worked, as the order calculation was done much faster. The challenge was solved.

The parameter finding and solution finding was done by me, and the programming was done by rbtree.



I learned a lot from solving this problem :) I'm still inexperienced, lots of studying to do... 

```python
pr = []
for x in range(50, 200):
    if x in Primes():
        pr.append(x)
while True:
    p = random_prime(2 ** 512, False, 2 ** 511)
    if p % 3 == 2: ## in this case, y^2 = x^3 + b is guaranteed to be supersingular
        continue
    d = randint(1, p-1)
    E = EllipticCurve(GF(p), [0, d])
    if E.is_supersingular() == True:
        continue
    print(p)
    L = E.order()
    for cc in pr:
        if L % cc == 0:
            print(p, d, cc, L)
            break
 
## find any point on the elliptic curve
for u in range(1, 100):
    goal = (u ** 3 + a * u + b) % p
    if pow(goal, (p-1) // 2, p) == 1:
        v = tonelli(goal, p) ## sqrt, so you can directly use sage
        G = E(u, v)
        break
 
## hope that G is nonzero
G = G * (Ord // pr)
G1 = G
G2 = G
 
## this ends parameter generation

```

```python
## by rbtree
 
from pwn import *
import string
import itertools
 
conn = remote('47.242.140.57', 9998)
conn.settimeout(None)
 
# PoW
 
challenge = conn.recvline().strip()
print(challenge)
prefix = challenge[7:7+16]
h = challenge.split()[-1]
charset = (string.ascii_letters + string.digits).encode()
for suffix in itertools.product(charset, repeat=4):
    if hashlib.sha256(prefix+bytes(suffix)).hexdigest() == h.decode():
        conn.sendlineafter(b'Give me XXXX: ', bytes(suffix))
        break
print("PoW Done")
 
p = 11572562087281212077294341316763410822093276559896892655806738743748493229131824454041157658617469079306138012813995393545636120267619633658087398895787057 
a = 0
b = 587626359248673832094266933340735482471140319598254235432650868938827936103013631493279303809976008538035914917596142929543705518144408460458007005924570
pr = 97
order = 11572562087281212077294341316763410822093276559896892655806738743748493229131918957581964494921602014693617723606720177358361724985583223555103419211299648
 
Gs = [] ## bunch of points (G, 2G, ... 97G)
print(len(Gs))
 
def get_points():
    points_s = conn.recvline().decode().strip()[1:-1].split(') (')
    points = []
    for point_s in points_s:
        point = tuple(int(v.strip()) for v in point_s.split(':')[:2])
        points.append(point)
    return points
 
conn.sendlineafter(b'P: ', str(p))
conn.sendlineafter(b'A: ', str(a))
conn.sendlineafter(b'B: ', str(b))
conn.sendlineafter(b'X1: ', str(Gs[0][0]))
conn.sendlineafter(b'Y1: ', str(Gs[0][1]))
conn.sendlineafter(b'X2: ', str(Gs[0][0]))
conn.sendlineafter(b'Y2: ', str(Gs[0][1]))
 
print("Parameter Sent")
 
for _ in range(30):
    points = get_points()
 
    for i in range(96):
        if points[0] == Gs[i]:
            a = i + 1
            break
 
    for i in range(96):
        if points[1] == Gs[i]:
            b = i + 1
            break
 
    to_send = 0 if Gs[(a * b % 97) - 1] == points[2] else 1
    conn.sendlineafter(b'Choice: ', str(to_send))
 
conn.interactive()

```

