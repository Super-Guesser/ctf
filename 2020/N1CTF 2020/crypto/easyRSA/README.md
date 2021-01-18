## easyRSA?

```python
from Crypto.Util.number import *
import numpy as np
 
mark = 3**66
 
def get_random_prime():
    total = 0
    for i in range(5):
        total += mark**i * getRandomNBitInteger(32)
    fac = str(factor(total)).split(" * ")
    return int(fac[-1])
 
def get_B(size):
    x = np.random.normal(0, 16, size)
    return np.rint(x)
 
p = get_random_prime()
q = get_random_prime()
N = p * q
e = 127
 
flag = b"N1CTF{************************************}"
secret = np.array(list(flag))
 
upper = 152989197224467
A = np.random.randint(281474976710655, size=(e, 43))
B = get_B(size=e).astype(np.int64)
linear = (A.dot(secret) + B) % upper
 
result = []
for l in linear:
    result.append(pow(l, e, N))
 
print(result)
print(N)
np.save("A.npy", A)
```

Looking at the problem, we see that we need to do the following

- Factorize NN using the vulnerable random prime generator, and recover the array "linear"
- Solve the instance of LWE by using the fact that secret vector (the flag) is small as well

We first focus on the first part. I actually thought about coppersmith method, but I couldn't get it to work.

I already have an experience in wasting time with coppersmith approach, (sharsable) so I stopped attempting.



rbtree noted that there is a polynomial ff with small coefficients, degree 8, and f(3^66) ≡ 0 (mod N)

This is because for each p,qp,q, there's a degree 4 polynomial with small coefficients that vanishes at 3^66 modulo that prime.

If we multiply the two degree 4 polynomials, we arrive at the described polynomial of degree 8.

He then suggested using a lattice to find this polynomial. This was an excellent idea!



Since we want a small-coefficient-linear-combination of 3^(66⋅0),3^(66⋅1),⋯,3^(66⋅8) that vanishes to zero, we must use scaling, as I did in sharsable. Check the code for technical details. As I do usually, I used Babai's closest vector algorithm. We can expect ff to be factorized into two polynomials of degree 4. By calculating each polynomial at 3^66 and taking GCDs, we can retrieve p,q This completes Part 1. 



For Part 2, we need to solve the LWE problem. This is hard in general, but we know that the secret vector is small as well. 

Of course, LWE problem can be modeled as CVP problem, and we use the "secret vector is small" fact here as well.



```python
## Step 1 : Factorization of N
rat = 2 ** 1000 
## scaling : super large to force zero in the first column
 
for i in range(0, 9):
    M[i, 0] = (3 ** (66 * i)) * rat
M[9, 0] = n * rat
for i in range(0, 9):
    M[i, i+1] = 1
 
Target = [0] * 10
for i in range(1, 10):
    Target[i] = (2 ** 64)
 
M = M.LLL()
GG = M.gram_schmidt()[0]
Target = vector(Target)
TT = Babai_closest_vector(M, GG, Target)
 
P.<x> = PolynomialRing(ZZ)
f = 0
for i in range(1, 10):
    f = f + TT[i] * x^(i-1)
print(f.factor())
## (2187594805*x^4 + 2330453070*x^3 + 2454571743*x^2 + 2172951063*x + 3997404950) 
## (3053645990*x^4 + 3025986779*x^3 + 2956649421*x^2 + 3181401791*x + 4085160459)
 
cc = 0
cc += 2187594805 * (3 ** (66 * 4))
cc += 2330453070 * (3 ** (66 * 3))
cc += 2454571743 * (3 ** (66 * 2))
cc += 2172951063 * (3 ** (66 * 1))
cc += 3997404950 * (3 ** (66 * 0))
 
p = gcd(cc, n)
print(p)
print(n // p)
print(n % p)
 
## Step 2 : housekeeping stuff
## res in res.txt, A in A.npy
p = 122286683590821384708927559261006610931573935494533014267913695701452160518376584698853935842772049170451497
q = 268599801432887942388349567231788231269064717981088022136662922349190872076740737541006100017108181256486533
e = 127
n = p * q
phi = (p-1) * (q-1)
d = inverse(e, phi)
 
cv = []
for x in res:
    cv.append(pow(x, d, n))
 
print(cv)
 
np.set_printoptions(threshold=sys.maxsize)
A = np.load("A.npy")
A = np.ndarray.tolist(A)
print(A)
 
## Step 3 : LWE with CVP
mod = 152989197224467
 
sel = 15 ## sel can be large as 127, but that's too slow
M = Matrix(ZZ, sel + 43, sel + 43)
for i in range(0, 43):
    for j in range(0, sel):
        M[i, j] = A[j][i]
    M[i, sel + i] = 1
for i in range(43, 43+sel):
    M[i, i-43] = mod
Target = [0] * (sel + 43)
for i in range(0, sel):
    Target[i] = res[i] - 8
for i in range(sel, sel + 43):
    Target[i] = 80 ## printable
 
Target = vector(Target)
M = M.LLL()
GG = M.gram_schmidt()[0]
Target = vector(Target)
TT = Babai_closest_vector(M, GG, Target)
 
print(TT)
 
res = ""
for i in range(sel, sel+43):
    res += chr(TT[i])
 
print(res)
```

