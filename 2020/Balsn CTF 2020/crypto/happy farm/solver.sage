import sys

n = int(sys.argv[1])
onion1 = int(sys.argv[2], 16)
onion2 = int(sys.argv[3], 16)

PR.<x> = PolynomialRing(Zmod(n))

for i in range(16):
    f = (x + ((onion2 + (i * 2 ^ 32)) * 2 ^ 296)) ^ 3 - onion1

    res = f.small_roots(beta=1.0, epsilon=0.04)
    if res:
        print(res[0] + ((onion2 + (i * 2 ^ 32)) * 2 ^ 296))
        exit(0)