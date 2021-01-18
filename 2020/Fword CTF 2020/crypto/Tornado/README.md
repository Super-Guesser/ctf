# Tornado - 43 Solves

## Analysis
```python
#!/usr/bin/python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import long_to_bytes
from binascii import hexlify
import random

key = "very_awes0m3_k3y"
flag = "FwordCTF{xxx_xxx}" #REDACTED
assert len(flag) == 62
assert len(key) == 16

def to_blocks(text):
        return [text[i*2:(i+1)*2].encode() for i in range(len(text)//2)]

def random_bytes(seed):
        random.seed(seed)
        return long_to_bytes(random.getrandbits(8*16))

def encrypt_block(block,key):
        cipher = AES.new(key.encode(), AES.MODE_ECB)
        plain_pad = pad(block, 16)
        return hexlify(cipher.encrypt(plain_pad)).decode()

def encrypt(txt, key):
        res = ""
        blocks = to_blocks(txt)
        for block in blocks:
                res += encrypt_block(block, key)
        return res

def translate(txt,l,r):
        return txt[:l]+txt[r:]+txt[l:r]

def shuffle(txt):
        seed=random.choice(txt)
        random.seed(seed)
        for _ in range(45):
                l = random.randint(0, 15)
                r = random.randint(l+1, 33)
                txt = translate(txt, l, r)
        return txt

flag = shuffle(flag)
print (encrypt(flag, key))

"""
3ce29d5f8d646d853b5f6677a564aec6bd1c9f0cbfac0af73fb5cfb446e08cfec5a261ec050f6f30d9f1dfd85a9df875168851e1a111a9d9bfdbab238ce4a4eb3b4f8e0db42e0a5af305105834605f90621940e3f801e0e4e0ca401ff451f1983701831243df999cfaf40b4ac50599de5c87cd68857980a037682b4dbfa1d26c949e743f8d77549c5991c8e1f21d891a1ac87166d3074e4859a26954d725ed4f2332a8b326f4634810a24f1908945052bfd0181ff801b1d3a0bc535df622a299a9666de40dfba06a684a4db213f28f3471ba7059bcbdc042fd45c58ae4970f53fb808143eaa9ec6cf35339c58fa12efa18728eb426a2fcb0234d8539c0628c49b416c0963a33e6a0b91e7733b42f29900921626bba03e76b1911d20728254b84f38a2ce12ec5d98a2fa3201522aa17d6972fe7c04f1f64c9fd4623583cc5a91cc471a13d6ab9b0903704727d1eb987fd5d59b5757babb92758e06d2f12fd7e32d66fe9e3b9d11cd93b11beb70c66b57af71787457c78ff152ff4bd63a83ef894c1f01ae476253cbef154701f07cc7e0e16f7eede0c8fa2d5a5dd5624caa5408ca74b4b8c8f847ba570023b481c6ec642dac634c112ae9fec3cbd59e1d2f84f56282cb74a3ac6152c32c671190e2f4c14704ed9bbe74eaafc3ce27849533141e9642c91a7bf846848d7fbfcd839c2ca3b
"""
```

We have to consider three key points of this challenge.  
This application invented by Python 3.x  
And this encryption logic consists of AES encryption and shuffled with randomize seeds. (Python 3's random seed tables are different from Python 2's)  
And we may use the brute-forcing attack.  

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import long_to_bytes
from binascii import hexlify, unhexlify
import random

key = "very_awes0m3_k3y"
flag = "FwordCTF{aah_i_a2b_abfc8ed!kolae_ngbom___f_9525eg__ihedpmertt}" #REDACTED
fla2 = "FwordCTF{helloworldmynameisyeonandmyicecreamissooooweet!!!jas}"
assert len(flag) == 62
assert len(key) == 16

enc = """
3ce29d5f8d646d853b5f6677a564aec6bd1c9f0cbfac0af73fb5cfb446e08cfec5a261ec050f6f30d9f1dfd85a9df87
5168851e1a111a9d9bfdbab238ce4a4eb3b4f8e0db42e0a5af305105834605f90621940e3f801e0e4e0ca401ff451f1
983701831243df999cfaf40b4ac50599de5c87cd68857980a037682b4dbfa1d26c949e743f8d77549c5991c8e1f21d8
91a1ac87166d3074e4859a26954d725ed4f2332a8b326f4634810a24f1908945052bfd0181ff801b1d3a0bc535df622
a299a9666de40dfba06a684a4db213f28f3471ba7059bcbdc042fd45c58ae4970f53fb808143eaa9ec6cf35339c58fa
12efa18728eb426a2fcb0234d8539c0628c49b416c0963a33e6a0b91e7733b42f29900921626bba03e76b1911d20728
254b84f38a2ce12ec5d98a2fa3201522aa17d6972fe7c04f1f64c9fd4623583cc5a91cc471a13d6ab9b0903704727d1
eb987fd5d59b5757babb92758e06d2f12fd7e32d66fe9e3b9d11cd93b11beb70c66b57af71787457c78ff152ff4bd63
a83ef894c1f01ae476253cbef154701f07cc7e0e16f7eede0c8fa2d5a5dd5624caa5408ca74b4b8c8f847ba570023b4
81c6ec642dac634c112ae9fec3cbd59e1d2f84f56282cb74a3ac6152c32c671190e2f4c14704ed9bbe74eaafc3ce278
49533141e9642c91a7bf846848d7fbfcd839c2ca3b
""".replace("\n", "")

def to_blocks(text):
        return [text[i*2:(i+1)*2].encode() for i in range(len(text)//2)]

def random_bytes(seed):
        random.seed(seed)
        return long_to_bytes(random.getrandbits(8*16))

def encrypt_block(block,key):
        cipher = AES.new(key.encode(), AES.MODE_ECB)
        plain_pad = pad(block, 16)
        return hexlify(cipher.encrypt(plain_pad)).decode()

def decrypt_block(block, key):
        cipher = AES.new(key.encode(), AES.MODE_ECB)
        dec = cipher.decrypt(block)
        return dec[0:2]

def encrypt(txt, key):
        res = ""
        blocks = to_blocks(txt)
        for block in blocks:
                enc_block = encrypt_block(block, key)
                res += enc_block
        return res

def decrypt(txt, key):
        res = ""
        dec = unhexlify(txt)
        for i in range(0, len(dec), 16):
            result = decrypt_block(dec[i:i+16], key)
            res += result.decode("utf-8")
        return res

def translate(txt,l,r):
        return txt[:l]+txt[r:]+txt[l:r]

def detranslate(txt,l,r):
        return txt[:l]+txt[len(txt)-(r-l):]+txt[l:len(txt)-(r-l)]

def real_shuffle(txt):
            seed=random.choice(txt)
            random.seed(seed)
            for _ in range(45):
                l = random.randint(0, 15)
                r = random.randint(l+1, 33)
                txt = translate(txt, l, r)
            return txt

def deshuffle(txt):
    for i in range(len(txt)):
        value = txt
        random.seed(value[i])
        arr = [0] * 45
        for _ in range(45):
                l = random.randint(0, 15)
                r = random.randint(l+1, 33)
                arr[_] = [l, r]
        for _ in range(45):
            value = detranslate(value, arr[len(arr) - 1 - _][0], arr[len(arr) - 1 - _][1])
        print(value)

def get_enc(txt, key):
    flag_ = real_shuffle(txt)
    return encrypt(flag_, key)

#encrypt("FwordCTF{aaaaaa}", key)
#raw_input()
#enc_flag = get_enc(fla2, key)
#print("===========================")
#deshuffle(decrypt(enc_flag, key))
#input()
#print(enc)
enc_shuffled = decrypt(enc, key)
#print(enc_shuffled)
#raw_input()
deshuffle(enc_shuffled)
```

Flag : FwordCTF{peekaboo_i_am_the_flag_!_i_am_the_danger_52592bbfcd8}