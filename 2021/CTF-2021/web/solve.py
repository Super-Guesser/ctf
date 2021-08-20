import requests
import json
import random
from base64 import b64decode as b_d 
from base64 import b64encode as b_e
import string

# url = "http://52.149.144.45:8080"
url = "http://127.0.0.1:8081"

def random_str(N):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(N))


def register_user(user, passw):
    
    """username=smug3&password=smug"""
    """POST /user/register HTTP/1.1"""

    res = requests.post(url + "/user/register", data={"username":user, "password":passw})
    b = json.loads(res.text)
    return b


def login(user, passw):
    """username=smug3&password=smug"""
    """POST /user/login HTTP/1.1"""

    res = requests.post(url + "/user/login", data={"username":user, "password":passw})
    b = json.loads(res.text)
    return b


def buy_lottery(api_token):
    """POST /lottery/buy HTTP/1.1"""
    """api_token=llTQDfxFggk7ESmUkWsfmoxMt7WWt3Xl"""

    res = requests.post(url + "/lottery/buy", data={"api_token":api_token})
    b = json.loads(res.text)
    return b["enc"]

def charge(userid, enc):
    """POST /lottery/charge HTTP/1.1"""
    """user=805abf15-6394-48f5-bcef-b864bcc3ed83&coin=63&enc=WygBlFNmrgHZhWBCO3KzjYLqxBSNPG17fhELNVKvthzReLw7WLZ1UhT%2BW2sCsI9TIaXIbvsuPqnuJ0Fs0vwYGG%2B2AwUQsLKqfJdgyFnqg7eJigLXjyBrnrI56NKlD3iaWCHxkEvg3avOdbBMvsoa90rUIuoWZxuGwSJ0pvmVkbU%3D"""

    res = requests.post(url + "/lottery/charge", data={"user":userid, "enc":enc})
    return 


my_real_user_name = "smugomega" + random_str(4)
my_real_user_pass = "smugomega"


register_user(my_real_user_name, my_real_user_pass)
real_user = login(my_real_user_name, my_real_user_pass)

print (real_user)
print (real_user['user']['api_token'])
real_user_id = real_user['user']['uuid']
_decoded = b_d(buy_lottery(real_user['user']['api_token']))
_enc_1 = _decoded[0:32]
_enc_2 = _decoded[32 : 32*2]
_enc_3 = _decoded[32*2: 32*3]
_enc_4 = _decoded[ 32*3 : 32*4]



for i in range(100):
    new_user_name = "ristu"+random_str(5)
    register_user(new_user_name, "test")
    new_user = login(new_user_name, "test")
    new_user_token = new_user['user']['api_token']
    
    for j in range(3):
        enc = buy_lottery(new_user_token)
        decoded = b_d(enc)
        
        enc_1 = decoded[0:32]
        enc_2 = decoded[32 : 32*2]
        enc_3 = decoded[32*2: 32*3]
        enc_4 = decoded[ 32*3 : 32*4]

        n_p = b_e(enc_1 + enc_2 + _enc_2 + _enc_3 + enc_4)
        charge(real_user_id, n_p)

        
        







