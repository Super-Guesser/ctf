## Challenge Description

Lottery come back again. Guessing is boring, so here is the code.

http://52.149.144.45:8080


## Solution

App uses AES-256 encryption in ECB mode. The following code show's attacking ECB mode encoded JSON.

JSON USER-1 = 
```
a1= {"lottery":"108abb0b-e3df-47e5-b
a2= 7c6-b977470ec0bb","user":"d747f1
a3= e9-55b9-4f95-a747-7cf16a9b6866",
a4= "coin":"34"}
```

JSON User-2 = 
```
b1={"lottery":"91ed6620-77d3-4f36-8
b2=74d-9763f9e3bb63","user":"6af3b3
b3=b7-3408-4f37-8869-318a55cca52a",
b4="coin":"7"}
```

New Key = a1+a2+b2+b3+b4


[solve.py](./solve.py)