# XSP

## HOW TO SOLVE

1. Use CSRF to add an iframe to admin's notes 
2. Bruteforce the path of the admin's note with defining a CSP for 256 iframes.<br> 
Like for bruteforcing `xx` in following path:<br> `https://xsp.chal.perfect.blue/data/xx/`, we have to add 256 iframes with following format.<br>
```html
<iframe id="ITERATOR_HERE" csp="default-src 'none'; script-src https://xsp.chal.perfect.blue/notes.js https://xsp.chal.perfect.blue/data/ITERATOR_HERE/">
</iframe>
```
3. Iterate through iframes and find one which it's window's length is more than `0`, the right one has our bruteforced path part in it's id.

4. include the bruteforced script with a defined `notes_callback` function to get results.


