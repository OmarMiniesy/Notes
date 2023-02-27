
### General Notes

> One of the [[NodeJs]] builtin [[Modules]]
> Used for creating web applications that listen on ports ad send and receive responses and requests
> [[Express Framework]] is used instead because it is better

---

### Creating a Server

```JavaScript
const http = require('http');
const server = http.createServer();

server.on("connection", (socket) => {
  console.log("connection established");
});

server.listen(3000);
```

Code that creates a server that listens on [[Port]] 3000. A connection is an event, and once it is established, the event is captured.


>Another way is to use function inside the server itself instead of using events
```JavaScript
const http = require('http');
const server = http.createServer((req, res) => {   //request and response
	//If this url is opened, webpage will display 'hello'.
	if(req.url === '/'){ 
	res.write('hello');
	res.end();
	}
	//if this url is opened, webpage will display numbers in json format
	if(req.url == '/mins'){
	res.write(JSON.stringify([1, 2, 3]))
	res.end()
	}
});

server.listen(3000);
```

> Uses the [[HTTP]] verbs and status codes.