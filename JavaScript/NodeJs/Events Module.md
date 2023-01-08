
### General Notes

> One of the built in [[NodeJs]] [[Modules]]
> Used in many other modules, such as the [[Express Framework]] framework, and the [[HTTP Module]]
> Contains an event emitter and an event reciever
```JavaScript
const EventEmitter = require("events");
const emitter = new EventEmitter();

// Register a listener
emitter.on("messageLogged", (arg) => {
  console.log("Listener called", arg);
});

// Raise an event
emitter.emit("messageLogged", { id: 1, url: "http://" });
```

>The emitter raises an event "messageLogged". The listener checks for the raised events, if it is the event "messageLogged",  a function is executed.
>The arguments contain an object 

---

### Using Classes 

> logger.js
```JavaScript
const EventEmitter = require("events");
const emitter = new EventEmitter();

class Logger extends EventEmitter{  //class that has all functionalities of events and more we define
	log(message){
		console.log(message);
		this.emit("Logged", {id: 1, url: "http://"})
	}
}

module.exports = Logger
```

> app.js
```JavaScript
const Logger = require("./logger.js");
const logger = new Logger();

logger.on("Logged", (arg) => {
	console.log("Listener Called", arg);
});

logger.log("message");
```

> Using a class to raise all events in logger.js and exporting the class
> Calling that class in the app.js module and instantiating it. Create a listener, and call for the function to raise an event.

