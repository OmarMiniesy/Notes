
### General Notes


Runnable instances of [[Image]]. 

> A container is a process which runs our application outlined by the image.

Containers are independant processes, and they are isolated from other process on the computer.

Can be run with [[Volumes]] to persist data, or to map data from the local machine to the computer.

---

#### Commands

* Start a new container from an Image:
```bash
docker run --name <container-name> -d -p <pc-port>:<container-port> <image-name>:<tag>
```
> `-d` is detached mode, which doesn't block the terminal.
> `-p` maps ports.

* Start a container that exists:
```bash
docker start <container-name> -d
```
> Will remember the options given when the container was first ran using `docker run` with the image.

* List all containers:
```bash
docker container ls -a
docker ps -a
```
> `-a` flag lists even the containers that are not running.
> Both commands do the same thing, since a container is a process.

* Delete all stopped containers:
```bash
docker container prune
```

* Delete a container
```bash
docker container rm <container-name>
```
> Can remove multiple containers by adding more than one name.

---

### Useful Tips

> To keep a container running even though it finished its task, add this command:
```bash
tail -f /dev/null
```



---