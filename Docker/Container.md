
### General Notes


Runnable instances of [[Images]]. 

> A container is a process which runs our application outlined by the image.

Containers are independant processes, and they are isolated from other process on the computer.

---

#### Commands

* Start a container:
```bash
docker start <container-name>
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
