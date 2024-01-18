
### General Notes

A feature of [[Docker]] that maps folders in our computer to folders in the [[Container]]. It also stores data across multiple containers. They are used to store data that should persist between container restarts.

---

### Volume Types

##### Host Volumes
> Reflects changes automatically from the local files to the container without having to rebuild the [[Image]] every time.

```bash
docker run --name <container-name> -v <absolute-path-pc>:<container-path> <image-name>:<tag>
```
> This maps the directory on the left to the container.

##### Named Volumes
> Volumes that are created and managed by docker.
> Accessed by multiple [[Container]]s.

```bash
docker volume create <name>
docker run --name <container-name> --mount type=volume,src=<name> <image-name>:<tag>
```
> Created a volume using the first command.
> Mounted that volume to that [[Container]]. Now, the data persists if this volume is used with another container, or if this container restarts.

##### Anonymous Volumes
> Created by [[Docker]] and are attached to containers when they are created.
> Not named, can't be reused.
> Doesn't need to be mapped to the container from the host.

```bash
docker run --name <container-name> -v <absolute-path-pc>:<container-path> -v <path> <image-name>:<tag>
```
> Specifying only a `path` with no mapping creates an anonymous volume.

---

### Commands

* To see what data is stored in a named volume:
```bash
docker volume inspect <name>
```

---
