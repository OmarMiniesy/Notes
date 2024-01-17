
### General Notes

> A blueprint that defines all what is needed to correctly run and operate a certain software.
> Images have their own folder structure and directories.
> Images are run inside [[Container]]s.

> Images are read-only. Once they are created, they cannot be changed.
#### Creating Images
> The [[Dockerfile]] has the instructions that creates the image.

---
### Architecture

Images are made of layers.

1. Parent image: includes the OS and the environment of the [[Container]]. This is another docker image by itself.
2. source code.
3. dependencies.
4. commands.

> Parent images can be found on [docker hub](https://hub.docker.com/).

---

### Running Images 

Running an image spawns a container. After an image is run for the first time, the options are saved. The container can then be run afterward simply by stating its name.

* To run an image:
```bash
docker run --name <container-name> -d <image-name>:<tag>
```
> the `--name` flag specifies the name of the container that we will spawn.
> The `image-name` is the name of an image that will be used to spawn this container. If it is not on the local machine it will be pulled from docker.hub.
> `-d` flag adds detached mode which doesn't block the terminal when the container is spun up.

* To map a [[Port]] from a container to that on a computer:
```bash
docker run -p <pc-port>:<container-port> <image-name>
```

---

### Using Images

* To download an image
```bash
docker pull <image-name>:<tag>
```

`tag` is used to specify a version of the `image` we are downloading. If we dont specify the `tag`, it automatically uses the `latest` tag.
> The `latest` tag simply means the latest version of that image.

* To list all downloaded images
```bash
docker image ls
```

* To delete an image
```bash
docker image rm <name>
```
> Can add the `-f` flag to force remove the image that is being used by a [[Container]]. 
> Deleting the container itself also deletes the image it is using.

---
