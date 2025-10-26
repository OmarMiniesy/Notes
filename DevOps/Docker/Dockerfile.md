
### General Notes

> The [[Docker]]file is a file that gives the instructions on how to create the [[Image]]. 

This dockerfile lists all of the different layers and instructions that are to be used while building the image.

> The dockerfile's name is only `Dockerfile` with no extensions.

---
### Building Images

* To create an image given its dockerfile:
```bash
docker build -t <image-name>:<tag> <path-to-dockerfile>
```
> Then `-t` flag is used to specify the name of the image.
> Can specify an optional `tag`.

---
### Dockerfile Commands

> This is the dockerfile reference: [docs](https://docs.docker.com/engine/reference/builder/).

These commands are placed in the dockerfile, and are the instructions that are used to build the docker image.

* `FROM <image:tag>` : This command is used to specify a parent image for our image. This is possibly an OS or an environment we want to run our application.
* `WORKDIR /<path>` : This command changes the working directory inside of the docker image itself. This command has an effect on all other commands after it in the dockerfile.
* `COPY <local-path> <image-path>` : This command copies files and directories from the local machine with a path relative to the docker file, and pastes it in the path specified inside the image.
* `RUN <command>` : This instruction executes the `<command>` *during the build time* of the image. *This is before the container is started.* This is usually used to download the dependencies.
* `EXPOSE <port>` : This command opens up a [[Port]] that the application inside the container will be listening on. This tells the container that the specified port will be used by the application defined in the image.
* `CMD ["<command>", "<command>", "..."]` : This instruction specifies default commands that are *executed at runtime*. *This is when the container first starts*.
> The `CMD` instruction has a different format. It is an array of strings, where each string is one word from the default command that is to be run.

The first command used is usually the `FROM` command to specify a parent image. After that, a `WORKDIR` is specified inside the image and then `COPY` is used. These two are used together to transfer the files and directories to the image. The `RUN` command is then used after to download all dependencies and needed libraries during build time. The `CMD` command then defines what happens when the container which uses the image to spawn. It is what the container first executes when it starts.

---
