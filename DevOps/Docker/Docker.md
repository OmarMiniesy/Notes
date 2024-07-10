
### General Notes

Docker manages everything that needs to run in a working environment and places it inside a container.

> A container is an isolated environment that contains all dependancies and libraries needed to run an application.

Virtual machines solve the same issues, but:
1. has its own operating system.
2. use more memory and resources.

[Installation Process](https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository).

---
### [[Image]]

These are blueprints used for containers, they contain:
* runtime environment.
* application code.
* dependencies.
* configuration and environment variables.

> Images are read-only. Once they are created, they cannot be changed.

These images can be shared, and regardless of what is installed on the recipient computer, the image defines all what it needs and is contained inside it. The container is what runs this image.

---
### [[Container]]

Runnable instances of [[Image]]. 

> A container is a process which runs our application outlined by the image.

Containers are independent processes, and they are isolated from other process on the computer.

---
