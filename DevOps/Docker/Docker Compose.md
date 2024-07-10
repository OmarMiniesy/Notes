### General Notes

A tool that manages multiple [[Container]]s and [[Volumes]] together and creates one environment combining all.

All the instructions are in the Docker Compose file, in `yaml` format.
> The Docker Compose file must be in the root directory of the project.
> The root directory then has the subfolders that contain the different containers that are to be spawned.

---

### The File; `docker-compose.yaml`

The structure of the file is organized such that each container is defined inside `service`.

> Each `service` has its own [[Image]], [[Volumes]], [[Port]]s, and configuration defined.
> They are all defined in one singular file, making creating a larger network of containers that communicate easier.

```yaml
version: <num>
services:
	<name>:
		build: <relative-path-to-folder-with-dockerfile>
		container-name: <name>
		ports:
			- <pc-port>:<container-port>
			- ...
		volumes:
			- <relative-path-to-local-file>:<path-in-container>
			- ...
		environment:
			-ENV_VAR: <value>
		command: "RUNS AFTER CONTAINER STARTS"
	<name-2>:
		...
volumes:
	<volume-name>:
```

Inside the services, there are `names`, or the name of the service we want created. Each `name` is basically a different [[Container]], with its build path, [[Dockerfile]] location, stated and all its related configuration.

To add volumes that persist between multiple containers, they are added in the `volumes` section, not in the volumes list underneath one of the services.

The command placed inside the services is executed after the container starts. It can either be a string command, or a location: `python3 ./app.py` .

> Multiple containers can be outlined in this singular compose file, making integration between containers an easier task.

---

### Commands

* To run the docker compose file, head to the directory where it exists:
```bash
docker compose up
```

* To stop the containers:
```bash
docker compose down --rmi all -v
```
> To remove all images and volumes, add the `--rmi all -v` flags at the end.

---
