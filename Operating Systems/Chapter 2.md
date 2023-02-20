
>the architecture defines the main structure that imposes restrictions on how the design could be adaptable
>To understand the architecture:
> look at the services it needs to serve, it needs to operate
> Look at the os user perspective and Os designer perspective

>Be able to support programs running on multiple modes of concurrency
>Support IO, file management, ...
>Ensure the efficient operation of the system in resource allocation, accounting and security

> There must be proper mechanisms to raise exceptions when failures occur, to detect and properly report what happened.
> There must be logs kept that record everything that happenss with the CPU, regarding users and processes.

>fairness of processes

>System programs are programs that get bundled with the OS: compilers, linkers, ...
>System calls are abstracted into an API.
>The call enters the API, it then checks the level of permission to be turned into an interrupt. 
>Parameters are passed there to transfer data using mapping

>systems are now structured, maintainable and dynamic
>The os should be convenient, easy, reliable, safe, and fast

> mechanism is how you will do something
> policy is what needs to be done

>the no structure meant that all systems and drivers had to be loaded in RAM, or else it wont start
>Dijkstra 3amal layered system where each set of functions were separated into modules. The kernel is composed of layers
>the drawback is that u cant bypass another layer, so it wasnt very efficient 
>unix is not layered

>microkernel architectures, uses messages and not APIs to run system calls. (happens inside the microkernel)
>have the OS load only the services that are needed by the users, allowing the oS to dynamically download or offload the needed or undeeded services/devices.
>These devices needed are downloaded into the user space, not in kernel space

>CPU's run in multiple mode of operation, we need more levels of execution
>the privilege levels are separated into many levels, separated into rings of priority or privilege
>Device drivers should have the ability to change privileges, into kernel mode, but they will still run in user space

> the messages are sent from driver to driver aftr checking the buffer and making sure that there is space in the buffer
> It is a slow mechanism due to the large amount of context switches

>new mechanism used requires only the first message to use 4 context switches.
>After that, a gateway is established between the 2 drivers, causing messages to be direct not involving the kernel.