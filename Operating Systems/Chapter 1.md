
#### General Stuff

> computer system organized in layers. Layered architecture is good because each layer shields details, allows evolving of a ceratin layer, and to achieve a certain goal or function. 

> machine language defines the architecture

> 85% of computer usage is created and used through the operating system.

> Some parts of the OS are not running at all times to allocate resources. 

> BIOS checks the hardware components on startup
> It then downloads the bootloader. The bootloader is downloaded based on charactersisitcs of each component. 
> Once the OS needed is decided, the kernel is then loaded for that OS into the memory.
> That kernel is then started so then the OS starts.

> system calls can be conducted in a synchronous(blocking) manner OR asynchronous(non-blocking). These are modes that exist for handling I/O .

> SISD, SIMD, MIMD

> Memory Management Unit (MMU)

> Multics is a blueprint for OS
> Talks about virtual memory, multiprocessing, virtual machines, 

---

#### P. 5-7

> OS objectives and definition in slides
> the os is a software that controls the common functions and allocates the resources.
> the os is the one program running at all times(kernel)

> kernel is part of the OS that is running at all times, the most used functionalities being used.
> can be static or dynamic to grow and shrink 

> middleware are a part of the OS that provide additional services to developers

```
summary, for our purposes, the operating system includes the always running kernel, middleware frameworks that ease application development and provide features, and system programs that aid in managing the system while it is running
```

---
#### P.7

> A device controller is in charge of a specific type of device. The driver maintains local buffer storage and a set of registers. Responsible for moving data between peripheral devices and local buffer storage for that device.

> A device driver is present for each controller that gives the OS with a uniform method to interface with that device

---
#### P. 8-10

> all controllers can access the data bus which is bad, leading to data scrambling
> the bus has a protocol called bus master that the contollers decide about which happens during a data collision

> Parallel operating devices to notify cpu can use interrupt driven operation

>after fetch execute cycle, check for interrupts
>the interrupt controller chip specificies interrupt priorities

> PSW -> flag register
> enable or disable interrupts can be set by a bit in the flag register

>interrupt vector starts at address 0 and every slot holds the address of the interrupt, accessible using offset. The pc then changes and becomes the value of that interrupt address.
>the interrupt vector shouldnt be accessible, must be protected
>Interrupts shouldnt interrupt interrupts that interrupt interrups, 

> Then resume operation of the interrupted operation by popping that pc from the stack

> Masked interrupts can wait
> Non-masked interrupts cannot wait, they must given priority

---
#### P. 23 -24

> use multiprogramming to reduce idle/wait time and increase utilization of the processor
> happens by running more than one application in parallel, each job(application) has its own dedicated address space.
> interrupt driven operation

> timesharing is quickly shifting between one app and another to make the user sense all applications are running at the same time 
> virtual concurrency: every app thinks it is the sole user of the machine, virtual parallelism
> swapping process.
> virtual memory to run processes whoese memory usage is larger than the physical memory

---
#### P. 24 -25

> the os is the only thing that can send instructions to the hardware
> Privelaged instructions are those that can be executed only by OS
> general instructions can be executed by any
> This instruction type can be checked in the fetch and execute cycle 
> There is a mode bit, it is set to 0 if it is the OS, otherwise it is in user mode.
> If the user tries to execute a privelaged instruction, the fetch cycle stops and sends an interrupt
> When an interrupt is issued, the mode bit is set to superuser

---

#### Process Management

> A process is a program in execution
> A process can be active and inactive
> They can be active but passive to save resources, and because they need to be up because we dont want to wait for them to startup. THey are already up, but they are dormant. We need them to react fast.
> Terminating process leads to reclaiming the resources that were used

---

>If there exist multiple processes all of which are blocked, they have resourrces and are waiting for other resources. But these resources are owned by their peers in their same place. This is called a deadlock.

---
#### P. 26

> A process is assigned a time slot. During that time it is given the cpu. Once it issues an IO request, the os then gets hold of the resources. However, if the timer exceeds, the os regains control through an interrupt.

---

> Processes are normally single threaded. They can be multi-threaded
> Interleave IO with processing has better performance(multiprogramming)
> Parallelizing applications will improve performance. This is multithreading.

> Important system calls to control processes in the slides (process management activities)

> Processes should have their memory managed by the OS (MMU)

> address space needed for the process.
> The os should also provide access to secondary storage 

> When a file is to opened: 
> A path is needed
> The access mode 
> The identity

> the virtual file system in linux handles all system calls to file management
> It has the NFS which handles mounted files from another device.
> It also has LP, BSD, WNP.

> to enforce protection. we need mechanisms and policies.
> give individuals specific IDs, as well create groups to ditinguish users. These groups help escalate privileges

> networks physically identifiy components and how these componentes are going to talk
> Hetrogenous networks.

> Client server
> Peer to peer

> VIrtualization 
> The vmm multiplexes the time and for non sharable resources like adress space, to the VM to manage it the way it wants. 
> It shares time between the VM's if the number of cpu cores is not enough.

>cloud computing