### General Notes

The capacity and power of the [[Stream]] instance can be upgraded in one of 2 ways, and it depends on the data impact and capacity requirements.
- **Upscaling**: This is by increasing the CPU and processing power of a single Stream system.
- **Outscaling**: This is by adding more instances of stream across multiple worker nodes.
- Both can be implemented.

Considering factors on the performance:
- The *volume* of data going in and going out. 
- The *amount* of data processing taking place. Transformations, extractions, parsing, obfuscations, ....
- The *availability/resilience* requirements of the deployment.
- The cloning, routing, and queueing that will be taking place.

> The recommended number of cores is: 400 GB per physical core and 200 GB per virtual CPU.

---
### Sizing Recommendations

The below shows the recommended sizing for cloud instances:

![[Scaling & Sizing, 1.png]]

The below shows the sizing recommendations for on prem instances:

**Number of Cores**:
- `400GB` of data per each physical core.
- `200GB` of data per each virtual CPU.

**Worker Nodes**:
- `+8` physical cores (`16` Virtual CPUs)
- `+32GB` of RAM (minimum of `8GB`)
- `+5GB` disk space free (more in the case of persistent queuing).

**Leader Node**: (lower requirements than worker nodes, worker has heavy node)
- `+4` physical cores (`8` Virtual CPUs)
- `+8GB` of RAM
- `+5GB` disk space free

These values still succumb to the following considerations:
- persistent queuing
- organizational constraints
- functional constraints
- security constraints
- high volume senders
- syslog

---
