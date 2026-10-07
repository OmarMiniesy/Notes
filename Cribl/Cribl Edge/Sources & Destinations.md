### Sources

Edge can receive continuous data from many sources:
- **Push Sources**: Allow collecting data from closer to where it resides on the edge, examples are [[HTTP]], TCP-JSON, and more.
- **System & Internal**: Unique to Edge, allow collecting from the local machine and running commands on it.

*Cribl Internal*: This is used to capture and send [[Edge]] logs and metrics.

*File Monitor* source can also be used to collect [[Logs|log files]] and generates events based on the log entries there.
- Some [[Securing Edge#Log Collection|Log Collection Permissions]] should be configured first.
- There is auto/manual mode in the GUI to discover files on the node.
- A discovery process runs to determine files, then there is a polling interval set to watch/monitor certain files present on an allow list. Current state is compared to saved state to determine updates and if the file will be updated after the interval.
- Auto mode discovers files as they are being written to. Only on Linux.
- Manual is the default mode, and the max depth can be used to find deeper files. Manual mode follows certain chosen directories. Used to collect files when the process that creates them rotates them.
- The Key Value store keeps track of the files monitored by this source. It is present at `$CRIBL_HOME/cribl-edge/state/kvstore/<fleet>/<input>`. These have a state file that has the file hashes and organizes them there. `/var/lib/cribl` directory at the edge node.
- The Idle timeout is used to close off file handles after a certain period of time of no changes.
- The Hash length is used to choose the length of the hash that uniquely identifies the file given the first set number of bytes. Changing the length of the hash might be needed for files of different types that need larger headers.

*Exec*: This is used to execute a command collect the output. Can be used to run anything.
- Used when it is hard to use current built edge sources, and custom requirements are needed.

*System State*: Captures the current state of the system and sends those out.
- Runs based on a configured interval or schedule.
- Only 1 can be run per node, or per fleet.

*Linux Sources*:
- **System Metrics**: Allows collecting metric data from the device.
- **Journal Files**: Central location for all messages logged by different components and stored in `systemd`.

*Windows Sources*:
- **[[Windows Events Log|Windows Event Logs]]**: Collects log data from the Windows Event Log subsystem.
	- Need to provide access by changing the permission in this [[Windows Registry]] key to `Read` - `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog`.
- **Windows Metrics**: Collects metrics data from the device.

> The `exec` source should be disabled on windows environments for security reasons. Run this command: `setx CRIBL_NOEXEC "1" /M`. 

*[[Kubernetes]] Sources*:
- **Kubernetes Logs**: Collects container logs and system logs from containers.
- **Kubernetes Events**: Collects events from the Kubernetes Cluster.
- **Kubernetes Metrics**: Periodic generations based on the status and configuration of the cluster.

---
### Destinations

Basic processing can be done on Edge, but not for huge processing. This is where sending data to Stream is useful.
- Basic functions like `drop` and `mask` are very useful to use on Edge.

Cribl Stream [[Sources]] need to be created, Cribl HTTP or Cribl TCP.
- Then we create the Cribl edge destinations, also Cribl HTTP or Cribl TCP.
- We can also use the **Disk Spool** destination, which is used to store recent evens on disk and can be searched using Cribl [[Search]]. This uses the `cribl_edge_spool` dataset.
	- In QuickConnect, we setup the source with disk spooling, and then connect to the `devnull` destination or any other of choice.
	- Search can then query the disk spooling configuration we made in the source.

Cribl HTTP and Cribl TCP are destinations that can be used to send data from Edge to [[Stream]].
- These can be used to send to the Worker nodes as long as all nodes are connected to the same leader.
- Cribl TCP is easier to implement, TCP pinning can occur.
- Cribl HTTP does not face this issue.

> There are also streaming and non-streaming destinations.

The two destinations are:
- **Cribl HTTP:** Enables Edge nodes to send data to Cribl Stream worker nodes in distributed deployments with load balancers. Ideal for larger environments. Useful in hybrid cloud deployments for optimized billing
- **Cribl TCP:** Recommended for medium-sized, on-premise deployments. It's faster and simpler to deploy than Cribl HTTP. Use this option when [[Firewall]]s or proxies allow raw TCP egress

---
