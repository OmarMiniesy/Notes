### Sources

Edge can receive continuous data from many sources:
- **Push Sources**: Allow collecting data from closer to where it resides on the edge, examples are [[HTTP]], TCP-JSON, and more.
- **System & Internal**: Unique to Edge, allow collecting from the local machine and running commands on it using `exec`. `File Monitor` can also be used to collect [[Logs|log files]] and generates events based on the log entries there.

*Linux Sources*:
- **System Metrics**: Allows collecting metric data from the device.
- **Journal Files**: Central location for all messages logged by different components and stored in `systemd`.

*Windows Sources*:
- **[[Windows Events Log|Windows Event Logs]]**: Collects log data from the Windows Event Log subsystem.
- **Windows Metrics**: Collects metrics data from the device.

*[[Kubernetes]] Sources*:
- **Kubernetes Logs**: Collects container logs and system logs from containers.
- **Kubernetes Events**: Collects events from the Kubernetes Cluster.
- **Kubernetes Metrics**: Periodic generations based on the status and configuration of the cluster.

### Destinations

Cribl HTTP and Cribl TCP are destinations that can be used to send data from Edge to [[Stream]].
- These can be used to send to the Worker nodes as long as all nodes are connected to the same leader.
- Cribl TCP is easier to implement, TCP pinning can occur.
- Cribl HTTP does not face this issue.

The two destinations are:
- **Cribl HTTP:** Enables Edge nodes to send data to Cribl Stream worker nodes in distributed deployments with load balancers. Ideal for larger environments. Useful in hybrid cloud deployments for optimized billing
- **Cribl TCP:** Recommended for medium-sized, on-premise deployments. It's faster and simpler to deploy than Cribl HTTP. Use this option when [[Firewall]]s or proxies allow raw TCP egress