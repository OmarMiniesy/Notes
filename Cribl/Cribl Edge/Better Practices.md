
![[Better Practices, 1.png]]


![[Better Practices, 2.png]]


![[Better Practices, 3.png]]


![[Better Practices, 4.png]]


---

- **Core Dump Creation:** Disable core dump creation when using Edge on Linux or in Kubernetes environments to avoid storage issues in case of container crashes.

Explore function is used to verify access to log files.

regulary updating cribl edge software and maintaining strong passwords is important for cribl edge

increase hash length needed when files are similar at the begining.

docker deployment: - **Host IP:** Ensure the host IP is set to 0.0.0.0 to avoid blocking health checks.

Kubernetes Logging:
- **Application Logs:** Provide insights into application behavior, aiding debugging and activity monitoring.
- **Cluster-Level Logging:** Ensures separate storage and lifecycle for logs independent of nodes, pods, or containers.
- **Logging Agents:** Dedicated tools that expose or push logs to a backend system. Cribl Edge utilizes DaemonSets for node-level logging efficiency.
**Alternative Logging Options:**
- Sidecar containers for dedicated in-pod logging.
- Direct log pushing from applications to a backend.