### General Notes

![[Cribl Products, pic1.png]]

Cribl Edge: Part of the [[Data Management]] Discovery phase.
- A lightweight agent deployed directly on the data source — edge nodes, servers, [[Docker|containers]], [[Kubernetes|Kubernetes pods]], or VMs.
- Gathers and auto-discovers data at the source it is deployed on, including [[Logs|log files]], metrics, syslog streams, and Windows events.
- Provides a centralized view of all deployed agents across the environment.
- Auto-discovery identifies the relevant log files and data streams that need to be collected.
- Can forward collected data to any destination for downstream processing — typically Cribl Stream.

[[Stream]]: Part of the [[Data Management]] Processing phase.
- The core data engine for processing machine data (logs, events, metrics) in real time.
- Operates via configurable pipelines that apply functions to transform data as it flows through — see [[Supporting Tech]] for the JS functions and Regex used inside pipelines.
- Supports any type of source: streaming, non-streaming, queues, pub/sub, and agents.
- Schema-agnostic — works on events without requiring a strict schema, making it flexible across all data types.
- Key pipeline capabilities: routing data to different destinations, reducing data volume, masking sensitive fields, and enriching events with metadata.
- Delivers processed data to any chosen platform or destination.

Cribl Lake: Part of the [[Data Management]] Storing phase.
- Stores data in an open, non-proprietary format (e.g., Parquet) to avoid vendor lock-in and ensure long-term accessibility.
- Zero-configuration setup with automated provisioning — no manual schema or index management required.
- BYOS (Bring Your Own Storage) option allows connecting S3-compatible storage (e.g., [[Simple Storage Service (S3)|AWS S3]], MinIO). Alternatively, Cribl can manage the storage entirely.
- Tiered storage design allows hot, warm, and cold data to be stored cost-effectively based on access frequency.

Cribl Search: Part of the [[Data Management]] Exploring phase.
- Federated search engine that queries data in place without requiring ingestion into a separate analytics platform.
- Can explore data across Cribl Lake, object stores, and other sources simultaneously.
- Uses KQL as the default query language — see [[Supporting Tech]] for query syntax and examples.
- Allows pushing results or curated datasets to a [[SIEM]] for alerting and correlation.
- Enables ad-hoc analysis without the cost and latency of full data ingestion.

Cribl Cloud:
- The managed SaaS platform that bundles Edge, Stream, Lake, and Search into a single offering — no infrastructure setup required.
- Hybrid architecture: supports a mix of worker nodes running on-premises and worker nodes in the cloud, offering flexibility based on data residency, latency, and compliance needs.
- Built-in high availability and scalability are managed by Cribl, reducing operational overhead.
- Comes with Search included by default.

---
### Access

Cribl Members: Assigning roles and permissions across the products above.

Access Levels (hierarchical — follows a least-privilege model designed to support multi-team organizations):
- **Organization**: The top-level deployment encompassing the entire suite of Cribl products.
- **Product**: Scoped to a specific product (Stream, Edge, Search, Lake).
- **Group/Fleet**: Worker Groups in Stream or Fleets in Edge — a logical grouping of processing nodes.
- **Resource**: Fine-grained scope such as a Stream Project, Search Dataset, Dataset Provider, etc.

Roles & Permissions:
- **Organization roles**: User, Admin, or Owner.
  - A member must have at least the User role at the Organization level to gain access to any product.
- **User**: Most basic role. At the product level, makes a member assignable to worker groups or specific resources.
- **Read Only**: Allows support personnel to view configurations without modifying them — useful for troubleshooting without risk.
- **Editor**: Can modify configurations and commit changes, but cannot deploy to the live environment.
- **Admin**: Full superuser access — can modify, commit, and deploy configurations.

---
