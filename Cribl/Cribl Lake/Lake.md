### General Notes

Cribl Lake is a managed cloud data lake built specifically for IT and security telemetry. It is part of the [[Data Management]] Storing phase — see [[Cribl Products]] for where Lake fits in the broader product lineup.
- Stores data in open, non-proprietary formats (JSON, Parquet, DDSS) to prevent vendor lock-in and ensure long-term accessibility.
- Schema-on-need: no pre-defined schema is required before ingesting data. This reduces storage costs by keeping raw data in inexpensive storage.
- Accepts any telemetry format — raw, structured, or unstructured — from any source.
- Integrates natively with [[Stream]] (pipeline ingestion and replay), [[Cribl Products#Cribl Edge|Cribl Edge]] (distributed edge ingestion), and [[Cribl Products#Cribl Search|Cribl Search]] (federated querying at rest).
- A free tier is available with 50 GB of storage.

> Referenced in the [Cribl Certified User (Level 1)](https://certifications.cribl.io/group/359630) curriculum under the Lake component — covering storage configuration, dataset management, ingestion paths, and Lakehouse-accelerated search. Full documentation: [docs.cribl.io/lake](https://docs.cribl.io/lake/).

---
### Datasets

Datasets are the primary organizational unit inside Cribl Lake — each dataset is a named container for a specific type of telemetry data.
- A workspace supports up to **200 Lake Datasets**. Additional capacity requires contacting Cribl Support.
- Supported storage formats per dataset:
	- **JSON**: Human-readable; recommended for initial exploration and flexibility.
	- **Parquet**: Columnar binary format; optimized for analytical queries and reduced storage costs.
	- **DDSS**: Used for Splunk Cloud Self Storage (Splunk Dynamic Data Self Storage) integration.

**Default Datasets** ship pre-configured with Cribl Lake and cannot be edited or deleted:

| Dataset | Retention |
|---|---|
| `default_logs` | 30 days |
| `default_metrics` | 15 days |
| `default_spans` | 10 days |
| `default_events` | 30 days |
| `cribl_metrics` | 30 days (read-only) |
| `cribl_logs` | 30 days (read-only) |

- `cribl_metrics` and `cribl_logs` are internal Cribl datasets and cannot be used as a destination target.

**Custom Datasets** can be created with retention configured up to **10 years**.
- When a dataset is linked to a Lakehouse, cached data retention extends up to **365 days**.
- Retention is calculated from the **upload date**, not from the timestamp of the individual events stored. This matters for batch uploads of historical data — old events uploaded today will expire based on today's date.

---
### Storage Locations (BYOS)

BYOS (Bring Your Own Storage) allows an organization to back a dataset with an S3 bucket they own directly, maintaining data ownership for compliance and data residency requirements while still using Cribl's management interface.

- Only **[[Simple Storage Service (S3)|Amazon S3]]** is supported. Other S3-compatible stores (MinIO, etc.) are not supported for BYOS.
- One bucket per Storage Location.

**Configuration approaches:**
- **Recommended**: Configure initial settings in the Lake UI, then Cribl generates a **CloudFormation template** to deploy the required IAM roles and bucket policies in AWS.
- **Manual**: Advanced users can create the S3 bucket and IAM role directly in AWS and provide the ARN to Cribl.

**Authentication**: Cribl Lake uses **STS Assume Role** to access buckets. The trust policy must authorize Cribl's Lake admin role, Stream Worker Group roles, and the Search execution role.

**Supported AWS Regions:**
- US East (N. Virginia, Ohio)
- US West (Oregon)
- Canada (Central)
- Europe (Frankfurt, London, Zurich)
- Asia Pacific (Singapore, Sydney)
- FedRAMP Moderate deployments: `us-east-1`, `us-east-2`, `us-west-2` only.

**BYOS Limitations:**
- No Direct Access support for BYOS-backed datasets.
- BYOS datasets cannot be linked to a Lakehouse.
- Data uploaded directly to the S3 bucket outside of Cribl is not visible to Cribl Search or Stream.

---
### Lakehouse

A Lakehouse is a caching layer on top of a Lake Dataset that accelerates search performance.
- Temporarily stores frequently accessed data for fast retrieval, reducing the cost and latency of full dataset scans.
- When data ages out of the Lakehouse cache, it remains searchable in the underlying Dataset until that dataset's own retention expires.
- A single Lakehouse can link **multiple** Lake Datasets.

**Capacity tiers** (sized by expected ingest volume per day):

| Tier | Ingest Capacity |
|---|---|
| Small | 600 GB/day |
| Medium | 1.2 TB/day |
| Large | 2.5 TB/day |
| XLarge | 5 TB/day |
| 2XLarge | 10 TB/day |
| 6XLarge | 28 TB/day |

- Resizing a Lakehouse is supported but temporarily disables cached searching during reprovisioning.
- **Mirrored Datasets** (linked at creation time) automatically populate the Lakehouse cache regardless of event timestamps.
- Datasets linked after creation only cache **future** ingestion — historical data is not backfilled into the cache.
- **Billing**: Lakehouse uses flat-rate billing, unlike standard Lake which bills on CPU credit usage per query.

> Cribl recommends migrating Lakehouse workloads to **Cribl Search lakehouse engines** for new deployments, as that is the forward-looking architecture.

---
### Ingestion

Data reaches Cribl Lake through several paths:

- **[[Stream]] → Lake Destination**: The most common path. Stream processes and shapes data through [[Pipelines, Functions, Packs|pipelines]], then sends it to Lake as a configured destination — see [[Sources, Destinations, Collectors]].
- **[[Cribl Products#Cribl Edge|Cribl Edge]] → Lake**: Edge nodes forward collected [[Logs|log]] and metric telemetry to Lake directly, or via Stream for processing first.
- **Direct Access**: Data can be written to Lake directly over HTTP without going through Stream, bypassing pipeline processing.
- **Cribl Lake Collector**: Used to pull data back out of Lake for replay — pointing Stream at the stored data to reprocess it.

---
### Search & Replay

- [[Cribl Products#Cribl Search|Cribl Search]] can query Lake datasets in place without requiring data to be moved or re-ingested into a separate platform. Uses KQL — see [[Supporting Tech]] for query syntax.
- **Replay**: Archived data in Lake can be replayed through any Stream pipeline and routed to any destination. Useful for reprocessing historical data, migrating to a new [[SIEM]], or backfilling a new tool. See [[Replay]] for replay best practices and S3 storage class compatibility.

---
### Access & Security

Access to Cribl Lake follows the same role hierarchy as all Cribl products — see the Access section in [[Cribl Products]] for the full role and permission model.
- Dataset-level access control allows users to be scoped to specific datasets rather than the entire Lake workspace.
- Data stored in open formats (Parquet, JSON) can be read directly by external tools that support those formats, independent of Cribl — supporting governance and auditability requirements described in [[Data Management]].
- [[Logs|Log]] and security data stored in Lake can feed [[SIEM]] workflows via Cribl Search queries or Stream replay, avoiding the cost of re-ingesting raw data into the SIEM directly.

---
