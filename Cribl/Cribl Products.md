### General Notes

Cribl Edge: Part of the Discovery process
- Gathers and autodiscovers data the source it is deployed on.
- Centralized view with all the deployed agents.
- Autodiscovery allows discovering the log files needed.
- Can then send the data to any destination for processing.

Cribl Stream: Part of the Processing.
- data engine 
- can process machine data (logs, data, metrics)
- real time
- to deliver data to any chosen platform.
- Can send data from any type of source (streaming, non streaming, queues, pub/sub, agents)
- Schema agnostic, so it works on events without a strict schema.

Cribl Lake: Part of the storing process.
- Store the data in the lake in an open non prop format.
- zero configuration with automated provisioning.
- can enable BYOS (bring your own storage) or have cribl manage the storage.

Cribl Search: Part of the exploring process.
- search through data.
- search in place to see the data 
- Can explore data in place to check what data is in place
- Push the data to a SIEM
- Analyze the data, no need to ingest into a system of analysis.

Cribl CLoud:
- SAAS platform offering all the above to run immediately.
- Hyrid worker nodes on prem andworker nodes on the cloud
- flexibility depdning on needs and high availability
- Comes with search.

---
### Access

Cribl Members: Assining roles & permissions to the products above.

Access Levels:
- Organization (the deployment of a whole suite of cribl products)
- Product (stream, edge, search, lake)
- Group/Fleet (Worker groups in Stream or Fleets on the Edge)
- Resource (Stream Project, Search Dataset, Dataset Provider, etc..)

Roles & Permissions:
- Organization: user, admin, or owner.
- Must be user in organization to get access to product level.
- User: Most basic. At product level, makes member assignable to worker groups or resources.
- Read Only: Enable support personnel to help other users by viewing their configs but not modifying.
- Editor: Can modify configurations and commit changes without deploying.
- Admin: Superuser.

---
