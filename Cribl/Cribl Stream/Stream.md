### General Notes

Cribl Stream allows users to route data from any source to any destination.
- Can obtain data from any source and send it to any destination.
- Can perform processing on data in transit — see [[Pipelines, Functions, Packs]] and [[Routes]].
- [[Cribl Products#Cribl Edge|Cribl Edge]] can help send the data to Cribl Stream, or straight to the destination.
- [[Cribl Products#Cribl Search|Cribl Search]] allows searching on Cribl Edge or at the destination.
##### Cribl Stream Deployments - Check [[Architecture]]
- **Single Mode**: Run the leader node and worker node on single machine. Test environment.
- **Distributed Mode**: leader node and worker nodes are on diff machines. One leader node manages worker nodes present in worker groups.
##### Worker Groups
Worker Groups are a set of worker nodes that share the same configuration.
- A group of machines that work together to process data.
- Worker groups are logical groupings of worker nodes that share the same configuration.
- Each worker group has its own configuration, but all the nodes in 1 worker group share the same configuration.
- Groups can be separated by location, data type, function, or dedicated processing workflows
- A worker group can have any number of worker nodes.

The worker nodes do a lot of stuff, including:
- Reporting metrics to the leader node
- Receiving from push based sources
- Collecting from pull based sources
- Pushing results to destinations
- Handles all data processing
##### Worker Process
A worker node has many worker processes operating inside, where data coming from a single connection is operated on entirely by a single worker process.
- As a result, data should come over multiple connections, so multiple processes spawn and handle data at the same time.
- Processes do not know about each other.
##### Mapping Ruleset
A **Mapping Ruleset** is used to map the *workers* to their designated *worker groups* using a set of filters. 
- A ruleset has a list of rules that are matched against, and it works based on a first match wins algorithm.
- Only 1 can be active at a time.
- It evaluates filter expressions on the worker heartbeat payloads.
##### Leader Node
A leader node manages all the configs for the worker groups and [[Edge]] nodes, and sends the config information.
- Comm takes place by sending configs on how to collect data based on rules.
- The leader communicates via TCP [[Port]] `4200`. This is used for heartbeats, metrics, and notification communications.
- Also uses [[HTTP]] port 4200 to download bundles and configuration distribution.
- Port 443 is done through Cribl Cloud.

The leader does a lot of work, so it should be maintained and have the necessary processing power and resources to manage the traffic. It is responsible for:
- Hosting the GUI that is used to expose the APIs used for interaction with the stream deployment.
- Managing authentication & enforcing RBAC permissions
- Configuring the workers and handling the worker queue. It is the configuration source for all pipelines, routes, sources, .... 
- Holds the state of pull sources, that is, which files have been collected and to maintain state to ensure no repetition.
- Supports disaster recovery services and fault tolerance using git and others. Check out [[Architecture#Fault Tolerance & Reliability|Fault Tolerance]].

##### Stream Directory Structure

![[Stream, 5.png]]

---
### Stream Projects & Teams

This is used to ensure fine grained role based access control and necessary security permissions. This is used for least privileged access.
- **Teams** are logical groupings of users, where users can get assigned permissions through their team. Teams only exist in distributed deployments or [[Cribl Cloud]], not single-instance.
- **Projects** define what data a scoped group can consume (via its Subscriptions), where that data can go (its Destinations), and who's allowed to touch it.
- Each team gets secure access to its own data, and one team's transformations and config changes don't affect the other team's data or configs.

All the permissions that can be assigned are:
- **Admin**: Full access
- **Editor**: Can modify resources within the worker group
- **Read Only**: Has read only access to resources within the worker group
- **User**: Has no access until something is shared with them.

Gives administrators the ability to control access to data.
- Creates isolated spaces for teams and users to access data.
- Each project grants access to sources, destinations, pipelines, and more.
- Projects are scoped to a worker group.

**Project Editors**:
- Can adjust the data flow for the entire project.
- Can configure objects and commit changes to git.

**Cribl Admin**:
- Can create subscriptions and projects.
- Provides users with access to different projects.

**Subscriptions**
- This is a subset of data that is used by a team. It takes a unique ID.
- Specify a subset of a worker group's data using filters and pre-processing pipelines.
- Multiple subscriptions can be assigned to a single project.
- A Subscription must always specify a pre-processing pipeline.
- For the team to be able to use that subscription, it needs to be assigned as a *user* in that worker group.

**Data Projects**
- Connections between subscriptions and destinations.
- Multiple subscriptions and multiple destinations can be combined in one project.
- Projects ensure that teams get access to the data they need without affecting the other teams.
- Teams should be given the necessary access to the project to be able to use. This includes read only, editor, maintainer (assigned when admin or editor worker group), or no access.

---
### Stream CLI

This command line interface is used to perform some automations and more.
- Check the reference documentation here : [CLI Reference](https://docs.cribl.io/stream/cli-reference/).

> If `systemd` or `initd` is used to start/stop Stream, then use these commands and not the cribl native commands.

The diagnostic folder created through the CLI has these contents:

![[Stream, 3.png]]

---
### Stream Logs

Stream generates logs for both leader nodes and worker nodes.
- These can be viewed from the *Monitoring* tab.
- Logging levels can be adjusted to change the type of data that is shown.
- Can also redact information from the logs if needed.

> To enable internal logs, enable them from the Cribl internal [[Sources]] and check the enabled toggle.

The leader node cannot collect and send out its own logs and forward them.
- An agent needs to be deployed on the leader node to collect the logs.

For the leader node, which takes place in the main process in `$CRIBL_HOME/log/directory`. The main API process is the one that generates these logs.
- `cribl.log` - The principal log in Stream, including license validation logs.
- `access.log` - Has all the API calls.
- `audit.log` - Actions related to files, so creating updating committing deploying and deleting.
- `notifications.log` - Messages that appear in the notification list
- `ui-access.log` - This has the interactions with the different components in the UI written as URLs.

For the worker nodes, the main API log also generates logs, as well as the worker processes present in `$CRIBL_HOME/log/worker/[WP#]/directory`.
- `cribl.log` by the API process has messages about the workers communication with the leader node.
- `cribl.log` by the worker process has the worker process data itself.

---
### Upgrading Stream

To upgrade, the leader node is upgraded first, then follows the worker nodes.
- After the upgrade, it should be validated, and then use git to commit and deploy the configuration changes from leader to worker nodes.
- This is because some default files are modified due to the upgrade.

During an upgrade:
- Default files get overwritten, so any modifications need to be done again.
- Any custom functions should be moved to `$CRIBL_HOME/local/cribl/functions/`

---
