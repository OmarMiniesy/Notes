### General Notes

Pipelines sit after [[Routes]]. There are also optional pipelines that run outside the main routing flow:
- **Preprocessing**: Normalizes data before it reaches the routes.
- **Postprocessing**: Modifies or normalizes data after routing, before it is sent to the destinations.

Inside the pipelines, are *functions* that can be used to perform actions on the data and process it.
- There are also *packs* that are pre-configured configurations and actions that can be used directly to simplify making configurations and changes.

---
### Pipeline

A series of functions that execute in order.
- Data events that are taken in via the route are sent to the pipeline, where functions start to act on it in order.

> Copilot Editor can help in generating pipelines.

Pipelines are mainly used in the *processing* phase of the [[Data Management]] lifecycle.
- *Transform the data*: Improving the quality of the data and adding additional context.
- *Secure the data*: Redacting sensitive data and masking PII.
- *Route the data*: Send data to destinations based on their needs, so to storage or analysis locations.
- *Replay the data*: To replay the data from the long term storage through the pipeline and then to the location of choice.

##### Types of Pipelines

Creating multiple pipelines for different datasets is more efficient than creating 1 big pipeline.
- Moreover, filtering at the beginning removes data that will not be processed to move on, making it faster.
- It is not good practice to use the same pipeline for both pre & post processing.

**Pre-processing**: This is used to normalize events at the [[Sources]].
- Before sending it off to be processed.
- Can be used to remove redundant fields, enforce certain log shapes, so on.
- *Optional.*

**Processing**: The one that attaches to [[Routes]] to do most of processing.
- Events get passed to the functions where the filter applies.

**Post-Processing**: This is used to normalize events before they are sent out to the [[Destinations]].
- Used to format the data before sending it to the final destination.
- Add certain columns that are needed at the end.
- This is destination specific, and is *optional*.

*Pipeline profiling* can be used to test the performance and efficiency of the pipelines before they are in production.

*Statistics* can be used to check how well the pipelines are functioning, by viewing the changes to events and fields.

---
### Function

Performs an action on the data it sees.
- A collection of functions is a pipeline.
- A function is a piece of JavaScript code that executes on an event — see [[Supporting Tech]] for JS syntax used inside functions.
- Functions can be configured with filters to match only the relevant events, including [[Regular Expressions|regex]]-based conditions.
- There is the Final Flag as well, similar to the one in the [[Routes]].
- Comments can be added for documentation.

> There are default functions that come with Cribl, with the full list [here](https://docs.cribl.io/stream/functions/).

Functions that are regularly used are:
- `Eval` - Evaluate Fields - Used to add fields, keep fields, or remove fields.
- `Parser` - Can be used to Extract key-value pairs from the `_raw` field, or can be used to re-serialize events. Can use filter expressions to choose which fields to keep. 
- `Lookup` - Used to enrich fields based on other information in other data sources. Exact matches are case sensitive. Results are added as fields by default.
- `Aggregations` - Used to apply statistical calculations on the data. 
- `Sampling` - Can be used to deduplicate data in a time window and choose the sampling ratio, which is the number of events that is deduplicated.
- `Mask` - Can be used to mask and replace data.
- `Regex Extract`

---
### Packs

Prebuilt configs created to allow users to share and use.
- This is a prebuilt file that can include the whole infrastructure necessary, or a few parts like a pipeline or a route and so on. 
- They can include sources, destinations, pipelines, routes, functions, sample data files, and knowledge objects.
- Can be installed directly and to be used easily.
- Can be added from the Cribl Packs Dispensary, [List of Packs](https://packs.cribl.io).

When [[Sources]] are included in packs, they do not come with the necessary [[Transport Layer Security (TLS)]] [[Certificates]], and they do not come with Quickconnect.
- This should be manually done.
- Moreover, some Sources are still not supported by Packs.

This is the structure of a Pack folder.

![[Pipelines, Functions, Packs, 1.png]]

When creating a Pack, these are good standards to follow:

![[Pipelines, Functions, Packs, 2.png]]

#### Pack Modifications

Changes should be made in the `local` directory because what is in the `local` directory will override the `default` directory.
- There is no concept of `local` directory inside the `data` directory, which includes the lookup files and the sample data files. This has the knowledge objects.
- Changes made to these files will be lost when the Pack is upgrade.
- To overcome this, create a new knowledge object and add whatever is needed there.

Changes made in a pack will be copied to the `local` directory.
- If changes are made anywhere, it will be placed in the `local` directory and then will override `default` on upgrade. 

If anything is to be deleted from a pack from the `default` folder, it will simply reappear on reload.
- To delete anything:
	- untar the pack in the CLI
	- delete the necessary things and update file references
	- Tar the pack contents again from within the pack folder.


---
