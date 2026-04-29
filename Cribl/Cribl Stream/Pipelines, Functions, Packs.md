### General Notes

Pipelines are present after [[Routes]], there are optional pipelines:
- Preprocessing used to normalize the data before it gets sent to the routes.
- Postprocessing used to modify/normalize the data before it gets sent to the destinations.

Inside the pipelines, are *functions* that can be used to perform actions on the data and process it.
- There are also *packs* that are pre-configured configurations and actions that can be used directly to simplify making configurations and changes.

---
### Pipeline

A series of functions that execute in order.
- Data events that are taken in via the route are sent to the pipeline, where functions start to act on it in order.

> Copilot Editor can help in generating pipelines.

---
### Function

Performs an action on the data it sees.
- A collection of functions is a pipeline.
- A function is a piece of JavaScript code that executes on an event.
- Functions can be configured with filters as well to match necessary events.
- There is the Final Flag as well, similar to the one in the [[Routes]].
- Comments can be added for documentation.

There are default functions that come with Cribl, with the full list [here](https://docs.cribl.io/stream/functions/).

The `Parser` function can be used to `Extract` key-value pairs from the `_raw` field. 

---
### Packs

Prebuilt configs created to allow users to share and use.
- This is a prebuilt file that can include the whole infrastructure necessary, or a few parts like a pipeline or a route and so on. 
- Can be installed directly and to be used easily.
- Can be added from the Cribl Packs Dispensary, [List of Packs](https://packs.cribl.io).

---
