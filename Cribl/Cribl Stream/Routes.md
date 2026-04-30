### General Notes

There are two types of ways to route traffic in Cribl:
- **QuickConnect**: Fast and simple drag and drop UI to connect sources with destinations.
- **Routes**: These are used to configure the data path by defining filter expressions to check what data is coming in, process, filter it, perform any actions on it, then route it to the appropriate pipeline/destination. Each route can be associated with only 1 pipeline and 1 destination.

All incoming data is evaluated against every route in order.
- Each route can modify the data through its associated pipeline and then send it to the configured destination.
- The Final flag determines whether matched data stops at that route or continues to be evaluated by the routes below it.
- Pipelines are responsible for modifying data — routes cannot pass data between each other or chain transformations sequentially. That is not their purpose.

---
### QuickConnect

To quickly connect configured source to configured destination.
- Easy to drag and drop connection between them.
- Packs (prebuilt pipeline) can quickly process the data to do some quick actions on the data (event breaking, field extraction, reduction).
	- Each event can only go to one destination — data cannot be sent to multiple destinations simultaneously or have one connection feed into another.
	- Unlike full Routes, QuickConnect only supports a single direct path per connection, not parallel multi-destination routing.

---
### Routes

![[Routes.png]]

A route is a direct link used to send data to the proper pipeline.
- Routes evaluate data against filters to determine the pipeline and destination to send it to.
- Each route is associated with only 1 pipeline and only 1 output.
- The routes are all evaluated in order
- Routes default with Final Flag set to Yes. If the Final Flag is yes, the data that is matched for the route gets sent to the pipeline and is no longer evaluated in other routes. If the flag is set to No, then Cribl continues checking routes below the matched route. This can be used to clone data and send it to multiple locations.

> data that does not match any route is dropped, unless there is a catch all route at the bottom to send it to a storage site.

The default destination for routes is set by default to DevNull, but can be changed.

---
