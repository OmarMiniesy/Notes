
### General Notes

NoSQL database service that is fully managed.
- It is cheap, fast, and can scale horizontally.
- However, it is hard to model relational date.

>  Data stored in `JSON` format 

There is another service called Document DB that is similar to mongodb.

___
### Tables

> Must have primary key

-   _Overview_ - This tab shows high-level details about the table. For example, the table name, partition key, primary sort key (if any), encryption type, and much more. Tables can be encrypted at rest with no overhead. You can also see the region and the Amazon Resource Name (ARN), which is a unique identifier for the current resource.

-   _Items_ - It lists all of the items/data stored in the table.

-   _Metrics_ - View the metrics for your table, such as, read/write capacity (units/sec), count of throttled read/write requests, and count of throttled read/write counts.
    
-   _Alarms_ - Set up alarms to notify you if you exceed your capacity limits. For each alarm, you will have to specify a metric and the upper threshold.
    
-   _Capacity_ - Set up the capacity of the selected table to read and write.
    
-   _Indexes_ - Set up the index using a primary key, and project on a set of attributes. Indexes help you to improve querying performance.
    
-   _Global Tables_ - When you set up a table as a global table, that table can exist in two or more AWS regions with automatic replication.
    
-   _Backups_ - A backup helps in restoring a _Point-in-time state_. DynamoDB maintains continuous backups of your table for the last 35 days.
    
-   _Triggers_ - Create triggers, for example, you can have a lambda function run whenever data is inserted into the current table.
    
-   _Access control_ - Set up access control policies (JSON files) that can allow access to the current table from Facebook, Google, or Amazon (not AWS).

___

### Adding Items

> `Scan` then choose `Create item`

___

### Query the table

> `Query` then enter value

___

### Delete the table

> Delete table by name and ensure *Delete all CloudWatch alarms*

