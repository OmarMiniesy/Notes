### General Notes

Mapping is the process of defining the schema of how the data will be stored in [[ELK - Elasticsearch, Kibana, & Logstash]].
- It is the process of defining the field types, specifying the data type, and whether it is keyword or text - [[Strings and Field Types]].
- This process is done once, when the index is created. To update the fields, a new index has to be created.
- This process directly controls the query performance and storage size of the data.

Mapping is done automatically by Elasticsearch, and this is called *dynamic mapping*, and it happens when a first document is added to an index.
- When mapping is to be done manually by the developer, it is called *explicit mapping*.
- The `properties` key is where the field name and type (mapping) takes place.

```
PUT /my-index
{
  "mappings": {
    "properties": {
      "event_id":   { "type": "keyword", "parameter1":"value" },
      "src_ip":     { "type": "ip" },
      "timestamp":  { "type": "date" },
      "user_name":  { "type": "keyword" },
      "message":    { "type": "text" },
      "bytes_sent": { "type": "long" }
      "extra_field": {"type": "text", 
	      "fields": { 
		      "keyword": { "type": "keyword" }
		 }
    }
  }
}
```

Notice above how the `extra_field` is both `text` and `keyword`.
- This is a [[Strings and Field Types#Multi-fields|Multi-Field]].
- Dynamic mapping does this for every string, causing twice the storage.

> Creating an empty index first and setting the mapping is to be done before adding any data to avoid Elasticsearch from performing dynamic mapping.

---
### The Reindex API

This is a function that is used to copy documents from one index to another.
- The destination index's mapping is used on the data.
-  It reads documents from the source index and writes them to the destination, where they're indexed according to the new mapping.

```
POST _reindex
{
    "source": {
        "index" : "blogs"
    },
    "dest": {
        "index" : "blogs_fixed"
    }
}
```

> The `_count` API can be used to check whether all documents have been moved. This can be done in the case of timeouts or just to check.

---
### Mapping Parameters

These are parameters used during mapping to enhance searching and storage.
- `copy_to`
- `doc_values`

The `copy_to` parameter is used to copy the value of this field into another field that can be searched.
- This allows a single query to search across the values of multiple fields by querying only this single field.
- This target field is used during search only, and it is not present in the `_source`.
- The target field's [[Strings and Field Types#Analyzers|Analyzer]] is used on the data.

```json
"source_field": {
	"type":"keyword",
	"copy_to":"target_field"
}
```

The `doc_values` parameter is always enabled by default, and it allows for sorting and aggregation on the fields.
- However, we can disable it for fields that we don't need sorting/aggregation on.

```json
"url": { 
	"type": "keyword", 
	"doc_values": false 
} 
```

---
