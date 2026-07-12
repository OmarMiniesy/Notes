##### Creating an Index

```
PUT /my-index
```

##### Adding a document to an Index

```
POST /my-index/_doc

{
    "id": "park_rocky-mountain",
    "title": "Rocky Mountain",
    "description": "blablablabla"
}
```

##### To get the [[Mappings]] of an Index

```
GET my_index/_mapping
```

##### To set the [[Mappings]] of an Index

```
PUT my_index 
{ 
	"mappings": { 
		"properties": { 
			"@timestamp": { "type": "date" }, 
			"abstract": { "type": "text" }, 
			"author": { "type": "keyword" } 
		} 
	} 
}
```

##### Using the `_reindex` API

```
POST _reindex
{
    "source": {
        "index" : "source_index_name"
    },
    "dest": {
        "index" : "dest_index_name"
    }
}
```

##### To run a Search Query

```
GET my_index/_search
{
    "query": {
        "match": {
          "authors.first_name": "Kim"
        }
    }
}
```