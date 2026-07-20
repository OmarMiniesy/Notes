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

#### Writing Match Queries

Writing a query is as simple as this:
```
GET index_name/_search
{
    "query": {
        "match": {
          "field_name": "open source"
        }
    }
}
```
- Match queries run using the `or` operator by default, so it will look in the `field_name` for `open` OR `source`. Returning all documents that have these values in the specified `field_name`.
- This can be changed by using the `operator` parameter and choosing `and`.

To improve the quality of these queries, we can add parameters like:
```
GET my_index/_search
{
    "query": {
        "match": {
          "field_name": "open source",
          "operator": "and"
        }
    },
    
    "size": 10,
    "from": 5,
    "fields": [
      "chosen_field", "chosen_field2"
    ],
    "_source": false,
    "sort": [ { "publish_date": { "order": "desc" } } ]
}
```
- `size` controls how many output documents are returned.
- `from` controls the page. So if we state `from: 5`, this means show all results but ignore the first 5.
- `fields` controls which fields to see in the output.
- The `_source` field is always returned by default and contains the entire document. Can be disabled for improved visibility.

To sort results, we can use the `sort` parameter.
- we need to specify the field we sort on and the order of sorting.
- This takes priority over the value scoring that Elasticsearch gives the results.

To match on an exact phrase or string, we can use the `match_phrase` query:

```
GET my_index/_search
{
  "query": {
    "match_phrase": {
      "field": "open source"
    }
  }
}
```

To search in several fields at the same time, we can use the `multi_match` query:
```
GET my_index/_search
{
  "query": {
    "multi_match": {
      "query": "needed_text_to_search_for",
      "type": "choose_type",
      "fields": [
        "field1",
        "field2",
        "field3"
      ]
    }
  }
}
```
- There are several types to be used in `multi_match` depending on what is needed:
	- `best_fields` is the default. It runs a `match` query on each field, and the document's score is taken from the _single best-matching field_. Use it when the search terms are expected to appear together in one field (e.g. the whole phrase lives in either `title` or `body`).
	- `most_fields` also runs a `match` per field, but _adds up_ the scores across all fields. Use it when the same text is indexed into multiple fields with different analyzers (e.g. `title`, `title.english`, `title.stemmed`) and every matching field should boost relevance.
	- `cross_fields` treats all the listed fields as if they were _one big combined field_, analyzing the query term-by-term. Use it when the search terms are spread across fields (e.g. searching `"John Smith"` against `first_name` and `last_name`).
	- `phrase` runs a `match_phrase` query on each field instead of a `match`. Word order and adjacency matter.
	- `phrase_prefix` runs a `match_phrase_prefix` on each field: same as `phrase`, but the last term is treated as a prefix (useful for search-as-you-type).
	- `bool_prefix` creates a `match_bool_prefix` per field: every term matched normally except the last, which matches as a prefix, but _without_ requiring phrase order. Also a search-as-you-type option, more forgiving than `phrase_prefix`.

To count the number of matched documents, we can use the `_count` API instead of the `_search`.
```
GET blogs_fixed2/_count
{
  "query": {
    "match": {
      "authors.job_title": "Director of Engineering"
    }
  }
}
```

#### Writing Range Queries

We can also apply filters using `range` queries:
```
GET my_index/_search
{
  "_source": ["publish_date", "title"],
  "query": {
    "range": {
      "publish_date": {
        "gte": "2018-01-01",
        "lt": "2019-01-01"
      }
    }
  }
}
```
- Using the `gte` and `lt` amongst other operators.

#### Writing Term Queries

To look for exact matches on unanalyzed fields, use the `term` query with the `keyword` field:
```
GET blogs_fixed2/_search
{
  "query": {
    "term": {
      "authors.job_title.keyword": "Director of Engineering"
    }
  }
}
```