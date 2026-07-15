### Tokenization

A **Token** is a single word/unit produced when [[ELK - Elasticsearch, Kibana, & Logstash#Elasticsearch|Elasticsearch]] breaks a string apart.
- **Tokenization** is the process of splitting a string into tokens (also lowercases by default)
- Tokens (not the raw string) are what gets stored in the searchable index

> Example: `"User logged in"` → tokens: `["user", "logged", "in"]`

---
### `text` vs `keyword` Fields

A `text` field is *analyzed* (tokenized + lowercased). 
- Use for: log messages, descriptions, full-text search
- **Cannot** be sorted or aggregated.
- Case insensitive
- Docs: [text field type](https://www.elastic.co/guide/en/elasticsearch/reference/current/text.html)

A `keyword` field is *NOT analyzed*, stored as exact whole string. 
- Use for: [[IP]]s, usernames, status codes, hostnames — exact match/filter/sort/aggregation
- **Can** be sorted or aggregated.
- Case sensitive

> Analyzing is the process of tokenizing and lowercasing the values of a field. There are several types of analyzers present, each with different properties.

#### Analyzers

There is the `standard` and the `english` analyzer.
- The `standard` analyzer simply splits on whitespace.
- The `english` analyzer is preconfigured for English language, and it results in a more storage aware tokenization and performs *stemming*, which is returning the world to its root form. It also removes stop words and lowercases the text.

These can be called using the `_analyze` API:
```
GET /_analyze
{
  "analyzer": "standard",
  "text": "The Quick-Fox's jumps!"
}
```

---
### Multi-fields

Index the same source field as both `text` and `keyword` simultaneously
- Access the sub-field via dot notation: `field.keyword`

```json
"message": {
  "type": "text",
  "fields": {
    "keyword": { "type": "keyword" }
  }
}
```

- `message` → tokenized, full-text searchable
- `message.keyword` → exact match, sortable, aggregable.
- In Kibana Discover, sortable fields often show as `field.keyword` in the sort dropdown

---
