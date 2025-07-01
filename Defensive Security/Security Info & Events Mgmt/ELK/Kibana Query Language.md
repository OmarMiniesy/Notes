### General Notes

Kibana Query Language or KQL is used by [[ELK - Elasticsearch, Kibana, & Logstash|Elastic]] to perform searching on the ingested logs in [[ELK - Elasticsearch, Kibana, & Logstash#Elasticsearch|Elasticsearch]].
- There is *free-text search* and *field-based search*.

---
### Free Text Search

Using only text, the logs can be searched.
- Entering text between quotes `"menu"` will return all the documents that contain this term.
- It looks for whole matches only in the document.

> We can use the wildcard `*` to match for anything. So in the above case, if `"menu"` doesn't match for anything, we can check for `"menu*"`.

This also supports using operators like:
- `AND`
- `NOT`
- `OR`

### Field Based Search

By specifying the fields to search for and using `key:value` syntax.
- Can also utilize the operators above.

---
