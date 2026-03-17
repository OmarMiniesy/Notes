### General Notes

Kibana Query Language or KQL is used by [[ELK - Elasticsearch, Kibana, & Logstash|Elastic]] to perform searching on the ingested logs in [[ELK - Elasticsearch, Kibana, & Logstash#Elasticsearch|Elasticsearch]].
- There is *free-text search* and *field-based search*.

---
### Elastic Common Schema (ECS)

This is a shared vocabulary used for events across the Elastic stack. Using the ECS has several advantages. The documentation provides a list of the ECS fields present:
- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/ecs-reference.html)
- [Elastic Common Schema (ECS) event fields](https://www.elastic.co/guide/en/ecs/current/ecs-event.html)
- [Winlogbeat fields](https://www.elastic.co/guide/en/beats/winlogbeat/current/exported-fields-winlog.html)
- [Winlogbeat ECS fields](https://www.elastic.co/guide/en/beats/winlogbeat/current/exported-fields-ecs.html)
- [Winlogbeat security module fields](https://www.elastic.co/guide/en/beats/winlogbeat/current/exported-fields-security.html)
- [Filebeat fields](https://www.elastic.co/guide/en/beats/filebeat/current/exported-fields.html)
- [Filebeat ECS fields](https://www.elastic.co/guide/en/beats/filebeat/current/exported-fields-ecs.html)

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

### Comparison Operators 

KQL supports various comparison operators such as
- `:`
- `:>`
- `:>=`
- `:<`
- `:<=`
- `:!`

---
