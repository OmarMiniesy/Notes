### General Notes

Full reference: [Query DSL docs](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html)

##### Match Queries

`match` → searches against tokens. Use on `text` fields.
- Docs: [match query](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-match-query.html)
- This query uses `or` logic.
- Check out [[Using the Dev Console#Writing Match Queries|Writing Match Queries]].

##### Term Queries

`term` → exact value match. Use on `keyword` fields.
- Docs: [term query](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-term-query.html)
- `term` on a `text` field usually fails — the raw string was never stored, only its tokens
- Check out [[Using the Dev Console#Writing Term Queries|Writing Term Queries]].

##### Bool Queries

`bool` -> A compound query that combines multiple queries using `must`, `must_not`, `should`, and `filter` clauses.
- Docs: [Bool Query](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-bool-query).
- It's used to add multiple conditions to the same query. Think of it as a container that allows multiple clauses to be added.
- Inside the `bool` query, `match`, `term`, `range`, and other query types can be added within. 
- Check out [[Using the Dev Console#Writing Bool Queries|Writing Bool Queries]].

The operators used:

| Operator   | Must match?                           | Affects score? | Use case                                                                                              |
| ---------- | ------------------------------------- | -------------- | ----------------------------------------------------------------------------------------------------- |
| `must`     | yes                                   | yes            | required text search (relevance matters)                                                              |
| `filter`   | yes                                   | no (cached)    | required condition where relevance is not necessary — dates, exact values, exists checks              |
| `must_not` | must NOT match                        | no             | exclusions                                                                                            |
| `should`   | no (unless it's the only clause type) | yes            | "nice to have" boosts that increase the relevance of documents returned with the specified condition. |

> Check [[Strings and Field Types]] for details on `text` and `keyword` fields.

---

