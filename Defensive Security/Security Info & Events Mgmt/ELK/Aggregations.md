### General Notes

There are two types of *aggregations* in [[ELK - Elasticsearch, Kibana, & Logstash]]:
- **Metric Aggregation**: This computes a single number that is summarized from a set of documents (min, max, avg, sum, ...).
- **Bucket Aggregation**: This groups documents into buckets to categorize them based on different things like time, status, category, and then returns the document count per bucket.

Some important terms useful to know:
- **Percentile**: This is the value under which the given number of data falls under. So the `90th` percentile is the point where `90%` of the data fall under.
- **Cardinality**: This is the count of distinct values present in a field. This number is approximated on large datasets to ensure efficiency.

> When calculating the `cardinality` of a field, it is essential to use the `.keyword` field because the normal `text` field will treat each word in the field as unique, returning a wrong answer. Check out [[Strings and Field Types]] for more info on keyword and text fields.

---
### Metric Aggregations

This is done by returning a single metric based on a set of documents, which can be done by using the following request through the [[Using the Dev Console|Dev Console]].

For example, to obtain the fastest request in the dataset:
```
GET my_index/_search
{
"size": 0,
  "aggs": {
    "my_fastest_request_time": {
      "min": {
        "field": "runtime_sec"
      }
    }
  }
}
```
- By choosing the index to be `my_index` and using the `_search` endpoint.
- Setting `size` to be `0` because we don't need to return any document, we just want the needed metric.
- `aggs` is the aggregation container which inside contains the metrics we need.
- The `my_fastest_request_time` is a custom label we choose to describe what we need, and inside it, we choose the `min` metric, to return the smallest value from the index.
	- Here we can choose any metric we need, this includes `stats` as well that returns a large array of useful metrics.
- The `field` we then choose is the `runtime_sec` field that is going to be matched against all of the documents.

To obtain the median, which is the same as the 50th percentile, we can use the `percentiles` aggregation metric:
```
GET my_index/_search
{
  "size": 0,
  "aggs": {
    "runtime_median_and_90": {
      "percentiles": {
        "field": "runtime_sec",
        "percents": [
          50,
          90
        ]
      }
    }
  }
}
```
- We also add a `percents` parameter that indicates the percentiles we want to return. We can also choose multiple values to return the value at multiple percentiles. 

We can also do the inverse using the `percentile_rank` metric, which obtains the percentile for the value we supply:
- This is useful for SLA reporting.
```
GET my_index/_search
{
  "size": 0,
  "aggs": {
    "runtime_goal": {
      "percentile_ranks": {
        "field": "runtime_sec",
        "values": [
          5
        ]
      }
    }
  }
}
```

---
### Bucket Aggregations

There are several types of bucket aggregations:
- **Term Aggregation**: This splits documents into buckets based on the unique values of a chosen field.
- **Date Histogram**: This splits documents into a chosen fixed time interval. 
- **Calendar Interval**: This distributes the documents onto the real calendar dates.

Using the Term Aggregation:
```
GET my_index/_search
{
  "size": 0,
  "aggs": {
    "method_buckets": {
      "terms": {
        "field": "chosen_field.keyword",
        "order": { "_key": "asc" }"
      }
    }
  }
}
```
- The `method_buckets` is used followed by the `terms` bucket aggregation.
- Using `keyword` here is essential, similar to cardinality in normal metric aggregation.
- We can also add `order` to sort the results.

---
