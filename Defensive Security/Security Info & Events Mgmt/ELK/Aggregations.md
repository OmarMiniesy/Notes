### General Notes

There are two types of *aggregations* in [[ELK - Elasticsearch, Kibana, & Logstash]]:
- **Metric Aggregation**: This computes a single number that is summarized from a set of documents (min, max, avg, sum, ...).
- **Bucket Aggregation**: This groups documents into buckets to categorize them based on different things like time, status, category, and then returns the document count per bucket.

Some important terms useful to know:
- **Percentile**: This is the value under which the given number of data falls under. So the `90th` percentile is the point where `90%` of the data fall under.
- **Cardinality**: This is the count of distinct values present in a field. This number is approximated on large datasets to ensure efficiency.

> When calculating the `cardinality` of a field, it is essential to use the `.keyword` field because the normal `text` field will treat each word in the field as unique, returning a wrong answer. Check out [[Strings and Field Types]] for more info on keyword and text fields.

###### Best Practice
Running multiple aggregations in one request is more efficient than separate calls.
- Elasticsearch scans the data once and computes all aggregations in parallel.
- Check out [[Using the Dev Console#Combining Aggregations|Combining Aggregations]].

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
### Nesting Aggregations

Multi-level analytics can be created by performing:
- Metrics within buckets, so the metric is calculated independently per bucket.
- Sort buckets using the per bucket-metrics.
- Applying aggregations on the outputs of other aggregations.

First, performing *sub-aggregation* to run the metric aggregation separately for each bucket:
- This calculates the median for each response code.
```
GET my_index/_search
{
  "size": 0,
  "aggs": {
    "bucket_name": {
      "terms": {
        "field": "response_code.keyword"
      },
      "aggs": {
        "runtime": {
          "percentiles": {
            "field": "runtime_sec",
            "percents": [
              50
            ]
          }
        }
      }
    }
  }
}
```

We can also *sort buckets by metrics* calculated inside of them:
- Here, we modify the above query to sort by the median in descending order.
- This is done by referencing the aggregation's name as the key. If there are multiple percentiles, we use this syntax: `aggregation_name.X` where `X` is the percentile value.
- Here, the metric we want to sort the buckets by is the `runtime` percentile. We use the `.50` to specify the median percentile. If there were other percentiles being calculated, we would have to specify. This is optional.
```
GET my_index/_search
{
  "size": 0,
  "aggs": {
    "bucket_name": {
      "terms": {
        "field": "response_code.keyword",
        "order": {
          "runtime.50": "desc"
        }
      },
      "aggs": {
        "runtime": {
          "percentiles": {
            "field": "runtime_sec",
            "percents": [
              50
            ]
          }
        }
      }
    }
  }
}
```

Nesting buckets inside one another is useful to create 2D views of data:
- Here, we first split the data into months, then inside each month, we create a bucket for the different response codes.
```
GET web_traffic/_search
{
  "size": 0,
  "aggs": {
    "logs_by_month": {
      "date_histogram": {
          "field": "@timestamp",
          "calendar_interval": "month"
      },
      "aggs": {
        "response": {
          "terms": {
            "field": "response_code.keyword"
          }
        }
      }
    }
  }
}
```

Finally, we can apply aggregations on the output of aggregations on buckets. This is *pipeline aggregation*:
- This is used to find the bucket with the highest value, the least value, and so on.
- Here, the syntax used is the `>` and is used to traverse the aggregation hierarchy.
- This aggregation below groups the runtimes per month, then gets the average for each bucket, then returns the max runtime from all the averages.
```
GET web_traffic/_search
{
  "size": 0,
  "aggs": {
    "runtime_avg_per_month": {
      "date_histogram": {
        "field": "@timestamp",
        "calendar_interval": "month"
      },
      "aggs": {
        "avg_runtime": {
          "avg": {
            "field": "runtime_sec"
          }
        }
      }
    },
    "max_avg_runtime": {
      "max_bucket": {
        "buckets_path": "runtime_avg_per_month>avg_runtime"
      }
    }
  }
}
```

---
