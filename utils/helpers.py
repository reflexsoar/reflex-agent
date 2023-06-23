def create_piped_aggregation(fields, threshold=100, max_size=10):
    '''
    Automatically creates a piped aggregation for the given fields.
    '''
    def create_terms_aggs(level, fields, threshold, max_size):
        if level >= len(fields):
            return {
                "doc": {
                    "top_hits": {
                        "size": max_size
                    }
                }
            }
        return {
            f"{fields[level]}": {
                "terms": {
                    "field": fields[level],
                    "min_doc_count": threshold
                },
                "aggs": create_terms_aggs(level + 1, fields, threshold, max_size)
            }
        }

    return create_terms_aggs(0, fields, threshold, max_size)


def check_deepest_doc_count(aggregation_result, docs, fields, level=0, threshold=100):
    '''
    Looks at an elastic/opensearch piped aggregation and discovers
    the doc_count of the last set of buckets.  If the doc_count is greater
    than the threshold, then the doc is added to the docs list.'''

    key = fields[level]
    if key in aggregation_result:
        for bucket in aggregation_result[key]["buckets"]:
            if level == len(fields) - 1:
                if bucket["doc_count"] > threshold:
                    print(bucket["key"], bucket["doc_count"])
                    docs.extend(bucket["doc"]["hits"]["hits"])
            else:
                check_deepest_doc_count(
                    bucket, docs, fields, level + 1, threshold)
