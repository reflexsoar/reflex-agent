from concurrent.futures import ThreadPoolExecutor
import copy
from .rule import BaseRule
from loguru import logger

class ThresholdRule(BaseRule):

    def __init__(self, detection: dict,
                 detection_input,
                 credential, agent=None,
                 signature_fields=[],
                 field_mapping={}):
        super().__init__(detection, detection_input, credential, agent, signature_fields, field_mapping)
        self._config = self.detection.threshold_config
        self.create_multi_term_aggregation()
        self.query["size"] = 0

    def execute(self):

        docs = []

        data = self.elastic.conn.search(
            index=self.detection_input['config']['index'], body=self.query)
        
        if 'took' in data:
            self.query_time += data['took']

        operator = self._config['operator']
        threshold = self._config['threshold']
        key_fields = self._config['key_field']
        threshold_field = self._config['threshold_field']
        rule_name = self.detection.name
        mode = self._config['mode']

        doc_searches = []

        try:
            hits = False
            if mode == 'cardinality':
                if 'buckets' in data['aggregations']["1"]:
                    for bucket in data['aggregations']["1"]["buckets"]:
                        value = bucket[threshold_field]['value']
                        if self.test_threshold(value, operator, threshold):
                            hits = True
                            # Zip the bucket key_fields and bucket keys together
                            # and create a dictionary of the key_fields and bucket keys
                            key_values = dict(zip(key_fields, bucket['key']))
                            doc_searches.append(key_values)
                            logger.warning(f"[!] Rule \"{rule_name}\" has matched - {value} {operator} {threshold} - {bucket['key']}")
                else:
                    value = data['aggregations']["1"]["value"]
                    if self.test_threshold(value, operator, threshold):
                        hits = True
                        doc_searches.append({})
                        logger.warning(f"[!] Rule \"{rule_name}\" has matched - {value} {operator} {threshold}")
            elif mode == 'terms':
                if 'aggregations' in data:
                    for bucket in data['aggregations']["1"]["buckets"]:
                        if len(key_fields) == 1:
                            value = bucket['doc_count']
                            if self.test_threshold(value, operator, threshold):
                                hits = True
                                doc_searches.append(dict(zip([threshold_field], [bucket['key']])))
                                logger.warning(f"[!] Rule \"{rule_name}\" has matched - {value} {operator} {threshold} - {bucket['key']}")
                        else:
                            for _bucket in bucket[threshold_field]['buckets']:
                                value = _bucket['doc_count']
                                if self.test_threshold(value, operator, threshold):
                                    hits = True
                                    key_values = dict(zip([threshold_field], [_bucket['key']]))
                                    doc_searches.append(key_values)
                                    logger.warning(f"[!] Rule \"{rule_name}\" has matched - {value} {operator} {threshold} - {bucket['key']} to {_bucket['key']}")
            elif mode == 'count':
                value = data['hits']['total']['value']
                if self.test_threshold(value, operator, threshold):
                    hits = True
                    logger.warning(f"[!] Rule \"{rule_name}\" has matched - {value} {operator} {threshold}")
                #print(json.dumps(data['aggregations'], indent=2))

            if not hits:
                logger.success(f"[i] Rule \"{rule_name}\" did not match")
        except KeyError as e:
            logger.error(f"[!] Rule \"{rule_name}\" failed to match")
            logger.error(e)
            logger.error(data)

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(self.fetch_documents, fields_values=doc_search, threshold_field=threshold_field) for doc_search in doc_searches]
            for future in futures:
                docs.extend(future.result())

        docs = self.elastic.parse_events(docs, title=self.detection.name, signature_values=[
                                    self.detection.detection_id], risk_score=self.detection.risk_score)
        
        return docs 
            

    def test_threshold(self, count, operator, threshold):
        """
        Test the count against the threshold and return true if the condition is met
        """

        if operator == '>':
            return count > threshold
        elif operator == '>=':
            return count >= threshold
        elif operator == '<':
            return count < threshold
        elif operator == '<=':
            return count <= threshold
        elif operator == '==':
            return count == threshold
        else:
            return False

    def get_bucket_count(self, key_fields, threshold_field, data, mode):
        """ Collapse the buckets and keys in to a new dictionary
        by diving in to nested buckets until we reach the threshold field
        """

        threshold_values = []

        if threshold_field in data:
            threshold_values = data[threshold_field]['buckets']
            return threshold_values
        else:
            for key in key_fields:
                if key in data and 'buckets' in data[key]:
                    for bucket in data[key]['buckets']:
                        if threshold_field in bucket:
                            return bucket[threshold_field]['buckets']
                        else:
                            threshold_values = self.get_bucket_count(
                                key_fields[1:], threshold_field, bucket, mode)

        return threshold_values
    
    def fetch_documents(self, fields_values, threshold_field):
        """ Fetch the documents that match the query and return the results
        """

        documents = []

        keys = list(fields_values.keys())
        top_hits_size = 1

        if len(keys) == 1 and threshold_field == keys[0]:
            top_hits_size = self._config['max_events']

        query = copy.deepcopy(self.query)

        # Set the size to max_size 
        #query['size'] = self._config['max_events']

        # Remove the aggregations
        if 'aggs' in query:
            del query['aggs']

        # Update the base_query to include the fields and values
        for field, value in fields_values.items():
            query['query']['bool']['must'].append({
                "match": {
                    field: value
                }
            })
        
        # Replace the aggs with a terms aggregation on the threshold_field and a top_hits aggregation
        query['aggs'] = {
            "1": {
                "terms": {
                    "field": threshold_field,
                    "size": self._config['max_events']
                },
                "aggs": {
                    "hits": {
                        "top_hits": {
                            "size": top_hits_size
                        }
                    }
                }
            }
        }

        import json
        #print(json.dumps(query, indent=2))

        # Run the query
        data = self.elastic.conn.search(
            index=self.detection_input['config']['index'], body=query)
        
        #if 'took' in data:
        #    self.query_time += data['took']
        
        # Loop through the buckets and append the hits to the documents list
        for bucket in data['aggregations']['1']['buckets']:
            if bucket['hits']['hits']['total']['value'] > 0:
                documents.extend(bucket['hits']['hits']['hits'])
        return documents
    
    def create_multi_term_aggregation(self):
        '''
        Automatically creates a multi_term aggregation with the threshold_field being a piped aggregation
        of the multi_term aggregation.
        '''

        fields = self._config['key_field']
        threshold = self._config['threshold']
        max_size = 100
        mode = self._config['mode']
        threshold_field = self._config['threshold_field']

        if threshold_field is None:
            threshold_field = fields[-1]

        if len(fields) == 1:
            agg = {
                "1": {
                    mode: {
                        "field": fields[0]
                        
                    }
                }
            }

            if mode == "terms":
                agg["1"][mode]["size"] = max_size
                agg["1"][mode]["min_doc_count"] = threshold
        
        elif len(fields) == 2 and threshold_field == fields[1]:
            agg = {
                "1": {
                    "terms": {
                        "field": fields[0],
                        "size": max_size
                    },
                    "aggs": {
                        threshold_field: {
                            mode: {
                                "field": fields[1]
                            }
                        }
                    }
                }
            }

            if mode == "terms":
                agg["1"]["aggs"][threshold_field]["terms"]["size"] = max_size
                agg["1"]["aggs"][threshold_field]["terms"]["min_doc_count"] = threshold   

        else:
            if threshold_field == fields[-1]:
                fields = fields[0:-1]
                
            agg = {
                "1": {
                    "multi_terms": {
                        "terms": [{"field": f} for f in fields[0:len(fields)]]
                    },
                    "aggs": {
                        threshold_field: {
                            mode: {
                                "field": threshold_field
                            }
                        }
                    }
                }
            }

            if mode == "terms":
                agg["1"]["aggs"][threshold_field]["terms"]["size"] = max_size
                agg["1"]["aggs"][threshold_field]["terms"]["min_doc_count"] = threshold

        if agg:
            self.query['aggs'] = agg
