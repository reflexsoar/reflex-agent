from .rule import BaseRule


class ThresholdRule(BaseRule):

    def __init__(self, detection: dict, detection_input, elastic=None, agent=None):
        super().__init__(detection, detection_input, elastic, agent)
        self._config = self.detection.threshold_config
        self.create_piped_aggregation()
        self.query["size"] = 0

    def execute(self):
        data = self.conn.search(
            index=self.detection_input['index'], body=self.query)

        operator = self._config['operator']
        threshold = self._config['threshold']
        key_fields = self._config['key_field']
        threshold_field = self._config['threshold_field']
        rule_name = self.detection.name
        mode = 'cardinality' if self._config['cardinality'] else 'count'

        if len(key_fields) == 0:
            hits = data['hits']['total']['value']
            if self.test_threshold(hits, operator, threshold):
                print(
                    f"[!] Rule \"{rule_name}\" has matched - {hits} {operator} {threshold}")

        if len(key_fields) == 1:
            threshold_values = self.get_bucket_count(
                key_fields, key_fields[0], data['aggregations'], mode)
            if mode == 'cardinality':
                if self.test_threshold(len(threshold_values), operator, threshold):
                    print(
                        f"[!] Rule \"{rule_name}\" has matched - {len(threshold_values)} {operator} {threshold} - {','.join([str(x['key']) for x in threshold_values])}")
            else:
                for threshold_value in threshold_values:
                    if self.test_threshold(threshold_value['doc_count'], operator, threshold):
                        print(
                            f"[!] {threshold_value['key']} has matched rule \"{rule_name}\" - {threshold_value['doc_count']} {operator} {threshold}")

        elif len(key_fields) >= 2:
            for bucket in data['aggregations'][key_fields[0]]['buckets']:
                threshold_values = self.get_bucket_count(
                    key_fields[1:], threshold_field, bucket, mode)
                if mode == 'cardinality':
                    if self.test_threshold(len(threshold_values), operator, threshold):
                        print(
                            f"[!] {bucket['key']} has matched rule \"{rule_name}\" - {len(threshold_values)} {operator} {threshold} - {','.join([str(x['key']) for x in threshold_values])}")
                else:
                    for threshold_value in threshold_values:
                        if self.test_threshold(threshold_value['doc_count'], operator, threshold):
                            print(
                                f"[!] {bucket['key']} has matched rule \"{rule_name}\" - {threshold_value['doc_count']} {operator} {threshold} - {','.join([str(x['key']) for x in threshold_values])}")

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

    def create_piped_aggregation(self):
        '''
        Automatically creates a piped aggregation for the given fields.
        '''
        def create_terms_aggs(level, fields, threshold, max_size):

            if level >= len(fields):
                return None

            agg = {
                f"{fields[level]}": {
                    "terms": {
                        "field": fields[level],
                        "size": max_size
                    }
                }
            }

            # if threshold > 0:
            #    agg[f"{fields[level]}"]["terms"]["min_doc_count"] = threshold

            # If this is the second to last field, add a top_hits aggregation
            if level == len(fields)-2:
                agg[f"{fields[level]}"]["aggs"] = {
                    "top_hits": {
                        "top_hits": {
                            "size": 1
                        }
                    }
                }

            if level < len(fields)+1:
                aggs = create_terms_aggs(
                    level + 1, fields, threshold, max_size)
                if aggs:
                    agg[f"{fields[level]}"]["aggs"] = aggs

            return agg

        aggs = create_terms_aggs(0, self._config['key_field'],
                                 self._config['threshold'],
                                 100)
        if aggs:
            self.query['aggs'] = aggs
