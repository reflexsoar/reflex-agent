import json
import time
from loguru import logger


class BaseRule:
    ''' Defines a base class used by all rule types '''

    def __init__(self, detection: dict, detection_input, elastic=None, agent=None):
        ''' Initializes the rule type '''

        self.type_num = -1
        self.type_name = 'base'

        self.detection = detection

        if not detection_input:
            raise ValueError('Detection input is required')
        self.detection_input = detection_input

        if not agent:
            raise ValueError('Reflex Agent object is required')
        self.agent = agent

        if not elastic:
            raise ValueError(
                'Elasticsearch/Opensearch connection object is required')
        self.conn = elastic  # Connection to the backend to query for data

        self.execution_time = 0.0  # Time taken to execute the detection
        self.errors = []  # List of errors that occurred during execution
        self.error = False  # Whether or not an error occurred during execution
        self.timefield = '@timestamp'  # The timefield to use for the detection
        self.query = {
            "query": {
                "bool": {
                    "must": []
                }
            }
        }  # The query used to execute the detection

        self.set_base_filter()
        self.set_time_range()
        self.set_exclusions()

    def set_time_range(self):
        """
        Sets the initial time range for the detection
        """
        # Override the default timestamp field if one is specified in the detection
        if hasattr(self.detection, 'alert_time_field'):
            self.timefield = self.detection.alert_time_field

        self.query["query"]["bool"]["must"].append({
            "range": {
                f"{self.timefield}": {
                    "gte": f"now-{self.detection.lookbehind}m"
                }
            }
        })

    def query_as_json(self):
        """
        Prints the query as JSON
        """
        print(json.dumps(self.query, indent=2))

    def set_base_filter(self):
        ''' Sets the base query for the detection '''
        self.query['query']['bool']['must'].append({
            "query_string": {
                "query": self.detection.query['query']}
        })

    def set_exclusions(self):
        '''Sets the exclusions based on the detection'''
        if hasattr(self.detection, 'exceptions') and self.detection.exceptions != None:
            self.query["query"]["bool"]["must_not"] = []
            for exception in self.detection.exceptions:

                if 'condition' in exception and exception['condition'] == 'wildcard':
                    for value in exception['values']:
                        self.query["query"]["bool"]["must_not"].append(
                            {
                                "wildcard": {
                                    f"{exception['field']}": value
                                }
                            }
                        )
                else:
                    if 'list' in exception and exception['list']['uuid'] != None:
                        list_values = self.agent.get_list_values(
                            uuid=exception['list']['uuid'])
                        exception['values'] = list_values

                    self.query["query"]["bool"]["must_not"].append(
                        {
                            "terms": {
                                f"{exception['field']}": exception['values']
                            }
                        }
                    )

    def run(self):
        ''' Runs the detection '''

        # Start the timer
        start_timer = time.time()

        # Run the detection
        print(self.query)
