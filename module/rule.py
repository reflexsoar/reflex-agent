import os
import json
import time
from datetime import datetime
from utils.elasticsearch import Elastic
from opensearchpy.helpers import bulk


class BaseRule:
    ''' Defines a base class used by all rule types '''

    def __init__(self, detection: dict,
                 detection_input,
                 credential, agent=None,
                 signature_fields=[],
                 field_mapping={}):
        ''' Initializes the rule type '''

        self.type_num = -1
        self.type_name = 'base'

        self.detection = detection
        self.credential = credential
        self.signature_fields = signature_fields
        self.field_mapping = field_mapping
        self.has_errors = False
        self.errors = []

        if not detection_input:
            raise ValueError('Detection input is required')
        self.detection_input = detection_input

        if not agent:
            raise ValueError('Reflex Agent object is required')
        self.agent = agent

        self.conn = None

        self.execution_time = 0.0  # Time taken to execute the detection
        self.query_time = 0.0
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

        self.build_connection()  # Connection to the backend to query for data
        self.set_base_filter()
        self.set_time_range()
        self.build_exceptions()

    def add_error(self, error_message):
        ''' Adds an error to the list of errors '''
        self.errors.append(error_message)
        self.error = True

    def suppress_events(self, events):
        '''
        Reduces the number of events by grouping the events by the signature and
        only returning max_events per signature
        '''
        # Group the events by signature
        grouped_events = {}

        max_events = 0
        if hasattr(self.detection, 'suppression_max_events'):
            max_events = self.detection.suppression_max_events

        if max_events <= 0:
            return events

        for event in events:
            if event.signature not in grouped_events:
                grouped_events[event.signature] = []
            if len(grouped_events[event.signature]) < max_events:
                grouped_events[event.signature].append(event)

        # Coallesce the events for each signature back in to a single list
        _events = []
        for signature in grouped_events:
            _events.extend(grouped_events[signature])

        return _events
    
    def ship_docs(self, docs):
        """
        Sends the documents as Events to the API via the Agent
        """

        for doc in docs:
            doc.description = getattr(
                self.detection, 'description', 'No description provided')
            doc.tags += getattr(self.detection, 'tags', [])
            doc.severity = getattr(self.detection, 'severity', 1)
            doc.detection_id = getattr(self.detection, 'uuid', None)
            doc.input_uuid = self.detection_input['uuid']

        if len(docs) > 0:

            # Write the docs to Elasticsearch if there are any
            # and the writeback is enabled
            self.writeback(docs)

            # If the detection has suppression_max_events set to something other than 0
            # suppress the events
            docs = self.suppress_events(docs)
            
            # If not dropping the event, process the hits
            if not self.drop:
                self.agent.process_events(docs, True)

            

    def writeback(self, events):
        # If the environment variable for writeback_index is set, write the results to the index
        # using the bulk helper and reusing the elastic.conn connection object
        if os.getenv('REFLEX_DETECTIONS_WRITEBACK_INDEX') != None:
            #self.logger.info(
            #    f"Writing {len(events)} events to {os.getenv('REFLEX_DETECTIONS_WRITEBACK_INDEX')}")
            bulk(self.conn, events, index=os.getenv(
                'REFLEX_DETECTIONS_WRITEBACK_INDEX'))

    @property
    def drop(self):
        # If the environment variable for drop_events is set, drop the events
        if os.getenv('REFLEX_DETECTIONS_DROP_EVENTS') != None:
            #self.logger.info(
            #    f"The REFLEX_DETECTIONS_DROP_EVENTS environment variable is set.  Dropping events.")
            return True
        return False

    def build_connection(self):
        """
        Returns a connection object to ElasticSearch
        """
        self.elastic = Elastic(
            self.detection_input['config'],
            self.field_mapping,
            self.credential,
            self.signature_fields
        )

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

    def build_exceptions(self):
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

        docs = self.execute()
        
        if docs:
            self.ship_docs(docs)

        end_timer = time.time()

        total_hits = self.detection.total_hits if self.detection.total_hits else 0
        

        update_payload = {
            'last_run': self.detection.last_run,
            'time_taken': (end_timer - start_timer)*1000,
            'query_time_taken': self.query_time,
        }

        if len(docs) > 0:
            update_payload['last_hit'] = datetime.utcnow().isoformat()
            update_payload['total_hits'] = total_hits + len(docs)
            update_payload['hits'] = len(docs)

        self.agent.update_detection(self.detection.uuid, payload=update_payload)

        # Close the connection to Elasticsearch
        self.elastic.conn.transport.close()
