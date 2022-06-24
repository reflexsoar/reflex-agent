import math
import time
import logging
import datetime
from dateutil import parser as date_parser
from multiprocessing import Process
from multiprocessing.pool import ThreadPool
from utils.base import JSONSerializable
from utils.elasticsearch import Elastic

class Detection(JSONSerializable):
    '''
    A Detection Rule object that makes it easier to interact with the rule
    '''

    def __init__(self, *args, **kwargs):
        if kwargs:
            self.__dict__.update(kwargs)

    def __repr__(self) -> str:
        return f"Detection({self.__dict__})"


    def should_run(self, catchup_period=1440) -> bool:
        '''
        Returns True if the detection is due for execution and False if the detection
        should be skipped during this execution interval

        Parameters:
            catchup_period (int) - The maximum time in minutes that the detection should adjust
                                    the lookbehind to find missed detections
        '''
        
        if hasattr(self, 'last_run'):

            # Convert the last_run ISO8601 UTC timestamp back to a datetime object
            last_run = date_parser.isoparse(self.last_run)

            # Determine the next time the rule should run
            next_run = last_run + datetime.timedelta(minutes=self.interval)
            next_run = next_run.replace(tzinfo=None)

            # Determine the current time in UTC
            current_time = datetime.datetime.utcnow()

            # Compute the mute period based on the last_hit property
            if hasattr(self, 'mute_period') and self.mute_period != None and self.mute_period > 0 and hasattr(self,'last_hit') and self.last_hit:
                mute_time = self.last_hit + datetime.timedelta(seconds=self.mute_period*60)
                mute_time = mute_time.replace(tzinfo=None)
            else:
                mute_time = current_time

            # If the current_time is greater than the when the detection rule should run again
            if current_time > next_run and current_time >= mute_time:

                # Compute the delta between the next_run and the current_time
                # if it is greater than the lookbehind, adjust the lookbehind to account 
                # for the gap in time
                minutes_since = (current_time - next_run).total_seconds()/60

                # If minutes since is greater than 24 hours don't go beyond that
                # TODO: Convert 60*24 to a detector configuration item
                if minutes_since > catchup_period:
                    self.lookbehind = math.ceil(self.lookbehind+catchup_period)
                elif minutes_since > self.lookbehind:
                    self.lookbehind = math.ceil(self.lookbehind+minutes_since)

                return True
        else:
            raise ValueError(message="Detection rule missing the last_run property")
        return False


class Detector(Process):
    '''
    The detector process runs detection rules against a target source
    Detection rules that return matches are sent to the API as Events
    '''

    def __init__(self, config, agent=None, log_level='INFO', *args, **kwargs):

        super(Detector, self).__init__(*args, **kwargs)

        # Establish a basic configuration
        if 'detector' in config:
            self.config = config['detector']
        else:
            self.config = {
                'concurrent_rules': 10,
                'graceful_exit': False,
                'catchup_period': 1440,
                'wait_interval': 30
            }
        
        self.running = True

        log_levels = {
            'DEBUG': logging.DEBUG,
            'ERROR': logging.ERROR,
            'INFO': logging.INFO
        }

        log_handler = logging.StreamHandler()
        log_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.addHandler(log_handler)
        self.logger.setLevel(log_levels[log_level])
        self.log_level = log_level
        self.agent = agent
        self.inputs = {}
        self.credentials = {}
        #self.graceful_shutdown = self.config['graceful_shutdown']

    def extract_fields(self, props):
        '''
        Extracts all the fields as flattened dot notation
        '''
        fields = []
        for field in props:
            if 'properties' in props[field]:
                for k in props[field]['properties']:
                    if 'fields' in props[field]['properties'][k]:
                        for f in props[field]['properties'][k]['fields']:
                            fields.append(f"{field}.{k}.{f}")
                    fields.append(f"{field}.{k}")
            else:
                fields.append(field)
        return fields


    def update_input_mappings(self):
        '''
        Fetches the mappings for each input and updates them so that future rules can leverage
        the mappings for autocomplete activity
        '''
        self.logger.info('Updating input field lists for detection rule autocompletion')
        for i in self.inputs:
            _input = self.inputs[i]
            credential = self.credentials[_input['credential']]

            # Check to see if the fields should be updated based on the last time they were updated
            should_update_fields = False
            if 'index_fields_last_updated' in _input:
                index_fields_last_updated = date_parser.isoparse(_input['index_fields_last_updated'])
                index_fields_last_updated = index_fields_last_updated.replace(tzinfo=None)
                current_time = datetime.datetime.utcnow()
                total_seconds = (current_time - index_fields_last_updated).total_seconds()
                if total_seconds >= 86400:
                    should_update_fields = True
            else:
                should_update_fields = True

            # If it is time to update the fields, build an Elastic connection object
            if should_update_fields:
                elastic = Elastic(_input['config'], _input['field_mapping'], credential)

                fields = []
                
                # Pull the index field mappings for all indices matching the inputs index pattern
                field_mappings = elastic.conn.indices.get_mapping(_input['config']['index'])
                for index in field_mappings:
                    props = field_mappings[index]['mappings']['properties']

                    # Flatten the field names
                    fields += self.extract_fields(props)

                # Create a unique, sorted list of field names
                fields = sorted(list(set(fields)))
                put_body = {
                    'index_fields': fields
                }
                
                # Update the inputs fields
                self.agent.call_mgmt_api(f"input/{i}/update_index_fields", data=put_body, method='PUT')


    def load_detections(self, active=True):
        '''
        Polls the API to find all detection work that should be assigned to this agent
        '''

        # Fetch the detections from the API
        response = self.agent.call_mgmt_api(f"detection?agent={self.agent.uuid}&active={active}")
        if response and response.status_code == 200:
            self.detection_rules = response.json()['detections']

        # Load all the input configurations for each detection
        self.inputs = {}
        input_uuids = []
        for rule in self.detection_rules:
            source = rule['source']
            if source['uuid'] not in input_uuids:
                input_uuids.append(source['uuid'])
        
        # Get the configuration for each input
        for input_uuid in input_uuids:
            _input = self.agent.get_input(input_uuid)
            if _input:
                self.inputs[input_uuid] = _input

        # Get the credential for each input
        for input_uuid in self.inputs:
            credential_uuid = self.inputs[input_uuid]['credential']
            self.credentials[credential_uuid] = self.agent.fetch_credentials(credential_uuid)


    def shutdown(self):
        """
        Shuts down the detector process, if graceful_shutdown 
        """
        raise NotImplementedError


    def match_rule(self, detection):
        """
        Runs a match rule (rule_type: 0) against the log source
        """
        raise NotImplementedError


    def execute(self, rule):
        """
        Executes a Detection Rule against the defined input on the rule and returns the results
        as events to the API
        """
        detection = Detection(**rule)

        input_uuid = detection.source['uuid']

        # Get the input or report an error if the agent doesn't know it
        if input_uuid in self.inputs:
            _input = self.inputs[input_uuid]
        else:
            # TODO: Add a call to insert a reflex-detections-log record
            self.logger.error(f"Detection {detection.name} attempted to use source {input_uuid} but no input found")

        # Get the credential or report an error if the agent doesn't know it
        if _input['credential'] in self.credentials:
            credential = self.credentials[_input['credential']]
        else:
            # TODO: Add a call to insert a reflex-detections-log record
            self.logger.error(f"Detection {detection.name} attempted to use credential {_input['credential']} but no credential found")

        try:
            if detection.should_run(catchup_period=self.config['catchup_period']):
                self.logger.info(f"Running detection {detection.name} using {_input['name']} ({_input['uuid']}) and credential {_input['credential']}")

                if _input['plugin'] == "Elasticsearch":

                    docs = []

                    query_time = 0
                    scroll_size = 0
                    start_execution_timer = datetime.datetime.utcnow()

                    # Create a connection to Elasticsearch
                    elastic = Elastic(_input['config'], _input['field_mapping'], credential)

                    # TODO: Support for multiple queries
                    query = {
                        "query": {
                            "bool": { 
                                "must": [
                                    {"query_string": { "query": detection.query['query'] }},
                                    {"range": {"@timestamp": {"gt": "now-{}m".format(detection.lookbehind)}}}
                                ]
                            }
                        },
                        "size": _input['config']['search_size']
                    }

                    # If there are exclusions/exceptions add them to the query
                    if len(detection.exceptions) > 0:
                        query["query"]["bool"]["must_not"] = []
                        for exception in detection.exceptions:
                        
                            query["query"]["bool"]["must_not"].append(
                                {
                                    "query_string": {
                                        "query": exception["query"]
                                    }
                                }
                            )

                    detection.last_run = datetime.datetime.utcnow().isoformat()
                    res = elastic.conn.search(index=_input['config']['index'], body=query, scroll='2m')
                    
                    scroll_id = res['_scroll_id']
                    if 'total' in res['hits']:
                        self.logger.info(f"{detection.name} ({detection.uuid}) - Found {len(res['hits']['hits'])} detection hits.")
                        query_time += res['took']
                        scroll_size = res['hits']['total']['value']

                        # Parse the events and extract observables, tags, signature the event
                        docs += elastic.parse_events(res['hits']['hits'], title=detection.name, signature_values=[detection.detection_id])                                        
                    else:
                        scroll_size = 0
                        
                    # Scroll
                    self.logger.info(f"{scroll_size}")
                    while (scroll_size > 0):
                        self.logger.info(f"{detection.name} ({detection.uuid}) - Scrolling Elasticsearch results...")
                        res = elastic.conn.scroll(scroll_id = scroll_id, scroll = '2m') # TODO: Move scroll time to config
                        if len(res['hits']['hits']) > 0:
                            query_time += res['took']
                            self.logger.info(f"{detection.name} ({detection.uuid}) - Found {len(res['hits']['hits'])} detection hits.")
                            # Parse the events and extract observables, tags, signature the event
                            docs += elastic.parse_events(res['hits']['hits'], title=detection.name, signature_values=[detection.detection_id])

                        scroll_size = len(res['hits']['hits'])

                    self.logger.info(f"{detection.name} ({detection.uuid}) - Total Hits {len(docs)}")

                    # Update all the docs to have detection rule hard values
                    for doc in docs:
                        doc.description = detection.description
                        doc.tags += detection.tags
                        doc.severity = detection.severity
                        doc.detection_id = detection.uuid
                    
                    update_payload = {
                        'last_run': detection.last_run,
                        'hits': len(docs)
                    }
                    
                    if hasattr(detection, 'total_hits') and detection.total_hits != None:
                        update_payload['total_hits'] = detection.total_hits + len(docs)
                    else:
                        update_payload['total_hits'] = len(docs)

                    if len(docs) > 0:
                        update_payload['last_hit'] = datetime.datetime.utcnow().isoformat()

                    # Calculate how long the entire detection took to run, this helps identify
                    # bottlenecks outside the ES query times
                    end_execution_timer = datetime.datetime.utcnow()
                    total_execution_time = (end_execution_timer - start_execution_timer).total_seconds()*1000

                    update_payload['time_taken'] = total_execution_time
                    update_payload['query_time_taken'] = query_time

                    # Update the detection with the meta information from this run
                    self.agent.update_detection(detection.uuid, payload=update_payload)
                    
                    # Close the connection to Elasticsearch
                    elastic.conn.transport.close()

                    # Send the detection hits as events to the API
                    self.agent.process_events(docs)

        except Exception as e:
            self.logger.error(f"Foo: {e}")
        

    def run_rules(self):
        """
        Runs the set of rules configured for this detection agent
        """

        def split_rules(rules, concurrent_rules):
            """
            Splits a set of rules into a smaller set
            """
            for i in range(0, len(rules), concurrent_rules):                
                yield rules[i:i + concurrent_rules]

        # Determine which rules to run in parallel based on the concurrent_rules setting
        rule_sets = list(split_rules(self.detection_rules, self.config['concurrent_rules']))

        # For each set of rules
        for rules in rule_sets:

            results = []

            # Spawn a worker set for each rule in the rule_set
            pool = ThreadPool(processes=self.config['concurrent_rules'])
            result = pool.map_async(self.execute, rules)
            result.wait()

            # Join the threads to wait for rule completion

            # Collect the results of the run

            # Send the hits as events

            # Update each rules last_run date and hits count

    def run(self):
        """
        Periodically runs detection rules as defined by the ReflexSOAR API
        """
        while self.running:
            self.logger.info('Fetching detections')
            self.load_detections()
            #self.run_rules()
            self.update_input_mappings()
            self.logger.info('Run complete, waiting')
            time.sleep(self.config['wait_interval'])