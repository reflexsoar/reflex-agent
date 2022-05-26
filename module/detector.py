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

            # If the current_time is greater than the when the detection rule should run again
            if current_time > next_run:

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
            for source in rule['source']:
                if source['source'] not in input_uuids:
                    input_uuids.append(source['source'])
        
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

        # TODO: Support multiple sources in the future
        input_uuid = detection.source[0]['source']

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

                    elastic = Elastic(_input['config'],{},credential)

                    # TODO: Create a query generator that inserts any configured exclusions
                    # TODO: Support for multiple queries
                    query = {
                        "query": {
                            "bool": { 
                                "must": [
                                    {"query_string": { "query": detection.query[0]['query'] }},
                                    {"range": {"@timestamp": {"gt": "now-{}m".format(detection.lookbehind)}}}
                                ]
                            }
                        },
                        "size": _input['config']['search_size']
                    }

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

                    import json
                    print(json.dumps(query, indent=2))

                    detection.last_run = datetime.datetime.utcnow().isoformat()
                    res = elastic.conn.search(index=_input['config']['index'], body=query, scroll='2m')

                    scroll_id = res['_scroll_id']
                    if 'total' in res['hits']:
                        self.logger.info(f"{detection.name} ({detection.uuid}) - Found {len(res['hits']['hits'])} detection hits.")
                        scroll_size = res['hits']['total']['value']

                        # TODO: PARSE THESE
                        docs += res['hits']['hits']
                        #events += self.parse_events(res['hits']['hits'])
                                        
                    else:
                        scroll_size = 0
                        
                    # Scroll
                    while (scroll_size > 0):
                        self.logger.info(f"{detection.name} ({detection.uuid}) - Scrolling Elasticsearch results...")
                        res = elastic.conn.scroll(scroll_id = scroll_id, scroll = '2m') # TODO: Move scroll time to config
                        if len(res['hits']['hits']) > 0:
                            self.logger.info(f"{detection.name} ({detection.uuid}) - Found {len(res['hits']['hits'])} detection hits.")

                            # TODO: PARSE THESE
                            docs += res['hits']['hits']
                        #events += self.parse_events(res['hits']['hits'])
                        scroll_size = len(res['hits']['hits'])

                    self.logger.info(f"{detection.name} ({detection.uuid}) - Total Hits {len(docs)}")

                    if hasattr(detection, 'total_hits'):
                        detection.total_hits += len(docs)
                    else:
                        detection.total_hits = len(docs)

                    update_payload = {
                        'last_run': detection.last_run,
                        'total_hits': detection.total_hits
                    }

                    if detection.total_hits > 0:
                        update_payload['last_hit'] = datetime.datetime.utcnow().isoformat()

                    # Update the detection with the meta information from this run
                    self.agent.update_detection(detection.uuid, payload=update_payload)

                    # Close the connection to Elasticsearch
                    elastic.conn.transport.close()
                    
                    
        except Exception as e:
            print(e)
        

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
            self.run_rules()
            self.logger.info('Run complete, waiting')
            time.sleep(self.config['wait_interval'])