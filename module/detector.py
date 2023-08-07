from concurrent.futures import ThreadPoolExecutor
import copy
import re
import os
import uuid
import json
import math
import time
import logging
import datetime
from dateutil import parser as date_parser
from multiprocessing import Process, Event
from multiprocessing.pool import ThreadPool
from concurrent.futures import ThreadPoolExecutor

from opensearchpy import ConnectionTimeout, NotFoundError
from opensearchpy.helpers import bulk
from utils.base import JSONSerializable
from utils.elasticsearch import Elastic
from utils.helpers import create_piped_aggregation
from utils.indexed_dict import IndexedDict
from .rule import BaseRule


class Detection(JSONSerializable):
    '''
    A Detection Rule object that makes it easier to interact with the rule
    '''

    def __init__(self, *args, **kwargs):
        if kwargs:
            self.__dict__.update(kwargs)

        log_handler = logging.StreamHandler()
        log_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

        self.logger = logging.getLogger(self.__class__.__name__)

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
            if hasattr(self, 'mute_period') and self.mute_period != None and self.mute_period > 0 and hasattr(self, 'last_hit') and self.last_hit:
                last_hit = date_parser.isoparse(self.last_hit)
                mute_time = last_hit + \
                    datetime.timedelta(seconds=self.mute_period*60)
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
                    self.logger.info(
                        f"Adjusting lookbehind for {self.name} from {self.lookbehind} to {math.ceil(self.lookbehind+catchup_period)}")
                    self.lookbehind = math.ceil(self.lookbehind+catchup_period)
                elif minutes_since > self.lookbehind:
                    self.logger.info(
                        f"Minutes since is {minutes_since} which is greater than {self.lookbehind}.  Adjusting lookbehind for {self.name} from {self.lookbehind} to {math.ceil(self.lookbehind+minutes_since)}")
                    self.lookbehind = math.ceil(self.lookbehind+minutes_since)

                return True
        else:
            raise ValueError(
                message="Detection rule missing the last_run property")
        return False


class Detector(Process):
    '''
    The detector process runs detection rules against a target source
    Detection rules that return matches are sent to the API as Events
    '''

    def __init__(self, config, agent=None, log_level='INFO', *args, **kwargs):

        super(Detector, self).__init__(*args, **kwargs)

        # Establish a basic configuration
        if config:
            self.config = config
        else:
            self.config = {
                'concurrent_rules': 10,
                'graceful_exit': False,
                'catchup_period': 1440,
                'wait_interval': 10,
                'max_threshold_events': 1000
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
        self.detection_rules = []
        self.should_exit = Event()
        self.new_term_state_table = {}

    def suppress_events(self, detection, events):
        '''
        Reduces the number of events by grouping the events by the signature and
        only returning max_events per signature
        '''
        # Group the events by signature
        grouped_events = {}

        max_events = 0
        if hasattr(detection, 'suppression_max_events'):
            max_events = detection.suppression_max_events

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

    def writeback(self, conn, events):
        # If the environment variable for writeback_index is set, write the results to the index
        # using the bulk helper and reusing the elastic.conn connection object
        events = [
            {'test': 'test'}
        ]
        if os.getenv('REFLEX_DETECTIONS_WRITEBACK_INDEX') != None:
            self.logger.info(
                f"Writing {len(events)} events to {os.getenv('REFLEX_DETECTIONS_WRITEBACK_INDEX')}")
            bulk(conn, events, index=os.getenv(
                'REFLEX_DETECTIONS_WRITEBACK_INDEX'))

    @property
    def drop(self):
        # If the environment variable for drop_events is set, drop the events
        if os.getenv('REFLEX_DETECTIONS_DROP_EVENTS') != None:
            self.logger.info(
                f"The REFLEX_DETECTIONS_DROP_EVENTS environment variable is set.  Dropping events.")
            return True
        return False

    def set_new_term_state_entry(self, detection_id, field, terms):
        '''
        Sets the new term state table entry for a detection rule
        '''
        if detection_id not in self.new_term_state_table:
            self.new_term_state_table[detection_id] = {}
        if field not in self.new_term_state_table[detection_id]:
            self.new_term_state_table[detection_id][field] = terms
        else:
            self.new_term_state_table[detection_id][field].extend(terms)
            self.new_term_state_table[detection_id][field] = list(
                set(self.new_term_state_table[detection_id][field]))

    def get_new_term_state_entry(self, detection_id, field):
        '''
        Returns the new term state table entry for a detection rule
        '''
        if detection_id in self.new_term_state_table and field in self.new_term_state_table[detection_id]:
            return self.new_term_state_table[detection_id][field]
        return []

    def exit(self):
        '''
        Shuts down the detector
        '''
        self.should_exit.set()

    def extract_fields_from_indexed_dict(self, props):

        field_dict = IndexedDict(props)

        fields = []

        for field in field_dict:
            field = field.replace('.properties', '')
            if field.endswith('.type'):
                field = field.replace('.type', '')
            if field.endswith('.ignore_above'):
                continue
            if field.endswith('.norms'):
                continue
            field = field.replace('.fields', '')
            fields.append(field)

        return fields

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
        self.logger.info(
            'Updating input field lists for detection rule autocompletion')
        for i in self.inputs:
            _input = self.inputs[i]
            credential = self.credentials[_input['credential']]

            # Check to see if the fields should be updated based on the last time they were updated
            should_update_fields = False
            if 'index_fields_last_updated' in _input:
                if _input['index_fields_last_updated'] == None:
                    should_update_fields = True
                else:
                    index_fields_last_updated = date_parser.isoparse(
                        _input['index_fields_last_updated'])
                    index_fields_last_updated = index_fields_last_updated.replace(
                        tzinfo=None)
                    current_time = datetime.datetime.utcnow()
                    total_seconds = (
                        current_time - index_fields_last_updated).total_seconds()
                    if total_seconds >= 86400:
                        should_update_fields = True
            else:
                should_update_fields = True

            # If it is time to update the fields, build an Elastic connection object
            if should_update_fields:
                elastic = Elastic(_input['config'],
                                  _input['field_mapping'], credential)

                fields = []

                # Pull the index field mappings for all indices matching the inputs index pattern
                try:
                    field_mappings = elastic.conn.indices.get_mapping(
                        _input['config']['index'])
                    for index in field_mappings:
                        props = field_mappings[index]['mappings']['properties']

                        # Flatten the field names
                        fields += self.extract_fields_from_indexed_dict(props)

                    # Create a unique, sorted list of field names
                    fields = sorted(list(set(fields)))
                    put_body = {
                        'index_fields': fields
                    }

                    # Update the inputs fields
                    self.agent.call_mgmt_api(
                        f"input/{i}/index_fields", data=put_body, method='PUT')
                except Exception as e:
                    self.logger.error(
                        f"Error updating input field list for input {_input['name']}: {e}")

    def load_rules_for_assessment(self):
        '''
        Loads rules that are in need of assessment from the API
        '''

        rules = []

        # Fetch the detections from the API
        response = self.agent.call_mgmt_api(
            f"detection?assess_rule=true&page_size=100&rule_type=0")
        if response and response.status_code == 200:
            data = response.json()
            if 'detections' in data:
                rules = data['detections']

        input_uuids = []
        for rule in rules:
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
            if credential_uuid not in self.credentials:
                self.credentials[credential_uuid] = self.agent.fetch_credentials(
                    credential_uuid)

        return rules

    def _assess_rule(self, rule):
        '''
        Runs the query against an input as a date histogram query
        '''

        DAYS = 30  # TODO: Make this configurable

        detection = Detection(**rule)
        self.logger.info(f"Assessing rule {detection.name}")
        source = detection.source
        if source['uuid'] is None:
            self.logger.error(f"Rule {detection.name} has no input")
            return
        _input = self.inputs[source['uuid']]
        credential = self.credentials[_input['credential']]
        elastic = Elastic(_input['config'],
                          _input['field_mapping'], credential)

        # Only support match rules at this time
        if detection.rule_type != 0:
            return

        query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": f"now-{DAYS}d",
                                    "lte": "now"
                                }
                            }
                        },
                        {
                            "query_string": {
                                "query": detection.query['query']
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "overtime": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1d",
                        "extended_bounds": {
                            "min": f"now-{DAYS}d",
                            "max": "now"
                        }
                    }
                }
            },
            "size": 0
        }

        # If there are exclusions/exceptions add them to the query
        if hasattr(detection, 'exceptions') and detection.exceptions != None:
            query["query"]["bool"]["must_not"] = []
            for exception in detection.exceptions:

                if 'list' in exception and exception['list']['uuid'] != None:
                    list_values = self.agent.get_list_values(
                        uuid=exception['list']['uuid'])
                    exception['values'] = list_values

                query["query"]["bool"]["must_not"].append(
                    {
                        "terms": {
                            f"{exception['field']}": exception['values']
                        }
                    }
                )

        # Run the query
        try:
            response = elastic.conn.search(
                index=_input['config']['index'], body=query)
            if response and response['hits']['total']['value'] > 0:

                events_over_time = {}
                # Print the results of the overtime bucketing
                for bucket in response['aggregations']['overtime']['buckets']:
                    events_over_time[bucket['key_as_string']
                                     ] = bucket['doc_count']

                # Sum all the buckets to get total_hits
                total_hits = 0
                days_with_hits = 0
                for bucket in response['aggregations']['overtime']['buckets']:
                    if bucket['doc_count'] > 0:
                        days_with_hits += 1
                    total_hits += bucket['doc_count']

                update_payload = {
                    'hits_over_time': json.dumps(events_over_time),
                    'average_hits_per_day': math.ceil(total_hits / days_with_hits),
                    'assess_rule': False,
                    'last_assessed': datetime.datetime.utcnow().isoformat()
                }
            else:
                update_payload = {
                    'hits_over_time': json.dumps({}),
                    'average_hits_per_day': 0,
                    'assess_rule': False,
                    'last_assessed': datetime.datetime.utcnow().isoformat()
                }

            # Run the query 5 times to get a good average of the response time
            try:
                total_time = 0
                for i in range(5):
                    performance_query = {
                        "query": {
                            "bool": {
                                "must": [
                                    {
                                        "query_string": {
                                            "query": detection.query['query']
                                        }
                                    },
                                    {
                                        "range": {
                                            "@timestamp": {
                                                "gte": f"now-5m",
                                                "lte": "now"
                                            }
                                        }
                                    }
                                ]
                            }
                        }
                    }
                    response = elastic.conn.search(
                        index=_input['config']['index'], body=performance_query)
                    total_time += response['took']

                update_payload['average_query_time'] = math.ceil(
                    total_time / 5)
            except Exception as e:
                self.logger.error(
                    f"Error getting average query time for rule {detection.name}: {e}")
                update_payload['average_query_time'] = 0

            self.agent.update_detection(detection.uuid, payload=update_payload)

        except Exception as e:
            self.logger.error(f"Error assessing rule {detection.name}: {e}")
            update_payload = {
                'hits_over_time': json.dumps({}),
                'average_hits_per_day': 0,
                'assess_rule': False,
                'last_assessed': datetime.datetime.utcnow().isoformat()
            }

            self.agent.update_detection(detection.uuid, payload=update_payload)

    def assess_rules(self):
        '''
        Runs the assessment logic for each rule that is in need of assessment
        '''
        self.logger.info('Assessing rules')

        # Allow for multiple rules to be assessed at once using concurrent futures
        # TODO: Make the max_parallel_assessments configurable
        max_parallel_assessments = 5
        rules = self.load_rules_for_assessment()
        with ThreadPoolExecutor(max_workers=max_parallel_assessments) as executor:
            executor.map(self._assess_rule, rules)

        #for rule in self.load_rules_for_assessment():
        #    self._assess_rule(rule)

    def load_detections(self, active=True):
        '''
        Polls the API to find all detection work that should be assigned to this agent
        '''

        # Fetch the detections from the API
        response = self.agent.call_mgmt_api(
            f"detection?agent={self.agent.uuid}&active={active}")
        if response and response.status_code == 200:
            self.detection_rules = response.json()['detections']
            self.logger.info(f"Loaded {len(self.detection_rules)} detections")

        # Load all the input configurations for each detection
        self.inputs = {}
        input_uuids = []
        if hasattr(self, 'detection_rules'):
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
            if credential_uuid not in self.credentials:
                self.credentials[credential_uuid] = self.agent.fetch_credentials(
                    credential_uuid)

    def shutdown(self):
        """
        Shuts down the detector process, if graceful_shutdown 
        """
        raise NotImplementedError

    def get_nested_field(self, message, field):
        '''
        Iterates over nested fields to get the final desired value
        e.g signal.rule.name should return the value of name
        '''

        if isinstance(field, str):
            # If the field exists as a flat field with .'s in it return the field
            if field in message:
                return message[field]
            args = field.split('.')
        else:
            args = field

        if args and message:
            element = args[0]
            if element:
                value = message.get(element)
                return value if len(args) == 1 else self.get_nested_field(value, args[1:])

    def mismatch_rule(self, detection, credential, _input, signature_fields=[], field_mapping={}):
        """
        Runs a field mismatch rule (rule_type: 3) against a log source
        """

        start_execution_timer = datetime.datetime.utcnow()

        # Create a connection to Elasticsearch
        elastic = Elastic(
            _input['config'], field_mapping, credential, signature_fields=signature_fields)

        query = {
            "query": {
                "bool": {
                    "must": [
                        {"query_string": {
                            "query": detection.query['query']}},
                        {"range": {
                            "@timestamp": {"gte": "now-{}m".format(detection.lookbehind)}}}
                    ]
                }
            },
            "size": _input['config']['search_size']
        }

        docs, query_time = self.run_rule_query(
            query, _input, detection, elastic)
        hits = []
        for doc in docs:

            doc.description = getattr(
                detection, 'description', 'No description provided')
            doc.tags += getattr(detection, 'tags', []) or []
            doc.severity = getattr(detection, 'severity', 1)
            doc.detection_id = getattr(detection, 'uuid', None)
            doc.input_uuid = _input['uuid']

            hit = False
            operator = detection.field_mismatch_config['operator']

            # Convert the raw log back to a dictionary
            raw_log = json.loads(doc.raw_log)

            # Extract the fields to compare
            source_field_value = self.get_nested_field(
                raw_log, detection.field_mismatch_config['source_field'])
            destination_field_value = self.get_nested_field(
                raw_log, detection.field_mismatch_config['target_field'])

            # If both fields have a value compare them
            if source_field_value and destination_field_value:
                hit = self.value_check(
                    source_field_value, operator, destination_field_value)

                if hit:
                    hit_descriptor = f"{detection.field_mismatch_config['source_field']} value {source_field_value} {operator} {detection.field_mismatch_config['target_field']} value {destination_field_value}"
                    if doc.description:
                        doc.description += f"\n\n{hit_descriptor}"
                    else:
                        doc.description = hit_descriptor
                    hits.append(doc)

        update_payload = {
            'last_run': detection.last_run,
            'hits': len(hits)
        }

        # Calculate how long the entire detection took to run, this helps identify
        # bottlenecks outside the ES query times
        end_execution_timer = datetime.datetime.utcnow()
        total_execution_time = (
            end_execution_timer - start_execution_timer).total_seconds()*1000

        update_payload['time_taken'] = total_execution_time
        update_payload['query_time_taken'] = query_time

        if hasattr(detection, 'total_hits') and detection.total_hits != None:
            update_payload['total_hits'] = detection.total_hits + len(docs)
        else:
            update_payload['total_hits'] = len(docs)

        if len(hits) > 0:

            # Write the docs to Elasticsearch if there are any
            # and the writeback is enabled
            self.writeback(elastic.conn, hits)

            # If the detection has suppression_max_events set to something other than 0
            # suppress the events
            hits = self.suppress_events(detection, hits)

            # If not dropping the event, process the hits
            if not self.drop:
                self.agent.process_events(hits, True)

            update_payload['last_hit'] = datetime.datetime.utcnow().isoformat()

        self.agent.update_detection(detection.uuid, payload=update_payload)

        # Close the connection to Elasticsearch
        elastic.conn.transport.close()

    def data_source_monitor_rule(self, detection, credential, _input, signature_fields=[], field_mapping={}):
        '''
        Runs a data source monitor rule (rule_type: 6) against a log source
        '''

        start_execution_timer = datetime.datetime.utcnow()
        query_time = 0

        # TODO - Add message and data_source as default signature fields
        # TODO - Add data_source as a default field_mapping

        elastic = Elastic(
            _input['config'], field_mapping, credential, signature_fields=signature_fields)

        # Fetch a list of all the data sources to monitor
        data_sources = []
        docs = []
        is_delta = detection.source_monitor_config['delta_change']
        operator = detection.source_monitor_config['operator']

        if 'source_lists' not in detection.source_monitor_config:
            detection.source_monitor_config['source_lists'] = []
        if 'excluded_source_lists' not in detection.source_monitor_config:
            detection.source_monitor_config['excluded_source_lists'] = []
        if 'excluded_sources' not in detection.source_monitor_config:
            detection.source_monitor_config['excluded_sources'] = []
        if 'data_sources' not in detection.source_monitor_config:
            detection.source_monitor_config['data_sources'] = []

        data_sources.extend(detection.source_monitor_config['data_sources'])

        # If the detection has any data sources in intel lists add them to the list
        if len(detection.source_monitor_config['source_lists']) > 0:
            for source_list in detection.source_monitor_config['source_lists']:
                data_sources.extend(
                    self.agent.get_list_values(uuid=source_list['uuid']))

        # If the detection has any data sources to exclude remove them from the list
        if len(detection.source_monitor_config['excluded_sources']) > 0:
            for excluded_source in detection.source_monitor_config['excluded_sources']:
                if excluded_source in data_sources:
                    data_sources.remove(excluded_source)

        # If the detection has any data sources to exclude in intel lists remove them from the list
        if len(detection.source_monitor_config['excluded_source_lists']) > 0:
            for excluded_source_list in detection.source_monitor_config['excluded_source_lists']:
                for source in self.agent.get_list_values(uuid=excluded_source_list['uuid']):
                    if source in data_sources:
                        data_sources.remove(source)

        # Dedupe the list of data sources
        data_sources = list(set(data_sources))

        # Run the count query against each data source and compare it to the threshold
        for data_source in data_sources:
            previous_period = 0

            # If the data source monitor is set to compare against a previous period
            # learn the data from the previous period and compare it to the current period
            if is_delta:
                delta_window = detection.source_monitor_config['delta_window']
                try:
                    minutes_ago = delta_window*1440+detection.lookbehind
                    res = elastic.conn.count(
                        index=data_source,
                        body={
                            "query": {
                                "range": {
                                    "@timestamp": {
                                        "gte": f"now-{minutes_ago}m",
                                        "lte": f"now-{delta_window}d"
                                    }
                                }
                            }
                        }
                    )

                    if 'count' in res:
                        previous_period = res['count']
                    if 'took' in res:
                        query_time += res['took']

                except NotFoundError:
                    self.logger.warning(
                        f"Failed to run count query against {data_source} - Data Source Not Found")
                    docs.append({
                                '_source': {
                                    'message': f"Failed to run count query against {data_source} - Data Source Not Found",
                                    '_id': str(uuid.uuid4()),
                                    '@timestamp': datetime.datetime.utcnow().isoformat(),
                                    'data_source': data_source
                                }})
                    continue
                except Exception as e:
                    self.logger.warning(
                        f"Failed to run count query against {data_source} - {e}")
                    continue

            count = 0
            try:
                res = elastic.conn.count(
                    index=data_source,
                    body={
                        "query": {
                            "range": {
                                "@timestamp": {
                                    "gte": f"now-{detection.lookbehind}m",
                                    "lte": "now"
                                }
                            }
                        }
                    }
                )

                if 'count' in res:
                    count = res['count']
                if 'took' in res:
                    query_time += res['took']

            except NotFoundError:
                self.logger.warning(
                    f"Failed to run count query against {data_source} - Data Source Not Found")
                docs.append({
                    '_source': {
                        'message': f"Failed to run count query against {data_source} - Data Source Not Found",
                        '_id': str(uuid.uuid4()),
                        '@timestamp': datetime.datetime.utcnow().isoformat(),
                        'data_source': data_source
                    }})
                continue
            except Exception as e:
                self.logger.warning(
                    f"Failed to run count query against {data_source} - {e}")
                continue

            threshold = detection.source_monitor_config['threshold']

            if is_delta:
                as_percentage = detection.source_monitor_config['threshold_as_percent']
                if as_percentage:
                    if operator in [">", ">="]:
                        threshold = previous_period + threshold / 100 * previous_period
                    else:
                        threshold = previous_period - threshold / 100 * previous_period

            result = self.value_check(count, operator, threshold)
            if result:
                docs.append({
                    '_source': {
                        'message': f"Data source {data_source} has {count} events which is {operator} the threshold of {threshold} events",
                        '_id': str(uuid.uuid4()),
                        '@timestamp': datetime.datetime.utcnow().isoformat(),
                        'data_source': data_source
                    }})

        docs = elastic.parse_events(docs, title=detection.name, signature_values=[
                                    detection.detection_id], risk_score=detection.risk_score)

        for doc in docs:
            doc.description = getattr(
                detection, 'description', 'No description provided')
            doc.tags += getattr(detection, 'tags', []) or []
            doc.severity = getattr(detection, 'severity', 1) or 1
            doc.detection_id = getattr(detection, 'uuid', None) or None
            doc.input_uuid = _input['uuid']

        update_payload = {
            'last_run': detection.last_run,
            'hits': len(docs)
        }

        # Calculate how long the entire detection took to run, this helps identify
        # bottlenecks outside the ES query times
        end_execution_timer = datetime.datetime.utcnow()
        total_execution_time = (
            end_execution_timer - start_execution_timer).total_seconds()*1000

        update_payload['time_taken'] = total_execution_time

        if hasattr(detection, 'total_hits') and detection.total_hits != None:
            update_payload['total_hits'] = detection.total_hits + len(docs)
        else:
            update_payload['total_hits'] = len(docs)

        if len(docs) > 0:

            # Write the docs to Elasticsearch if there are any
            # and the writeback is enabled
            self.writeback(elastic.conn, docs)

            # If the detection has suppression_max_events set to something other than 0
            # suppress the events
            docs = self.suppress_events(detection, docs)

            # If not dropping the event, process the hits
            if not self.drop:
                self.agent.process_events(docs, True)

            update_payload['last_hit'] = datetime.datetime.utcnow().isoformat()

        self.agent.update_detection(detection.uuid, payload=update_payload)

    def indicator_match_rule(self, detection, credential, _input, signature_fields=[], field_mapping={}):
        """
        Runs a match rule (rule_type: 5) against the log source
        """

        docs = []
        query_time = 0
        scroll_size = 0
        start_execution_timer = datetime.datetime.utcnow()

        # Create a connection to Elasticsearch
        elastic = Elastic(
            _input['config'], field_mapping, credential, signature_fields=signature_fields)

        query = {
            "query": {
                "bool": {
                    "must": [
                        {"query_string": {
                            "query": detection.query['query']}},
                        {"range": {
                            "@timestamp": {"gte": "now-{}m".format(detection.lookbehind)}}}
                    ]
                }
            },
            "size": 0
        }

        # If there are exclusions/exceptions add them to the query
        if hasattr(detection, 'exceptions') and detection.exceptions != None:
            query["query"]["bool"]["must_not"] = []
            for exception in detection.exceptions:

                if 'list' in exception and exception['list']['uuid'] != None:
                    list_values = self.agent.get_list_values(
                        uuid=exception['list']['uuid'])
                    exception['values'] = list_values

                query["query"]["bool"]["must_not"].append(
                    {
                        "terms": {
                            f"{exception['field']}": exception['values']
                        }
                    }
                )

        # Get the indicator config
        indicator_config = detection.indicator_match_config
        if not indicator_config['key_field']:
            self.logger.error(
                f"Indicator match rule {detection.uuid} has no key_field configured")
            return

        # Create an aggregation for the source_field
        query["aggs"] = {
            "indicator": {
                "terms": {
                    "field": indicator_config['key_field'],
                    "size": 10000
                }
            }
        }

        # Run the query
        try:
            matched_indicators = []
            response = elastic.conn.search(
                index=_input['config']['index'], body=query)
            if response and response['hits']['total']['value'] > 0:

                # Get the list of indicator values
                indicator_values = [
                    bucket['key'] for bucket in response['aggregations']['indicator']['buckets']]

                # Check the Intel List for matches
                matched_indicators = self.agent.check_intel_list_values(
                    detection.indicator_match_config['intel_list']['uuid'], values=indicator_values)

                del query['aggs']
                del query['size']

                # If there are matches, run a query to get the events
                if len(matched_indicators) > 0:

                    query['query']['bool']['must'].append(
                        {
                            'terms': {
                                f"{detection.indicator_match_config['key_field']}": matched_indicators
                            }
                        }
                    )

                    # Run the query again to get the events
                    response = elastic.conn.search(
                        index=_input['config']['index'], body=query, scroll='30s')

                    scroll_id = response['_scroll_id']
                    scroll_size = response['hits']['total']['value']
                    query_time += response['took']

                    # Get the first page of results
                    docs += response['hits']['hits']

                    # Get the rest of the pages
                    while (scroll_size > 0):
                        response = elastic.conn.scroll(
                            scroll_id=scroll_id, scroll='30s')
                        scroll_id = response['_scroll_id']
                        scroll_size = len(response['hits']['hits'])
                        query_time += response['took']
                        docs += response['hits']['hits']

                    # Clear the scroll
                    if scroll_id:
                        try:
                            elastic.conn.clear_scroll(scroll_id=scroll_id)
                        except:
                            pass

            # If there are hits, process them as events
            if len(docs) > 0:
                docs = elastic.parse_events(docs, title=detection.name, signature_values=[
                                            detection.detection_id], risk_score=detection.risk_score)

                for doc in docs:
                    doc.description = getattr(
                        detection, 'description', 'No description provided') or 'No description provided'
                    doc.tags += getattr(detection, 'tags') or []
                    doc.severity = getattr(detection, 'severity', 1) or 1
                    doc.detection_id = getattr(detection, 'uuid', None) or None
                    doc.input_uuid = _input['uuid']

            update_payload = {
                'last_run': detection.last_run,
                'hits': len(docs)
            }

            # Calculate how long the entire detection took to run, this helps identify
            # bottlenecks outside the ES query times
            end_execution_timer = datetime.datetime.utcnow()
            total_execution_time = (
                end_execution_timer - start_execution_timer).total_seconds()*1000

            update_payload['time_taken'] = total_execution_time
            update_payload['query_time_taken'] = query_time

            if hasattr(detection, 'total_hits') and detection.total_hits != None:
                update_payload['total_hits'] = detection.total_hits + len(docs)
            else:
                update_payload['total_hits'] = len(docs)

            if len(docs) > 0:

                # Write the docs to Elasticsearch if there are any
                # and the writeback is enabled
                self.writeback(elastic.conn, docs)

                # If the detection has suppression_max_events set to something other than 0
                # suppress the events
                docs = self.suppress_events(detection, docs)

                # If not dropping the event, process the hits
                if not self.drop:
                    self.agent.process_events(docs, True)

                update_payload['last_hit'] = datetime.datetime.utcnow(
                ).isoformat()

            self.agent.update_detection(detection.uuid, payload=update_payload)

        except Exception as e:
            self.logger.error(f"Error assessing rule {detection.name}: {e}")

    def match_rule(self, detection):
        """
        Runs a match rule (rule_type: 0) against the log source
        """
        raise NotImplementedError

    def metric_rule(self, detection):
        """
        Runs a metric rule (rule_type: 2)
        """
        raise NotImplementedError

    def value_check(self, value, operator, target):
        '''
        Checks if the value against a target value based on a specified
        operator
        '''

        try:
            if operator == '>':
                return value > target
            if operator == '>=':
                return value >= target
            if operator == '<':
                return value < target
            if operator == '<=':
                return value <= target
            if operator == '==':
                return value == target
            if operator == '!=':
                return value != target
            return False
        except TypeError as e:
            self.logger.error(f"Error comparing values: {e}")
            return False

    def new_terms_rule(self, detection, credential, _input, signature_fields=[], field_mapping={}):
        """
        Runs a terms aggregation using a base query and aggregation field and 
        stores the terms in a base64 encoded sorted list and also stores a 
        SHA1 hash of the base64 string
        """

        # If the detection has a max_events configured and it is not greater than what the
        # agent is configured to allow, use the configured value
        # If the detection does not have a max_events configured, default to 10 events
        if 'max_events' in detection.threshold_config:
            if detection.threshold_config['max_events'] > self.config['max_threshold_events']:
                detection.threshold_config['max_events'] = self.config['max_threshold_events']
        else:
            detection.threshold_config['max_events'] = 10

        start_execution_timer = datetime.datetime.utcnow()

        # Create a connection to Elasticsearch
        elastic = Elastic(
            _input['config'], field_mapping, credential, signature_fields=signature_fields)

        query_time = 0
        docs = []
        old_terms = self.get_new_term_state_entry(
            detection.uuid, detection.new_terms_config['key_field'])

        if old_terms == []:
            self.logger.info(
                f"New terms rule {detection.uuid} has no previous terms, running a full query")

            query = {
                "query": {
                    "bool": {
                        "must": [

                        ]
                    }
                },
                "size": 0
            }

            # If there are exclusions/exceptions add them to the query
            if hasattr(detection, 'exceptions') and detection.exceptions != None:
                query["query"]["bool"]["must_not"] = []
                for exception in detection.exceptions:

                    if 'list' in exception and exception['list']['uuid'] != None:
                        list_values = self.agent.get_list_values(
                            uuid=exception['list']['uuid'])
                        exception['values'] = list_values

                    query["query"]["bool"]["must_not"].append(
                        {
                            "terms": {
                                f"{exception['field']}": exception['values']
                            }
                        }
                    )

            # Set the time window
            # Set the time range for the old terms query
            query["query"]["bool"]["must"] = [{
                "query_string": {
                    "query": detection.query['query']
                }
            },
                {"range": {
                    "@timestamp": {
                        "gte": "now-{}d".format(detection.new_terms_config['window_size']),
                        "lte": "now"}}}
            ]

            # Determine how many terms actually exist for the query and
            # if they exceed max_terms disable the rule
            query["aggs"] = {
                detection.new_terms_config['key_field']: {
                    'cardinality': {
                        'field': detection.new_terms_config['key_field']
                    }
                }
            }

            res = elastic.conn.search(
                index=_input['config']['index'], body=query)

            if res:
                cardinality = res['aggregations'][detection.new_terms_config['key_field']]['value']
                if cardinality > detection.new_terms_config['max_terms']:
                    self.logger.error(
                        f"New terms rule {detection.uuid} has {cardinality} terms, which exceeds the maximum of {detection.new_terms_config['max_terms']}")
                    update_payload = {
                        'active': False,
                    }
                    if detection.warnings:
                        update_payload['warnings'] = detection.warnings
                        if isinstance(update_payload['warnings'], list) and 'max_terms_exceeded' not in update_payload['warnings']:
                            update_payload['warnings'].append('max_terms_exceeded')
                    else:
                        update_payload['warnings'] = ['max_terms_exceeded']

                    self.agent.update_detection(
                        detection.uuid, payload=update_payload)
                    return

            # Aggregate on the field where the terms should be found
            query["aggs"] = {
                detection.new_terms_config['key_field']: {
                    'terms': {
                        'field': detection.new_terms_config['key_field'],
                        'size': detection.new_terms_config['max_terms']
                    }
                }
            }

            # Search for terms in the window
            res = elastic.conn.search(
                index=_input['config']['index'], body=query)

            if res:
                query_time += res['took']
                old_terms = [term["key"] for term in res["aggregations"]
                             [detection.new_terms_config['key_field']]["buckets"]]

                self.set_new_term_state_entry(
                    detection.uuid, detection.new_terms_config['key_field'], old_terms)

        # If there are no old terms, there is nothing to compare against so skip
        if old_terms == None:
            self.logger.info(
                f"New terms rule {detection.uuid} has no previous terms, skipping")
            return

        query = {
            "query": {
                "bool": {
                    "must": [

                    ]
                }
            },
            "size": 0
        }

        query["query"]["bool"]["must"] = [{
            "query_string": {
                "query": detection.query['query']
            }
        },
            {"range": {
                "@timestamp": {
                    "gte": "now-{}m".format(detection.lookbehind)}}}
        ]

        # Change the aggregation to include the top hit document so we can use it in an alarm
        # should a term be new
        query["aggs"] = {
            detection.new_terms_config['key_field']: {
                'terms': {
                    'field': detection.new_terms_config['key_field'],
                    'size': detection.new_terms_config['max_terms']
                },
                'aggs': {
                    'doc': {
                        'top_hits': {
                            'size': detection.threshold_config['max_events']
                        }
                    }
                }
            }
        }

        # Search for terms in the poll interval
        res = elastic.conn.search(
            index=_input['config']['index'], body=query)

        new_terms = []
        if res:
            query_time += res['took']
            if res["aggregations"][detection.new_terms_config['key_field']]["buckets"]:
                new_terms = [term["key"] for term in res["aggregations"]
                             [detection.new_terms_config['key_field']]["buckets"]]

        # Calculate the difference between the old and new terms
        net_new_terms = [term for term in new_terms if term not in old_terms]

        if net_new_terms:
            self.set_new_term_state_entry(
                detection.uuid, detection.new_terms_config['key_field'], new_terms)
            for term in res["aggregations"][detection.new_terms_config['key_field']]["buckets"]:
                if term["key"] in net_new_terms:
                    docs += term["doc"]["hits"]["hits"]

        if len(docs) > 0:
            docs = elastic.parse_events(docs, title=detection.name, signature_values=[
                                        detection.detection_id], risk_score=detection.risk_score)

            for doc in docs:
                doc.description = getattr(
                    detection, 'description', 'No description provided') or 'No description provided'
                doc.tags += getattr(detection, 'tags') or []
                doc.severity = getattr(detection, 'severity', 1) or 1
                doc.detection_id = getattr(detection, 'uuid', None) or None
                doc.input_uuid = _input['uuid']

        update_payload = {
            'last_run': detection.last_run,
            'hits': len(docs)
        }

        # Calculate how long the entire detection took to run, this helps identify
        # bottlenecks outside the ES query times
        end_execution_timer = datetime.datetime.utcnow()
        total_execution_time = (
            end_execution_timer - start_execution_timer).total_seconds()*1000

        update_payload['time_taken'] = total_execution_time
        update_payload['query_time_taken'] = query_time

        if hasattr(detection, 'total_hits') and detection.total_hits != None:
            update_payload['total_hits'] = detection.total_hits + len(docs)
        else:
            update_payload['total_hits'] = len(docs)

        if len(docs) > 0:

            # Write the docs to Elasticsearch if there are any
            # and the writeback is enabled
            self.writeback(elastic.conn, docs)

            # If the detection has suppression_max_events set to something other than 0
            # suppress the events
            docs = self.suppress_events(detection, docs)

            # If not dropping the event, process the hits
            if not self.drop:
                self.agent.process_events(docs, True)

            update_payload['last_hit'] = datetime.datetime.utcnow().isoformat()

        self.agent.update_detection(detection.uuid, payload=update_payload)

    def threshold_rule(self, detection, credential, _input, signature_fields=[], field_mapping={}):
        """
        Runs a base query and determines if the threshold is above a certain value
        """

        start_execution_timer = datetime.datetime.utcnow()

        # Create a connection to Elasticsearch
        elastic = Elastic(
            _input['config'], field_mapping, credential, signature_fields=signature_fields)

        # If the detection has a max_events configured and it is not greater than what the
        # agent is configured to allow, use the configured value
        # If the detection does not have a max_events configured, default to 10 events
        if 'max_events' in detection.threshold_config:
            if detection.threshold_config['max_events'] > self.config['max_threshold_events']:
                detection.threshold_config['max_events'] = self.config['max_threshold_events']
        else:
            detection.threshold_config['max_events'] = 10

        query = {
            "query": {
                "bool": {
                    "must": [
                        {"query_string": {
                            "query": detection.query['query']}},
                        {"range": {
                            "@timestamp": {"gte": "now-{}m".format(detection.lookbehind)}}}
                    ]
                }
            },
            "size": _input['config']['search_size']
        }

        query["size"] = detection.threshold_config['max_events']

        # If there are exclusions/exceptions add them to the query
        if hasattr(detection, 'exceptions') and detection.exceptions != None:
            query["query"]["bool"]["must_not"] = []
            for exception in detection.exceptions:

                if 'list' in exception and exception['list']['uuid'] != None:
                    list_values = self.agent.get_list_values(
                        uuid=exception['list']['uuid'])
                    exception['values'] = list_values

                query["query"]["bool"]["must_not"].append(
                    {
                        "terms": {
                            f"{exception['field']}": exception['values']
                        }
                    }
                )

        # Change the query if the threshold is based off a key field
        has_key_field = False
        key_field = None
        """ # LIVE CODE """
        if detection.threshold_config['key_field']:
            has_key_field = True
            key_field = detection.threshold_config['key_field']
            query["size"] = 0
            query["aggs"] = {
                detection.threshold_config['key_field']: {
                    'terms': {
                        'field': detection.threshold_config['key_field']
                    },
                    'aggs': {
                        'doc': {
                            'top_hits': {
                                'size': detection.threshold_config['max_events']
                            }
                        }
                    }
                }
            }
        """ # END LIVE CODE """
        """
        # TEST CODE
        if detection.threshold_config['key_field']:
            query["size"] = 0
            has_key_field = True

            # Split the key field if it is a comma separated list, trim whitespace
            if ',' in detection.threshold_config['key_field']:
                key_field = [field.strip()
                             for field in detection.threshold_config['key_field'].split(',')]
            else:
                key_field = detection.threshold_config['key_field']
            
            if isinstance(key_field, str):
                query["aggs"] = create_piped_aggregation(
                    fields=[key_field],
                    threshold=detection.threshold_config['threshold'],
                    max_size=detection.threshold_config['max_events'])
            else:
                query["aggs"] = create_piped_aggregation(
                fields=key_field,
                threshold=detection.threshold_config['threshold'],
                max_size=detection.threshold_config['max_events'])
            
        print(json.dumps(query, indent=2))
        return []
        # END TEST CODE """

        docs = []
        learned_keys = []
        query_time = 0
        scroll_size = 0
        operator = detection.threshold_config['operator']
        threshold = detection.threshold_config['threshold']

        # We have to first learn the keys and then run the query again
        if operator in ['==', "<", "<=", "!="] and threshold == 0 and has_key_field:

            # Copy the query variable to a new variable so we can use it again but as a new object
            query_copy = copy.deepcopy(query)

            # Set the time range to 7 days ago
            # TODO: Set this to a learning period in variable
            query_copy['query']['bool']['must'][1]['range']['@timestamp']['gte'] = "now-14d"

            res = elastic.conn.search(
                index=_input['config']['index'], body=query_copy)

            # If there are aggregations, we need to add the keys to the learned_keys list
            if 'aggregations' in res:
                for bucket in res['aggregations'][key_field]['buckets']:
                    learned_keys.append(bucket['key'])

        if has_key_field:

            if operator in ['==', "<", "<=", "!="] and threshold == 0:
                # query["aggs"][key_field]['terms']['min_doc_count'] = 0
                query["aggs"][key_field]['terms']['size'] = 10000

        res = elastic.conn.search(
            index=_input['config']['index'], body=query)

        query_time = res['took']
        if has_key_field == False:
            hit_count = res['hits']['total']['value']

            hit = self.value_check(hit_count, operator, threshold)

            if hit:
                if operator in ['==', "<", "<=", "!="] and hit_count == 0:
                    docs += [{
                        '_source': {
                            'message': f"No results found.",
                            '_id': str(uuid.uuid4()),
                            '@timestamp': datetime.datetime.utcnow().isoformat()
                        }}]
                else:
                    docs += res['hits']['hits']

        else:
            buckets = res['aggregations'][key_field]['buckets']

            if 'per_field' in detection.threshold_config and detection.threshold_config['per_field']:

                if operator in ['=='] and threshold == 0:
                    bucket_keys = [bucket['key'] for bucket in buckets]
                    for key in learned_keys:
                        if key not in bucket_keys:
                            docs += [{
                                '_source': {
                                    'message': f"No results found for {key}",
                                    '_id': str(uuid.uuid4()),
                                    '@timestamp': datetime.datetime.utcnow().isoformat(),
                                    key_field: key
                                }}]

                else:
                    for bucket in buckets:
                        hit_count = bucket['doc_count']
                        hit = self.value_check(hit_count, operator, threshold)

                        if hit:
                            docs += bucket['doc']['hits']['hits']
            else:
                hit_count = len(buckets)
                hit = self.value_check(hit_count, operator, threshold)

                if hit:
                    if operator in ['=='] and hit_count == 0:
                        docs += [{
                            '_source': {
                                'message': f"No results found",
                                '_id': str(uuid.uuid4()),
                                '@timestamp': datetime.datetime.utcnow().isoformat()
                            }}]
                    else:
                        for bucket in buckets:
                            docs += bucket['doc']['hits']['hits']

        docs = elastic.parse_events(docs, title=detection.name, signature_values=[
                                    detection.detection_id], risk_score=detection.risk_score)

        for doc in docs:
            doc.description = getattr(
                detection, 'description', 'No description provided')
            doc.tags += getattr(detection, 'tags', [])
            doc.severity = getattr(detection, 'severity', 1)
            doc.detection_id = getattr(detection, 'uuid', None)
            doc.input_uuid = _input['uuid']

        update_payload = {
            'last_run': detection.last_run,
            'hits': len(docs)
        }

        # Calculate how long the entire detection took to run, this helps identify
        # bottlenecks outside the ES query times
        end_execution_timer = datetime.datetime.utcnow()
        total_execution_time = (
            end_execution_timer - start_execution_timer).total_seconds()*1000

        update_payload['time_taken'] = total_execution_time
        update_payload['query_time_taken'] = query_time

        if hasattr(detection, 'total_hits') and detection.total_hits != None:
            update_payload['total_hits'] = detection.total_hits + len(docs)
        else:
            update_payload['total_hits'] = len(docs)

        if len(docs) > 0:

            # Write the docs to Elasticsearch if there are any
            # and the writeback is enabled
            self.writeback(elastic.conn, docs)

            # If the detection has suppression_max_events set to something other than 0
            # suppress the events
            docs = self.suppress_events(detection, docs)

            # If not dropping the event, process the hits
            if not self.drop:
                self.agent.process_events(docs, True)

            update_payload['last_hit'] = datetime.datetime.utcnow().isoformat()

        self.agent.update_detection(detection.uuid, payload=update_payload)

    def run_rule_query(self, query, _input, detection, elastic):

        docs = []
        query_time = 0
        scroll_size = 0
        res = elastic.conn.search(
            index=_input['config']['index'], body=query, scroll='30s')

        scroll_id = res['_scroll_id']
        if 'total' in res['hits']:
            if len(res['hits']['hits']) > 0:
                self.logger.info(
                    f"{detection.name} ({detection.uuid}) - Found {len(res['hits']['hits'])} detection hits.")
            query_time += res['took']
            scroll_size = res['hits']['total']['value']

            # Parse the events and extract observables, tags, signature the event
            docs += elastic.parse_events(
                res['hits']['hits'], title=detection.name, signature_values=[detection.detection_id], risk_score=detection.risk_score)
        else:
            scroll_size = 0

        # Scroll
        while (scroll_size > 0):
            self.logger.info(
                f"{detection.name} ({detection.uuid}) - Scrolling Elasticsearch results...")
            # TODO: Move scroll time to config
            res = elastic.conn.scroll(
                scroll_id=scroll_id, scroll='30s')
            if len(res['hits']['hits']) > 0:
                query_time += res['took']
                self.logger.info(
                    f"{detection.name} ({detection.uuid}) - Found {len(res['hits']['hits'])} detection hits.")
                # Parse the events and extract observables, tags, signature the event
                docs += elastic.parse_events(
                    res['hits']['hits'], title=detection.name, signature_values=[detection.detection_id], risk_score=detection.risk_score)

            scroll_size = len(res['hits']['hits'])

        # Clear the scroll
        if scroll_id:
            try:
                elastic.conn.clear_scroll(scroll_id=scroll_id)
            except:
                pass

        if len(docs) > 0:
            self.logger.info(
                f"{detection.name} ({detection.uuid}) - Total Hits {len(docs)}")
        return docs, query_time

    def variable_replacement(self, query):
        """
        Replaces variables in the query with their values for example
        source.ip: ${intel:listname} will be replaced with the values of the intel list
        like source:ip (192.168.1.1 OR 192.168.1.1)
        """

        # Declare the type of variables we support
        variable_types = ['intel']

        # Create a regular expression to detect the variables they are formatted
        # like ${type:setting}
        variable_regex = re.compile(r"\$\{([a-zA-Z0-9_]+):([a-zA-Z0-9_\s]+)\}")

        # Find all the variables in the query
        variables = variable_regex.findall(query)

        # Loop through the variables and replace them with their values
        for variable in variables:
            var_type, var_setting = variable
            var_string = f"${{{var_type}:{var_setting}}}"
            var_values = []
            if var_type in variable_types:

                if var_type == 'intel':
                    var_values = self.agent.get_list_values(name=var_setting)

                variable_values = " OR ".join(var_values)
                if len(var_values) > 1:
                    variable_values = f"({variable_values})"
                query = query.replace(var_string, variable_values)

        return query

    def execute(self, rule):
        """
        Executes a Detection Rule against the defined input on the rule and returns the results
        as events to the API
        """
        detection = Detection(**rule)

        try:
            if detection.should_run(catchup_period=self.config['catchup_period']):
                input_uuid = detection.source['uuid']

                # Grab the field settings for the detection so we can use them to build the query
                # and parse the results
                # TODO: This should be cached in the agent for a period of time
                self.logger.info(
                    f"Fetching field settings for {detection.name}")
                response = self.agent.call_mgmt_api(
                    f"detection/{detection.uuid}/field_settings")

                signature_fields = []
                field_mapping = []

                """Call the API to fetch the expected field settings for this detection which includes
                the fields to extract as observables and the fields to use as signature fields
                If the API call fails, skip the detection run entirely and log an error
                If the API call succeeds but the response is not valid JSON, skip the detection run
                If the result of the API call is empty signature fields or fields default to using the
                defaults from the input
                """
                if response and response.status_code == 200:
                    try:
                        field_settings = response.json()
                        if 'signature_fields' in field_settings and len(field_settings['signature_fields']) > 0:
                            signature_fields = field_settings['signature_fields']
                        if 'fields' in field_settings and len(field_settings['fields']) > 0:
                            field_mapping = field_settings
                    except:
                        self.logger.error(
                            f"Failed to parse field settings for {detection.name}")
                        return
                else:
                    self.logger.error(
                        f"Failed to fetch field settings for {detection.name}")
                    return

                # Get the input or report an error if the agent doesn't know it
                if input_uuid in self.inputs:
                    _input = self.inputs[input_uuid]
                else:
                    # TODO: Add a call to insert a reflex-detections-log record
                    self.logger.error(
                        f"Detection {detection.name} attempted to use source {input_uuid} but no input found")
                    return

                # If the length of signature fields or field_mapping is 0 use the settings from the input
                if len(signature_fields) == 0:
                    signature_fields = _input['config']['signature_fields']
                if len(field_mapping) == 0:
                    field_mapping = _input['config']['fields']

                # Get the credential or report an error if the agent doesn't know it
                if _input['credential'] in self.credentials:
                    credential = self.credentials[_input['credential']]
                else:
                    # TODO: Add a call to insert a reflex-detections-log record
                    self.logger.error(
                        f"Detection {detection.name} attempted to use credential {_input['credential']} but no credential found")
                    return

                # Massage the query to replace variables with their values
                detection.query['query'] = self.variable_replacement(
                    detection.query['query'])

                self.logger.info(
                    f"Running detection {detection.name} using {_input['name']} ({_input['uuid']}) and credential {_input['credential']} - Lookbehind {detection.lookbehind} minutes.")

                if _input['plugin'] == "Elasticsearch":

                    docs = []

                    query_time = 0
                    scroll_size = 0
                    start_execution_timer = datetime.datetime.utcnow()

                    # Create a connection to Elasticsearch
                    elastic = Elastic(
                        _input['config'],
                        field_mapping=field_mapping,
                        credentials=credential,
                        signature_fields=signature_fields
                    )

                    rule_types = {
                        0: self.match_rule,
                        1: self.threshold_rule,
                        2: self.metric_rule,
                        3: self.mismatch_rule,
                        4: self.new_terms_rule,
                        5: self.indicator_match_rule,
                        6: self.data_source_monitor_rule
                    }

                    detection.last_run = datetime.datetime.utcnow().isoformat()

                    if detection.rule_type != 0:
                        rule_types[detection.rule_type](
                            detection, credential, _input, signature_fields, field_mapping)

                    if detection.rule_type == 0:

                        if 'config' in _input:
                            if 'alert_date_field' in _input['config']:
                                alert_date_field = _input['config']['alert_date_field']
                            else:
                                alert_date_field = '@timestamp'

                        # TODO: Support for multiple queries
                        query = {
                            "query": {
                                "bool": {
                                    "must": [
                                        {"query_string": {
                                            "query": detection.query['query']}},
                                        {"range": {
                                            alert_date_field: {"gte": "now-{}m".format(detection.lookbehind)}}}
                                    ]
                                }
                            },
                            "size": _input['config']['search_size']
                        }

                        # If there are exclusions/exceptions add them to the query
                        if hasattr(detection, 'exceptions') and detection.exceptions != None:
                            query["query"]["bool"]["must_not"] = []
                            for exception in detection.exceptions:

                                if 'list' in exception and exception['list']['uuid'] != None:
                                    list_values = self.agent.get_list_values(
                                        uuid=exception['list']['uuid'])
                                    exception['values'] = list_values

                                query["query"]["bool"]["must_not"].append(
                                    {
                                        "terms": {
                                            f"{exception['field']}": exception['values']
                                        }
                                    }
                                )

                        res = elastic.conn.search(
                            index=_input['config']['index'], body=query, scroll='30s')

                        scroll_id = res['_scroll_id']
                        if 'total' in res['hits']:
                            self.logger.info(
                                f"{detection.name} ({detection.uuid}) - Found {len(res['hits']['hits'])} detection hits.")
                            query_time += res['took']
                            scroll_size = res['hits']['total']['value']

                            # Parse the events and extract observables, tags, signature the event
                            docs += elastic.parse_events(
                                res['hits']['hits'], title=detection.name, signature_values=[
                                    detection.detection_id], risk_score=detection.risk_score,
                                time_to_detect=True)
                        else:
                            scroll_size = 0

                        # Scroll
                        while (scroll_size > 0):
                            self.logger.info(
                                f"{detection.name} ({detection.uuid}) - Scrolling Elasticsearch results...")
                            # TODO: Move scroll time to config
                            res = elastic.conn.scroll(
                                scroll_id=scroll_id, scroll='30s')
                            if len(res['hits']['hits']) > 0:
                                query_time += res['took']
                                self.logger.info(
                                    f"{detection.name} ({detection.uuid}) - Found {len(res['hits']['hits'])} detection hits.")
                                # Parse the events and extract observables, tags, signature the event
                                docs += elastic.parse_events(
                                    res['hits']['hits'], title=detection.name, signature_values=[
                                        detection.detection_id], risk_score=detection.risk_score,
                                    time_to_detect=True)

                            scroll_size = len(res['hits']['hits'])

                        # Clear the scroll
                        if scroll_id:
                            try:
                                elastic.conn.clear_scroll(scroll_id=scroll_id)
                            except:
                                pass

                        self.logger.info(
                            f"{detection.name} ({detection.uuid}) - Total Hits {len(docs)}")

                        # Update all the docs to have detection rule hard values
                        if docs:
                            for doc in docs:
                                doc.description = getattr(
                                    detection, 'description', 'No description provided')
                                doc.tags += getattr(detection,
                                                    'tags', []) or []
                                doc.severity = getattr(
                                    detection, 'severity', 1)
                                doc.detection_id = getattr(
                                    detection, 'uuid', None)
                                doc.input_uuid = _input['uuid']

                        update_payload = {
                            'last_run': detection.last_run,
                            'hits': len(docs)
                        }

                        if hasattr(detection, 'total_hits') and detection.total_hits != None:
                            update_payload['total_hits'] = detection.total_hits + \
                                len(docs)
                        else:
                            update_payload['total_hits'] = len(docs)

                        if len(docs) > 0:
                            update_payload['last_hit'] = datetime.datetime.utcnow(
                            ).isoformat()

                        # Calculate how long the entire detection took to run, this helps identify
                        # bottlenecks outside the ES query times
                        end_execution_timer = datetime.datetime.utcnow()
                        total_execution_time = (
                            end_execution_timer - start_execution_timer).total_seconds()*1000

                        update_payload['time_taken'] = total_execution_time
                        update_payload['query_time_taken'] = query_time

                        # Update the detection with the meta information from this run
                        self.agent.update_detection(
                            detection.uuid, payload=update_payload)

                        # Write the docs to Elasticsearch if there are any
                        # and the writeback is enabled
                        self.writeback(elastic.conn, docs)

                        # If the detection has suppression_max_events set to something other than 0
                        # suppress the events
                        docs = self.suppress_events(detection, docs)

                        # Close the connection to Elasticsearch
                        elastic.conn.transport.close()

                        # Send the detection hits as events to the API
                        # If not dropping the event, process the hits
                        if not self.drop:
                            self.agent.process_events(docs, True)

        except ConnectionTimeout as e:
            self.logger.error(
                f"Detection {detection.name} encountered an error: {e}")
            update_payload = {
                'warnings': ['timeout-error']
            }
            self.agent.update_detection(
                detection.uuid, payload=update_payload)
        except Exception as e:
            self.logger.error(
                f"Detection {detection.name} encountered an error: {e}")

    def run_rules(self):
        """
        Runs the set of rules configured for this detection agent
        """

        with ThreadPoolExecutor(max_workers=self.config['concurrent_rules']) as executor:
            executor.map(self.execute, self.detection_rules)

        '''

        def split_rules(rules, concurrent_rules):
            """
            Splits a set of rules into a smaller set
            """
            for i in range(0, len(rules), concurrent_rules):
                yield rules[i:i + concurrent_rules]

        # Determine which rules to run in parallel based on the concurrent_rules setting
        if self.detection_rules:
            rule_sets = list(split_rules(self.detection_rules,
                                         self.config['concurrent_rules']))
        else:
            rule_sets = []

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
        '''

    def run(self):
        """
        Periodically runs detection rules as defined by the ReflexSOAR API
        """
        self.logger.info('Starting detection agent')
        while self.running:

            self.logger.info('Fetching detections')
            self.load_detections()

            def run_func(f):
                f()

            # Run rules in its own thread
            with ThreadPoolExecutor(max_workers=2) as executor:
                executor.map(run_func, [self.run_rules, self.assess_rules])

            #self.run_rules()
            #self.assess_rules()

            self.update_input_mappings()
            self.logger.info('Run complete, waiting')

            if self.should_exit.is_set():
                self.logger.info('Shutting down')
                break

            time.sleep(self.config['wait_interval'])
