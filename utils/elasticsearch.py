import copy
import datetime
from elasticsearch import Elasticsearch
from multiprocessing import Process
from retry import retry
from dateutil import parser
import json
import ssl
import chevron
import ipaddress
from loguru import logger

from .base import Event

class Elastic(Process):

    def __init__(self, config, field_mapping, credentials, signature_fields=[], input_uuid=None, timeout=30):
        ''' 
        Initializes a new Elasticsearch poller object
        which pushes information to the api
        '''

        self.config = config
        self.status = 'waiting'
        self.credentials = credentials
        self.field_mapping = field_mapping
        self.plugin_type = 'events'
        self.signature_fields = []
        self.input_uuid = input_uuid
        self.timeout = timeout

        # If signature_fields are passed in, use them instead of the ones in the config file
        if signature_fields:
            self.signature_fields = signature_fields
        else:
            if 'signature_fields' in config:
                self.signature_fields = config['signature_fields']

        self.conn = self.build_es_connection()

    
    def build_es_connection(self):
        '''
        Creates an Elasticsearch connection object that can
        be used to query Elasticsearch
        '''

        # Create an empty configuration object
        es_config = {   
            'retry_on_timeout': True,
            'timeout': self.timeout,
            'max_retries': 3,
            'ssl_show_warn': False
        }

        # If we are defining a ca_file use ssl_contexts with the ca_file
        # else disable ca_certs and verify_certs and don't use ssl_context
        if 'cafile' in self.config and self.config['cafile'] != "":

            context = ssl.create_default_context(cafile=self.config['cafile'])
            CONTEXT_VERIFY_MODES = {
                "none": ssl.CERT_NONE,
                "optional": ssl.CERT_OPTIONAL,
                "required": ssl.CERT_REQUIRED
            }
        
            context.verify_mode = CONTEXT_VERIFY_MODES[self.config['cert_verification']]
            context.check_hostname = self.config['check_hostname']
            es_config['ssl_context'] = context
        else:
            #es_config['ca_certs'] = False
            es_config['verify_certs'] = False
            #es_config['ssl_assert_hostname'] = self.config['check_hostname']        

        # Set the API Authentication method
        if self.config['auth_method'] == 'api_key':
            es_config['api_key'] = self.credentials
        else:
            es_config['http_auth'] = self.credentials

        # Swap distros depending on the inputs configuration
        if 'distro' in self.config:
            if self.config['distro'] == 'opensearch':
                from opensearchpy import OpenSearch
                
                return OpenSearch(self.config['hosts'], **es_config)
            else:
                return Elasticsearch(self.config['hosts'], **es_config)
        else:
            return Elasticsearch(self.config['hosts'], **es_config)


    def extract_observables(self, source):
        ''' 
        extracts observables from fields mappings
        and returns an array of artifacts to add
        to the alarm 
        '''
        
        observables = []
        for field in self.field_mapping['fields']:

            # Skip fields that don't have an associated data type
            if field['data_type'] == 'none':
                continue

            if 'ioc' not in field:
                field['ioc'] = False

            if 'spotted' not in field:
                field['spotted'] = False

            if 'safe' not in field:
                field['safe'] = False

            tags = []
            if 'tags' in field:
                if field['tags'] is not None:
                    tags += field['tags']

            value = self.get_nested_field(source, field['field'])

            data_type = field['data_type']
            # Check to make sure the value isn't actually an IP address
            # if it is, change the data type to ip
            try:
                i = ipaddress.ip_address(value)
                if isinstance(i, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                    data_type = 'ip'
            except:
                pass

            source_field = field['field']
            original_source_field = field['field']

            # Set the source_field as the alias if one is defined
            if 'alias' in field and field['alias']:
                source_field = field['alias']

            if value:
                # Create a new observable for each item in the list
                if isinstance(value, list):
                    for item in value:
                        observables += [{
                            "value":str(item),
                            "data_type":data_type,
                            "tlp":field['tlp'],
                            "ioc": field['ioc'],
                            "safe": field['safe'],
                            "spotted": field['spotted'],
                            "tags":tags,
                            "source_field": source_field,
                            "original_source_field": original_source_field
                        }]
                else:
                    observables += [{
                        "value":str(value),
                        "data_type":data_type,
                        "tlp":field['tlp'],
                        "ioc": field['ioc'],
                        "safe": field['safe'],
                        "spotted": field['spotted'],
                        "tags":tags,
                        "source_field": source_field,
                        "original_source_field": original_source_field
                    }]
            else:
                pass
        return observables


    def parse_events(self, hits, title=None, signature_values=[], risk_score=None,
                     time_to_detect=False):
        '''
        Parses events pulled from Elasticsearch and formats them 
        into a JSON array that fits the expected input of the REST API
        '''

        events = []
        for record in hits:

            _sig_values = copy.copy(signature_values)
            
            source = record['_source']
            
            # Clone the _id field of the elasticsearch/opensearch document into _source
            if '_id' in record:
                source['_id'] = record['_id']

            event = self.set_base_alert(source, title=title, risk_score=risk_score)
            observables = self.extract_observables(source)
            if observables:
                event.observables = observables

            # Add tags to an event based on an array of source fields e.g. signal.rule.tags
            # tags from tag_fields will be added like 'event.code: 4624' where event.code is the
            # source field and 4625 is the value of the field
            if 'tag_fields' in self.config:
                tags = []
                for tag_field in self.config['tag_fields']:
                    tags = self.get_nested_field(source, tag_field)
                    if tags:
                        if isinstance(tags, list):
                            for tag in tags:
                                if tag:
                                    event.tags += [f"{tag_field}: {tag}"]
                        else:
                            event.tags += [f"{tag_field}: {tags}"]

            if 'static_tags' in self.config:
                if isinstance(self.config['static_tags'], list):
                    event.tags += self.config['static_tags']
                else:
                    event.tags += [self.config['static_tags']]

            if 'signature_fields' in self.config:
                event.generate_signature(source=source, fields=self.signature_fields, signature_values=_sig_values)
            else:
                event.generate_signature(source=source, signature_values=_sig_values)

            # If this is an Elastic Detection/Signal, extract the 
            # detection tags
            if 'signal' in source:
                event.tags += self.create_mitre_tags(source['signal']['rule']['threat'])
            #    event.tags += source['signal']['rule']['tags']
            
            # Remove duplicate tags
            event.tags = [tag for tag in event.tags if tag not in ['',None,'-']]
            event.tags = list(set(event.tags))

            if time_to_detect:
                
                if hasattr(event, 'original_date'):
                    now = datetime.datetime.utcnow()
                    try:
                        original_date = parser.parse(event.original_date)
                    except ValueError:
                        original_date = datetime.datetime.utcnow()

                    # Fix for original date being timezone aware
                    if original_date.tzinfo is not None:
                        event.time_to_detect = (now.astimezone(original_date.tzinfo) - original_date).total_seconds()
                    else:
                        event.time_to_detect = (now - original_date).total_seconds()

            events.append(event)
        
        return events


    @retry(delay=30, tries=10)
    def poll(self):
        '''
        Polls an Elasticsearch index using a scroll window
        Returns a collection of events
        '''

        events = []

        try:
            if 'lucene_filter' in self.config:
                body = {
                        "query": {
                            "bool": { 
                                "must": [
                                        {"query_string": { "query": self.config['lucene_filter'] }},
                                        {"range": {"@timestamp": {"gte": "now-{}".format(self.config['search_period'])}}}
                                    ]
                                }
                        },
                        "size": self.config['search_size']}
            else:
                body = {"query": {"range": {"@timestamp": {"gte": "now-{}".format(self.config['search_period'])}}}, "size":self.config['search_size']}
            res = self.conn.search(index=str(self.config['index']), body=body, scroll='2m') # TODO: Move scroll time to config

            scroll_id = None
            if '_scroll_id' in res:
                scroll_id = res['_scroll_id']

            if 'total' in res['hits']:
                logger.info(f"Found {len(res['hits']['hits'])} alerts.")
                scroll_size = res['hits']['total']['value']
                events += self.parse_events(res['hits']['hits'])
            else:
                scroll_size = 0
                
            # Scroll
            if scroll_id:
                while (scroll_size > 0):
                    logger.info("Scrolling Elasticsearch results...")
                    res = self.conn.scroll(scroll_id = scroll_id, scroll = '2m') # TODO: Move scroll time to config
                    if len(res['hits']['hits']) > 0:
                        logger.info(f"Found {len(res['hits']['hits'])} alerts.")
                        events += self.parse_events(res['hits']['hits'])
                    scroll_size = len(res['hits']['hits'])

            # Clear the scroll window
            if scroll_id:
                self.conn.clear_scroll(scroll_id = scroll_id)

            return events

        except Exception as e:
            logger.error("Failed to run search, make sure the Elasticsearch cluster is reachable. {}".format(e))
            return []
        
    def run(self):
        '''
        Polls an elasticsearch index at a set interval and pushes
        event data to the Events queue
        '''
        self.start_working()
        return self.poll()


    def start_working(self):
        ''' Sets a human readible status of 'working' '''
        self.status = 'working'

    def start_waiting(self):
        ''' Sets a human readible status of 'waiting' '''

        self.status = 'waiting'

    def stop_working(self):
        ''' Stops the worker process '''

        self.status = 'stopped'
        self.kill_received = True

    def get_nested_field(self, message, field):
        '''
        Iterates over nested fields to get the final desired value
        e.g signal.rule.name should return the value of name

        Paramters:
            message (dict): A dictionary of values you want to iterate over
            field (str): The field you want to extract from the message in dotted format

        Return:
            value: The extracted value, may be the response from this function calling itself again
        '''

        if field and message:
            flat_key = '.'.join(field)
            if flat_key in message:
                return message[flat_key]


        if isinstance(field, str) and message:
            if field in message:
                return message[field]

            args = field.split('.')
        else:
            args = field

        if args and message:
            element = args[0]
            if element:
                if isinstance(message, list):
                    values = []
                    value = [m for m in message if m is not None]
                    if any(isinstance(i, list) for i in value):
                        for l in value:
                            if isinstance(l, list):
                                values += [v for v in l if v is not None]
                    else:
                        values += [v for v in value if not isinstance(v, list)]
                    value = values                    
                else:
                    if isinstance(message, dict):
                        value = message.get(element)
                    else:
                        value = message

                if isinstance(value, list):
                    if len(value) > 0 and isinstance(value[0], dict):
                        if len(args) > 1:
                            value = [self.get_nested_field(item, args[1:]) for item in value]

                return value if len(args) == 1 else self.get_nested_field(value, args[1:])


    def create_mitre_tags(self, threats):
        '''
        Returns a unique list of tags based on MITRE attack
        techniques/tactics. Use specifically by Elastic signals
        '''

        tags = []

        if len(threats) > 0:
            for threat in threats:
                tags += [threat['tactic']['id']]

                for tech in threat['technique']:
                    tags += [tech['id']]

        return list(set(tags))


    def set_alert_field_using_field_data(self, source, field_name):
        '''
        Sets the content of a field using the chevron format
        '''

        field_value = self.config[field_name]
        if '{{source}}' in field_value:
            field_value = field_value.replace('{{source}}', json.dumps(source, sort_keys=True, indent=4))
        field_value = str(chevron.render(field_value, source))
        return field_value


    def severity_from_string(self, s):
        '''
        Returns an integer representation of the severity
        If the severity doesn't match default to low
        '''

        severities = {
            'informational': 0,
            'info': 0,
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
        s = s.lower()

        if s in severities:
            return severities[s]
        return 1


    def set_base_alert(self, source, title=None, risk_score=None):
        '''
        Sets the base information of the event by pulling
        fields defined in the Elastic input config
        '''

        event = Event()

        if hasattr(event, 'metrics'):
            event.metrics['agent_pickup_time'] = datetime.datetime.utcnow().isoformat()

        # Pull the event title unless overridden
        if not title:
            event.title = self.get_nested_field(source, self.config['rule_name'])
        else:
            event.title = title
        
        if 'description_field' in self.config:
            event.description = self.get_nested_field(source, self.config['description_field'])
        else:
            event.description = ''

        # Pull the default TLP, Event Type, Source
        # from the input configuration
        for field in ['tlp','type','source']:
            if field in self.config:
                setattr(event, field, self.config[field])

        # Track the input UUID that generated this event
        event.input_uuid = self.input_uuid

        # Replace the source of the event with the name of the index
        # if the source name was never defined
        if 'source' not in self.config:
            event.source = str(self.config['index']).replace('-*','')
        
        # Get the reference field, this should be unique per event
        event.reference = self.get_nested_field(source, self.config['source_reference'])

        # Find the original event date if supplied
        if 'original_date_field' in self.config:
            original_date_field = self.get_nested_field(source, self.config['original_date_field'])
            if original_date_field:
                event.original_date = original_date_field.replace('Z','')

        # Get the event severity field
        # if none is defined, default to Low
        if 'severity_field' in self.config:
            severity = self.get_nested_field(source, self.config['severity_field'])
            if isinstance(severity, str):
                event.severity = self.severity_from_string(severity)
            else:
                event.severity = severity
        else:
            event.severity = 0

        if risk_score:
            event.risk_score = risk_score

        # Set the raw_log field
        event.raw_log = json.dumps(source)

        return event
