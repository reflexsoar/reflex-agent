from elasticsearch import Elasticsearch
from multiprocessing import Process
from retry import retry
import json
import ssl
import base64
import chevron
import logging
import hashlib

from .base import Event


class Elastic(Process):

    def __init__(self, config, field_mapping, credentials):
        ''' 
        Initializes a new Elasticsearch poller object
        which pushes information to the api
        '''
        self.config = config
        self.status = 'waiting'
        self.credentials = credentials
        self.field_mapping = field_mapping
        self.conn = self.build_es_connection()
        self.plugin_type = 'events'

    
    def build_es_connection(self):
        '''
        Creates an Elasticsearch connection object that can
        be used to query Elasticsearch
        '''

        # Create an empty configuration object
        es_config = {            
        }

        # If we are defining a ca_file use ssl_contexts with the ca_file
        # else disable ca_certs and verify_certs and don't use ssl_context
        if self.config['cafile'] != "":

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
            es_config['ca_certs'] = False
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

            if 'ioc' not in field:
                field['ioc'] = False

            if 'spotted' not in field:
                field['spotted'] = False

            if 'safe' not in field:
                field['safe'] = False

            tags = []
            if 'tags' in field:
                tags += field['tags']

            value = self.get_nested_field(source, field['field'])

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
                            "value":item,
                            "data_type":field['data_type'],
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
                        "value":value,
                        "data_type":field['data_type'],
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


    def parse_events(self, hits):
        '''
        Parses events pulled from Elasticsearch and formats them 
        into a JSON array that fits the expected input of the REST API
        '''

        events = []
        for record in hits:
            source = record['_source']
            
            # Clone the _id field of the elasticsearch/opensearch document into _source
            if '_id' in record:
                source['_id'] = record['_id']

            event = self.set_base_alert(source)
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
                event.generate_signature(source=source, fields=self.config['signature_fields'])

            # If this is an Elastic Detection/Signal, extract the 
            # detection tags
            if 'signal' in source:
                event.tags += self.create_mitre_tags(source['signal']['rule']['threat'])
            #    event.tags += source['signal']['rule']['tags']
            
            # Remove duplicate tags
            event.tags = [tag for tag in event.tags if tag not in ['',None,'-']]
            event.tags = list(set(event.tags))

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
                                        {"range": {"@timestamp": {"gt": "now-{}".format(self.config['search_period'])}}}
                                    ]
                                }
                        },
                        "size": self.config['search_size']}
            else:
                body = {"query": {"range": {"@timestamp": {"gt": "now-{}".format(self.config['search_period'])}}}, "size":self.config['search_size']}
            res = self.conn.search(index=str(self.config['index']), body=body, scroll='2m') # TODO: Move scroll time to config

            scroll_id = res['_scroll_id']
            if 'total' in res['hits']:
                logging.info(f"Found {len(res['hits']['hits'])} alerts.")
                scroll_size = res['hits']['total']['value']
                events += self.parse_events(res['hits']['hits'])
                                
            else:
                scroll_size = 0
                
            # Scroll
            while (scroll_size > 0):
                logging.info("Scrolling Elasticsearch results...")
                res = self.conn.scroll(scroll_id = scroll_id, scroll = '2m') # TODO: Move scroll time to config
                logging.info(f"Found {len(res['hits']['hits'])} alerts.")
                events += self.parse_events(res['hits']['hits'])
                scroll_size = len(res['hits']['hits'])

            return events

        except Exception as e:
            logging.error("Failed to run search, make sure the Elasticsearch cluster is reachable. {}".format(e))
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
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
        s = s.lower()

        if s in severities:
            return severities[s]
        return 1


    def set_base_alert(self, source):
        '''
        Sets the base information of the event by pulling
        fields defined in the Elastic input config
        '''

        event = Event()

        # Pull the event title
        event.title = self.get_nested_field(source, self.config['rule_name'])
        if 'description_field' in self.config:
            event.description = self.get_nested_field(source, self.config['description_field'])
        else:
            event.description = ''

        # Pull the default TLP, Event Type, Source
        # from the input configuration
        for field in ['tlp','type','source']:
            if field in self.config:
                setattr(event, field, self.config[field])

        # Replace the source of the event with the name of the index
        # if the source name was never defined
        if 'source' not in self.config:
            event.source = str(self.config['index']).replace('-*','')
        
        # Get the reference field, this should be unique per event
        event.reference = self.get_nested_field(source, self.config['source_reference'])

        # Find the original event date if supplied
        if 'original_date_field' in self.config:
            event.original_date = self.get_nested_field(source, self.config['original_date_field']).replace('Z','')

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

        # Set the raw_log field
        event.raw_log = json.dumps(source)

        return event
