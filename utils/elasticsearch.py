from elasticsearch import Elasticsearch
from multiprocessing import Process
import ssl
import base64
import chevron

from base import EVENT_BODY


class Elastic(Process):

    def __init__(self, config, credentials):
        ''' 
        Initializes a new Elasticsearch poller object
        which pushes information to the api
        '''
        self.config = config
        self.status = 'waiting'
        self.credentials = credentials
        self.conn = self.build_es_connection()

    
    def build_es_connection(self):
        '''
        Creates an Elasticsearch connection object that can
        be used to query Elasticsearch
        '''

        if self.config['ca_file'] != "":
            # TODO: Make this work using base64 encoded certificate file
            raise NotImplementedError
        else:
            context = ssl.create_default_context()
        context.check_hostname = self.config['check_hostname']

        es_config = {
            'scheme': self.config['scheme'],
            'ssl_context': context
        }

        if self.config['auth_method'] == 'api_key':
            es_config['api_key'] = self.credentials
        else:
            es_config['api_key'] = self.credentials

        return = Elasticsearch(self.config['hosts'], **es_config)


    def extract_observables(self, source, field_mapping):
        ''' 
        extracts observables from fields mappings
        and returns an array of artifacts to add
        to the alarm 
        '''
        
        observables = []
        for field in field_mapping:
            tags = []
            if 'tags' in field:
                tags += field['tags']

            value = self.get_nested(source, *field['field'].split('.'))
            if value:
                if isinstance(value, list):
                    value = ' '.join(value)
                observables += [{"value":value, "dataType":field['dataType'], "tlp":field['tlp'], "tags":tags,}]
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
            observables = self.extract_observables(source, self.config['field_mapping'])
            event = {
                'title': source['signal']['rule']['name'],
                'description': source['signal']['rule']['description'],
                'reference': source['signal']['parent']['id'],
                'tags': ['foo','bar'],
                'raw_log': json.dumps(source)
            }
            if observables:
                event['observables'] = observables
            events.append(event)
            
        return events


    def poll(self):
        '''
        Polls an Elasticsearch index using a scroll window
        Returns a collection of events
        '''

        events = []

        try:
            # TODO: Move ES_QUERY_HISTORY and ES_QUERY_SIZE input config
            body = {'query': {'range': {"@timestamp": {"gt": "now-{}".format('1h')}}}, 'size':200}
            res = self.conn.search(index=self.index, body=body, scroll='2m') # TODO: Move scroll time to config

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

                # TODO: DEDUPE THIS CODE
                for doc in res['hits']['hits']:
                    events += self.parse_events(res['hits']['hits'])

                scroll_size = len(res['hits']['hits'])
        except Exception as e:
            print(e)
            logging.error("Failed to run search, make sure the Elasticsearch cluster is reachable")

        return events


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


    def get_nested_field(self, message, *args):
        '''
        Iterates over nested fields to get the final desired value
        e.g signal.rule.name should return the value of name
        '''

        if args and message:
            element = args[0]
            if element:
                value = message.get(element)
                return value if len(args) == 1 else self.get_nested_field(value, *args[1:])


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


    def set_base_alert(self, source, description):
        '''
        Sets the base information of the event by pulling
        fields defined in the Elastic input config
        '''

        event = EVENT_BODY

        # Pull the event title
        alert['title'] = self.set_alert_field_using_field_data(source, 'title')

        # Pull the default TLP, Event Type, Source
        # from the input configuration
        for field in ['tlp','type','source']:
            if field in self.config:
                event[field] = self.config[field]

        # Replace the source of the event with the name of the index
        # if the source name was never defined
        if 'source' not in self.config:
            event['source'] = str(pipeline['index']).replace('-*','')
        
        # Get the reference field, this should be unique per event
        alert['reference'] = self.get_nested_field(source, self.config['reference'])

        if 'severity_field': in self.config:
            event['severity'] = sour
