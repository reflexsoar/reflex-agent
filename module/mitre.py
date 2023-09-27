import logging
import time
from multiprocessing import Process, Event
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED

from utils.elasticsearch import Elastic


class MitreMapper(Process):
    '''
    The MitreMapper role automatically maps target indices to MITRE ATT&CK data
    sources on a period basis.  This is done by consuming Data Source Mapping
    templates from the ReflexSOAR API, the configured Inputs in the Reflex API
    and running mapped queries against all indices.
    '''

    def __init__(self, config, agent=None, log_level='INFO', *args, **kwargs):

        super(MitreMapper, self).__init__(*args, **kwargs)

        # Establish a basic configuration
        if config:
            self.config = config
        else:
            self.config = {
                'concurrent_inputs': 10,
                'graceful_exit': False,
                'mapping_refresh_interval': 60,
                'logging_level': log_level,
                'assessment_days': 14
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
        self.logger.setLevel(log_levels[self.config['logging_level']])
        self.log_level = self.config['logging_level']
        self.agent = agent
        self.inputs = {}
        self.data_source_templates = {}
        self.should_exit = Event()

    def build_connection(self, target_input):
        """
        Returns a connection object to ElasticSearch
        """

        credential = self.agent.fetch_credentials(target_input['credential'])

        return Elastic(
            target_input['config'],
            {},
            credential,
            []
        )

    def map_input_to_data_source(self, target_input):
        '''
        Maps an index to a data source template
        '''

        input_name = target_input['name']
        input_uuid = target_input['uuid']

        if len(target_input.get('data_source_templates', [])) == 0:
            self.logger.info(f"No data source templates found for { input_name } ({ input_uuid })")
            return
        
        try:
            es = self.build_connection(target_input)
        except Exception as e:
            self.logger.error(f"Failed to build connection: {e}")
            return
        
        try:
            if not es.conn.ping():
                self.logger.error(f"Failed to ping { input_name } ({ input_uuid })")
                return
        except Exception as e:
            self.logger.error(f"Failed to ping { input_name } ({ input_uuid }): {e}")
            return
            

        # Build a multisearch query for each data source in the data source templates sources
        # array and then execute that search against the target input

        assessment_days = self.config['assessment_days']

        query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": f"now-{assessment_days}d",
                                }
                            }
                        }
                    ]
                }
            },
            "aggs": {},
            "size": 0
        }

        for template in self.data_source_templates:
            if template['uuid'] in target_input['data_source_templates']:
                for source in template['sources']:
                    query['aggs'][source['name']] = {
                        "filter": {
                            "query_string": {
                                "query": source['query']
                            }
                        }
                    }
        
        self.logger.info(f"Mapping { input_name } ({ input_uuid }) to a data source template")

        observed_data_sources = []
        try:
            results = es.conn.search(index=target_input['config']['index'], body=query)
            if 'aggregations' in results:
                for agg in results['aggregations']:
                    # If the count is greater than 0, add the data source to the list
                    if results['aggregations'][agg]['doc_count'] > 0:
                        observed_data_sources.append(agg)
            
                # Update the data sources, even if the list is empty
                self.update_input_data_sources(target_input['uuid'], observed_data_sources)
            
        except Exception as e:
            self.logger.error(f"Failed to execute search: {e}")

        return

    def load_inputs(self):
        '''
        Fetches all the inputs from the Reflex API within this agents
        organization
        '''
        response = self.agent.call_mgmt_api('input')
        if response.status_code == 200:
            self.inputs = response.json()['inputs']
        else:
            self.logger.error(f"Failed to get inputs: {response.text}")

    def update_input_data_sources(self, uuid, data_sources):
        '''
        Updates the data sources for a given input
        '''
        response = self.agent.call_mgmt_api(f"input/{uuid}", method='PUT', data={
            'mitre_data_sources': data_sources
        })
        if response.status_code == 200:
            self.logger.info(f"Updated data sources for {uuid}")
        else:
            self.logger.error(f"Failed to update data sources for {uuid}: {response.text}")

    def load_data_source_templates(self):
        '''
        Fetches all the data source templates from the Reflex API within this
        agents organization
        '''
        response = self.agent.call_mgmt_api('data_source_template')
        if response.status_code == 200:
            self.data_source_templates = response.json()['templates']
        else:
            self.logger.error(
                f"Failed to get data source templates: {response.text}")


    def run(self):
        """
        Periodically runs the mapping process
        """
        self.logger.info(f'Starting the {self.__class__.__name__} role')
        while self.running:

            self.logger.info('Loading data source templates')
            self.load_data_source_templates()
            self.logger.info('Loading inputs')
            self.load_inputs()

            with ThreadPoolExecutor(
                max_workers=self.config['concurrent_inputs']) as executor:
                executor.map(self.map_input_to_data_source, self.inputs)

            self.logger.info('Mapping complete, waiting')

            if self.should_exit.is_set():
                self.logger.info('Shutting down')
                break

            # mapping_refresh_interval is in minutes, convert to seconds
            time.sleep(self.config['mapping_refresh_interval']*60)