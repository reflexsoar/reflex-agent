import time
from loguru import logger

class BaseRule:
    ''' Defines a base class used by all rule types '''

    def __init__(self, detection: dict, detection_input, elastic = None, agent = None):
        ''' Initializes the rule type '''

        self.type_num = -1
        self.type_name = 'base'

        self.detection = detection

        if not agent:
            raise ValueError('Agent is required')
        self.agent = agent

        if not elastic:
            raise ValueError('elastic is required')
        self.conn = elastic # Connection to the backend to query for data

        if not detection_input:
            raise ValueError('Detection input is required')
        self.detection_input = detection_input # The input for the detection

        self.execution_time = 0.0 # Time taken to execute the detection
        self.errors = [] # List of errors that occurred during execution
        self.error = False # Whether or not an error occurred during execution
        self.query = {
            "query": {
                "bool": {
                    "must": []
                }
            }
        } # The query used to execute the detection
        self.set_exclusions()

    def add_exclusion(self, exclusion: str):
        ''' Adds an exclusion to the detection '''

        if 'list' in exclusion and exclusion['list']['uuid'] is not None:
            list_values = self.agent.get_list_values(exclusion['list']['uuid'])
            if exclusion['values'] is not None:
                exclusion['values'].extend(list_values)
            else:
                exclusion['values'] = list_values

        self.query['query']['bool']['must_not'].append({
            "terms": {
                f"{exclusion['field']}": exclusion['values']
            }
        })

    def set_base_filter(self, query_filter: str):
        ''' Sets the base query for the detection '''
        self.query['query']['bool']['must'].append(query_filter)

    def set_exclusions(self):
        '''Sets the exclusions based on the detection'''
        if hasattr(self.detection, 'exceptions') and self.detection.exceptions != None:
            self.query["query"]["bool"]["must_not"] = []
            for exclusion in self.detection.exceptions:
                self.add_exclusion(exclusion)


    def run_query(self):
        
        docs = []
        query_time = 0
        scroll_size = 0
        res = self.elastic.conn.search(
            index=self.detection_input['config']['index'],
            body=self.query,
            scroll='2m'
        )

        scroll_id = res['_scroll_id']
        if 'total' in res['hits']:
            if len(res['hits']['hits']) > 0:
                logger.info(
                    f"{self.detection.name} ({self.detection.uuid}) - Found {len(res['hits']['hits'])} detection hits.")
            query_time += res['took']
            scroll_size = res['hits']['total']['value']

            # Parse the events and extract observables, tags, signature the event
            docs += self.elastic.conn.parse_events(
                res['hits']['hits'], title=self.detection.name, signature_values=[self.detection.detection_id], risk_score=self.detection.risk_score)
        else:
            scroll_size = 0

        # Scroll
        while (scroll_size > 0):
            logger.info(
                f"{self.detection.name} ({self.detection.uuid}) - Scrolling Elasticsearch results...")
            # TODO: Move scroll time to config
            res = self.elastic.conn.scroll(
                scroll_id=scroll_id, scroll='2m')
            if len(res['hits']['hits']) > 0:
                query_time += res['took']
                logger.info(
                    f"{self.detection.name} ({self.detection.uuid}) - Found {len(res['hits']['hits'])} detection hits.")
                # Parse the events and extract observables, tags, signature the event
                docs += self.elastic.parse_events(
                    res['hits']['hits'], title=self.detection.name, signature_values=[self.detection.detection_id], risk_score=self.detection.risk_score)

            scroll_size = len(res['hits']['hits'])

        if len(docs) > 0 :
            self.logger.info(
                f"{self.detection.name} ({self.detection.uuid}) - Total Hits {len(docs)}")
        return docs, query_time


    def run(self):
        ''' Runs the detection '''

        # Start the timer
        start_timer = time.time()

        # Run the detection
        print(self.query)