import time
from loguru import logger
from multiprocessing import Process, Event
from integrations import LOADED_OUTPUTS

POLLER = 'poller'

class Poller(Process):
    '''
    The poller process periodically polls inputs for data and sends them to
    one or more outputs
    '''

    def __init__(self, config, agent=None, log_level='INFO', *args, **kwargs):

        super(Poller, self).__init__(*args, **kwargs)

        # Establish a basic configuration
        if config:
            self.config = config
        else:
            self.config = {
                'concurrent_inputs': 5,
                'graceful_exit': False,
                'max_input_attempts': 3,
                'signature_cache_ttl': 3600
            }

        self.running = True

        self.log_level = log_level
        self.agent = agent
        self.credentials = {}
        self.detection_rules = []
        self.should_exit = Event()
        self.new_term_state_table = {}
        self.running_inputs = {}
        self.configured_outputs = {}
        self.initialized_outputs = {}
        self.configured_inputs = {}

    def start_input(self):
        '''
        Starts a configured input
        '''
        pass

    def stop_input(self):
        '''
        Stops a configured input
        '''
        pass

    def get_input_policy(self):
        '''
        Gets the input policy for the inputs
        '''
        response = self.agent.call_mgmt_api('agent/policy/inputs')
        if response.status_code == 200:
            self.configured_inputs = response.json()['inputs']
        else:
            logger.error(f"Failed to get input policy: {response.text}")

    def get_output_policy(self):
        '''
        Gets the output policy for the outputs
        '''
        response = self.agent.call_mgmt_api('agent/policy/outputs')
        if response.status_code == 200:
            self.configured_outputs = response.json()['outputs']
        else:
            logger.error(f"Failed to get output policy: {response.text}")        

    def run(self):
        """
        Periodically runs detection rules as defined by the ReflexSOAR API
        """
        logger.info('Starting poller role')
        while self.running:
            logger.info('Loading Input/Output Policy')
            self.get_output_policy()
            logger.info(f"Loaded {len(self.configured_outputs)} outputs")

            for output in self.configured_outputs:
                output_class = LOADED_OUTPUTS[output['integration']][output['name']]

                output_obj = output_class(**output['settings'], ignore_ssl=True) # FIX THIS LATER
                self.initialized_outputs[output['configuration_uuid']+"|"+output['name']] = output_obj

            self.get_input_policy()
            logger.info(f"Loaded {len(self.configured_inputs)} inputs")

            for i in self.configured_inputs:
                if i['name'] == 'read_from_file': 
                    target_outputs = []

                    if 'outputs' not in i['settings']:
                        continue

                    for output in i['settings']['outputs']:
                        configuration_uuid = output['value'].split("|")[1]
                        name = output['value'].split("|")[2]
                        target_outputs.append(self.initialized_outputs[configuration_uuid+"|"+name])

                    with open(i['settings']['file_path'], 'r') as f:
                        for line in f:
                            print(line)
                            for target_output in target_outputs:
                                print("REEE")
                                target_output.send(line)

            time.sleep(30)