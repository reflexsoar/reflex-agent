# /module/ilm/main.py

import logging
from multiprocessing import Process

ROLE = 'ilm'

class ILMPolicy:
    '''
    Defines an ILM Policy to be applied to a specific index
    '''

    def __init__(self, name, policy):
        self.name = name
        self.policy = policy


class ILMManager(Process):
    '''
    The detector process runs detection rules against a target source
    Detection rules that return matches are sent to the API as Events
    '''

    def __init__(self, config, agent=None, log_level='INFO', *args, **kwargs):

        super(ILMManager, self).__init__(*args, **kwargs)

        # Establish a basic configuration
        if config:
            self.config = config
        else:
            self.config = {}

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