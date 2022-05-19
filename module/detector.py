import time
import logging
from multiprocessing import Process


class Detector(Process):
    '''
    The detector process runs detection rules against a target source
    Detection rules that return matches are sent to the API as Events
    '''

    def __init__(self, config, log_level='INFO', *args, **kwargs):

        super(Detector, self).__init__(*args, **kwargs)
        self.config = config
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
        self.graceful_shutdown = self.config['graceful_shutdown']

    def shutdown(self):
        """
        Shuts down the detector process, if graceful_shutdown 
        """
        raise NotImplementedError

    def run(self):
        """
        Periodically runs detection rules as defined by the ReflexSOAR API
        """
        while self.running:
            self.logger.info('Fetching detections')
            self.logger.info('Run complete, sleeping')
            time.sleep(5)