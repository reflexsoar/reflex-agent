'''Contains logic to poll the SentinelOne API for information
Author: Brian Carroll https://github.com/n3tsurge
Created: 2022-11-03
'''

from base import BaseInput, EVENT_INPUT, INTEL_INPUT



class SentinelOneInput(BaseInput):
    def __init__(self, config, *args, **kwargs):
        super(SentinelOneInput, self).__init__(config, *args, **kwargs)
        self.type = EVENT_INPUT

    def run(self):
        raise NotImplementedError(
            f'{self.__class__.__name__} is not implemented')

