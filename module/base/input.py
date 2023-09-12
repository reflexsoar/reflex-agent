from typing import List

class Input:

    def __init__(self, outputs: List, *args, **kwargs):
        """
        Initialize the input
        """
        self.outputs = outputs

    def poll(self):
        '''Polls in the input for messages'''
        pass
