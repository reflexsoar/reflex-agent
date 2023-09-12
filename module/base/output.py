from loguru import logger

class Output:

    def __init__(self, *args, **kwargs):
        """
        Initialize the output
        """
        pass

    def send(self, message, event_type: str = None, envelope=None):
        '''Send message'''
        if isinstance(message, list):
            for m in message:
                self._send(m, event_type, envelope)
        else:
            self._send(message, event_type, envelope)
