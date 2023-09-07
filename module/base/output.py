from loguru import logger

class Output:

    def __init__(self, *args, **kwargs):
        """
        Initialize the output
        """
        pass

    def send(self, message):
        if isinstance(message, list):
            for m in message:
                logger.info(message)
        else:
            logger.info(message)
