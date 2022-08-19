""" Contains a Base Input class that all other Inputs inherit from """

from multiprocessing import Process

INTEL_INPUT = 'intel'  # Intel inputs will feed a defined intel list
EVENT_INPUT = 'event'  # Event inputs will feed into the event queue


class BaseInput(Process):
    """
    A class used by all other Inputs

    Attributes:
    -----------
        config (dict): The configuration for the input
        type (str): The type of input

    Methods:
    --------
        run (): Runs the input
    """

    def __init__(self, config, *args, **kwargs):

        super(BaseInput, self).__init__(*args, **kwargs)

        self.type = None  # The input type determines where the input will send its data

    def run(self):
        """
        Runs the input
        """

        raise NotImplementedError(
            f'{self.__class__.__name__} is not implemented')
