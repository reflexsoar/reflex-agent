""" Contains logic to parse EVTX files for events """

from module.poller.inputs.base import EVENT_INPUT, BaseInput


class EVTXInput(BaseInput):

    def __init__(self, config, *args, **kwargs):

        super(EVTXInput, self).__init__(*args, **kwargs)

        self.type = EVENT_INPUT

    def run(self):
        raise NotImplementedError(
            f'{self.__class__.__name__} is not implemented')
