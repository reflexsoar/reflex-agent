""" Contains logic to poll LDAP/LDAPS servers for information """

from module.poller.inputs.base import INTEL_INPUT, EVENT_INPUT, BaseInput


class FileInput(BaseInput):

    def __init__(self, config, *args, **kwargs):

        super(FileInput, self).__init__(*args, **kwargs)

        self.type = INTEL_INPUT

    def run(self):
        raise NotImplementedError(
            f'{self.__class__.__name__} is not implemented')
