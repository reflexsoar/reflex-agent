""" Contains logic to poll LDAP/LDAPS servers for information """

from module.poller.inputs.base import INTEL_INPUT, BaseInput
from ldap3 import (
    Server,
    Connection,
    SAFE_SYNC,
    ALL_ATTRIBUTES,
    SUBTREE
)


class LDAPInput(BaseInput):

    def __init__(self, config, *args, **kwargs):

        super(LDAPInput, self).__init__(*args, **kwargs)

        self.type = INTEL_INPUT

    def create_connection(self):
        '''
        Creates a connection object for communicatingf with the target
        LDAP server
        '''

        username, password = self.credentials
        self.conn = Connection(
            self.config['server'],
            username,
            password,
            client_strategy=SAFE_SYNC,
            auto_bind=self.config['auto_bind']
        )

    def query(self):

        generator = self.conn.extend.standard.paged_search(
            self.config['base_dn'],
            self.config['filter'],
            attributes=[self.config['attribute']],
            paged_size=250,
            generator=True
        )

    def run(self):
        raise NotImplementedError(
            f'{self.__class__.__name__} is not implemented')
