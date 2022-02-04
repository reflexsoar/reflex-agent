from multiprocessing import Process
from ldap3 import (
    Server,
    Connection,
    SAFE_SYNC,
    ALL_ATTRIBUTES,
    SUBTREE
)

class LDAPSource(Process):

    def __init__(self, config: dict, credentials: tuple) -> 'LDAPSource':
        ''' 
        Initializes a new LDAP poller object which pushes information to the api

        Parameters:
            config (dict): - Example Configuration
                config = {
                    'base_dn': 'ldap://ad.reflexsoar.com',
                    'filter': '(&(objectClass=user)(memberof=CN=Domain Admins,DC=ad,DC=reflexsoar,DC=com))
                    'attribute': 'samaccountname',
                    'server': '',
                    'auto_bind': True
                }
            credentials (tuple): The username and password (username, password)

        Returns:
            LDAPSource object
        '''
        self.config = config
        self.status = 'waiting'
        self.credentials = credentials
        self.conn = None
        self.plugin_type = 'intel_list'

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

        

