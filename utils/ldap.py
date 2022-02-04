from multiprocessing import Process
from exchangelib import (
    Credentials,
    Configuration,
    Account,
    ItemAttachment,
    Message,
    Mailbox,
    HTMLBody,
    FileAttachment,
    DELEGATE
)

class LDAPSource(Process):

    def __init__(self, config: dict, field_mapping: dict, credentials: tuple) -> 'LDAPSource':
        ''' 
        Initializes a new LDAP poller object
        which pushes information to the api
        '''
        self.config = config
        self.status = 'waiting'
        self.credentials = credentials
        self.field_mapping = field_mapping
        self.plugin_type = 'intel_list'