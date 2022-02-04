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


class MSExchange(Process):

    def __init__(self, config: dict, field_mapping: dict, credentials: tuple) -> 'MSExchange':
        ''' 
        Initializes a new Microsoft Exchange poller object
        which pushes information to the api
        '''
        self.config = config
        self.status = 'waiting'
        self.credentials = credentials
        self.field_mapping = field_mapping
        self.conn = self.connect_exchange()
        self.plugin_type = 'events'

    def connect_exchange(self):
        credentials = Credentials(self.credentials[0], self.credentials[1])

        server_config = Configuration(
            server=self.config['server'], credentials=credentials)
        account = Account(primary_smtp_address=self.config['email'], config=server_config,
                          audiscover=self.config['autodiscover'], access_type=DELEGATE)
        return account

    def poll_mailbox(self):
        raise NotImplementedError

    def analyze(self, data):
        raise NotImplementedError
