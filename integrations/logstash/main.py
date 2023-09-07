import os
import json
import socket
from loguru import logger
from requests import Session
from requests.adapters import HTTPAdapter, Retry
from ...module.base import Output
from ...module.base.errors import OutputError

PRODUCT_IDENTIFIER = "f6f65705-587f-4759-92b0-33696b1f240f"

class LogstashOutput(Output):

    def __init__(self, hostname: str, port: int, protocol: str,
                 log_name: str = 'default', *args, **kwargs) -> None:
        """Creates a new instance of the Logstash class

        Args:
            hostname (str): The hostname of the Logstash server
            port (int): The port of the Logstash server
            protocol (str): The protocol to use to connect to the Logstash server
        """

        self.hostname = hostname
        self.port = port
        self.protocol = protocol
        self.log_name = log_name
        self.raw = False
        self.client_key = None
        self.client_cert = None
        self.verify_ssl = True
        self._session = Session()

        if 'auth_method' in kwargs:
            self.auth_method = kwargs['auth_method']

        if 'verify_ssl' in kwargs:
            self.verify_ssl = kwargs['ignore_ssl']

        if 'client_cert' in kwargs:
            self.client_cert = kwargs['client_cert']
            if self.client_cert is not None:
                # Validate the client cert exists
                if not os.path.exists(self.client_cert):
                    raise Exception(
                        f"Client certificate {self.client_cert} does not exist.")

        if 'client_key' in kwargs:
            self.client_key = kwargs['client_key']
            if self.client_key is not None:
                # Validate the client key exists
                if not os.path.exists(self.client_key):
                    raise Exception(f"Client key {self.client_key} does not exist.")

        self._setup_certs()

        if self.verify_ssl is False:
            self._session.verify = False

        super().__init__({}, *args, **kwargs)

    def _setup_certs(self):
        '''Setup the client cert and key if they are specified'''
        cert = None
        if self.client_key and self.client_cert:
            cert = (self.client_cert, self.client_key)
        elif self.client_cert and not self.client_key:
            cert = self.client_cert
        self._session.cert = cert

    def send_http(self, message):
        '''Send message to logstash using http'''

        # Send the log name as a header so that logstash can use it as the source

        self._session.mount('http://', HTTPAdapter(max_retries=Retry(total=3, backoff_factor=0.5)))  # noqa: B950
        self._session.mount('https://', HTTPAdapter(max_retries=Retry(total=3, backoff_factor=0.5)))  # noqa: B950

        url = '{}:{}/'.format(self.hostname, self.port)
        headers = {'Content-Type': 'application/json'}
        try:
            response = self._session.post(url, data=message, headers=headers)
            if response.status_code != 200:
                logger.error(
                    'Error sending to logstash: {}'.format(response.text))
        except Exception as e:
            logger.error('Error sending to logstash: {}'.format(e))
            raise OutputError('Error sending to logstash: {}'.format(e))

    def send_udp(self, message):
        '''Send message to logstash using udp'''
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(message.encode(), (self.hostname, self.port))

    def send_tcp(self, message):
        '''Send message to logstash using tcp'''
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.hostname, self.port))
        sock.sendall(message.encode())
        sock.close()

    def _send(self, message, event_type: str = None, envelope=None):  # noqa: C901
        '''A generic function to send message to logstash using the specified protocol'''

        # If an envelope is specified, use it to wrap the message.
        # The envelope can be represented as a dot notation string,
        # e.g. 'mylog.alerts' or a single string.
        # If the envelope is a single string, it will be used as the key for
        # the message.
        # If the envelope is a dot notation string, it will be used to
        # create a nested dictionary.
        if envelope:
            if isinstance(envelope, str):
                if '.' in envelope:
                    envelope = envelope.split('.')
                    envelope = {envelope[0]: {envelope[1]: message}}
                else:
                    envelope = {envelope: message}
            message = envelope

        if event_type:
            if isinstance(message, str):
                message = json.loads(message)

            message['log_event_type'] = event_type

        if not self.raw:
            try:
                message = json.dumps(message)
            except TypeError:
                logger.error(f"Error converting message to JSON: {str(message)}")
        if self.protocol == 'http':
            self.send_http(message)
        elif self.protocol == 'udp':
            self.send_udp(message)
        elif self.protocol == 'tcp':
            self.send_tcp(message)
        else:
            raise Exception('Invalid protocol specified')