import os
import socket
import logging
import hashlib
import datetime
import json
import io
from functools import partial
import requests
from zipfile import ZipFile
from requests import Session, Request
from pluginbase import PluginBase
from multiprocessing import Process, Queue

logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)

here = os.path.abspath(os.path.dirname(__file__))
get_path = partial(os.path.join, here)
plugin_base = PluginBase(package='plugins', searchpath=[
                         get_path('../plugins')])


def event_severity(sev):
    '''
    Returns a dictionary object containing the
    severity of an event
    '''
    severities = [
        {'low': 0},
        {'medium': 1},
        {'high': 2},
        {'critical': 3}
    ]
    return severities[sev]


class CustomJsonEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, JSONSerializable):
            return o.__dict__
        return json.JSONEncoder.default(self, o)


class JSONSerializable(object):
    ''' Allows for an object to be represented in JSON format '''

    def jsonify(self):
        ''' Returns a json string of the object '''

        return json.dumps(self, sort_keys=True, indent=4, cls=CustomJsonEncoder)

    def attr(self, attributes, name, default, error=None):
        ''' Fetches an attribute from the passed dictionary '''
        
        is_required = error is not None

        if is_required and name not in attributes:
            raise ValueError(error)
        else:
            return attributes.get(name, default)


class Observable(JSONSerializable):

    def __init__(self, value, dataType, tlp, tags, ioc, spotted, safe):
        self.value = value
        self.dataType = dataType
        self.tlp = tlp
        self.tags = tags
        self.ioc = ioc
        self.spotted = spotted
        self.safe = safe


class Event(JSONSerializable):

    def __init__(self):

        self.title = ""
        self.description = ""
        self.reference = ""
        self.tags = []
        self.tlp = 0
        self.severity = 0
        self.observables = []
        self.raw_log = ""
        self.source = ""
        self.signature = ""


    def get_nested_field(self, message, field):
        '''
        Iterates over nested fields to get the final desired value
        e.g signal.rule.name should return the value of name
        '''

        if isinstance(field, str):
            args = field.split('.')
        else:
            args = field

        if args and message:
            element = args[0]
            if element:
                value = message.get(element)
                return value if len(args) == 1 else self.get_nested_field(value, args[1:])
    

    def generate_signature(self, source, fields=[]):
        '''
        Generates an event signature based on a set of supplied
        fields
        '''
        # Compute the signature for the event based on the signature_fields configuration item
        signature_values = []

        if fields != []:
            for signature_field in sorted(fields):
                value = self.get_nested_field(source, signature_field)
                if value:
                    signature_values.append(value)
        else:
            signature_values.append(self.title, datetime.datetime.utcnow())

        event_hasher = hashlib.md5()
        event_hasher.update(str(signature_values).encode())
        self.signature = event_hasher.hexdigest()


    def from_dict(self, data):
        '''
        Sets the properties of the Event object from a 
        python dictionary
        '''

        for k in data:
            if k == 'observables':
                setattr(self, k, [Observable(**o) for o in data[k]])
            else:
                setattr(self, k, data[k])

    def __repr__(self):
        return "<Event reference={}, title={}, signature={}>".format(
                    self.reference,
                    self.title,
                    self.signature
                )


class Plugin(object):

    def __init__(self, name):
        self.name = name
        self.actions = {}

        self.source = plugin_base.make_plugin_source(
            searchpath=[get_path('./plugins')],
            identifier=self.name)

        for plugin_name in self.source.list_plugins():
            plugin = self.source.load_plugin(plugin_name)
            plugin.setup(self)

    def register_action(self, name, action):
        self.actions[name] = action

    def run_action(self, name, *args, **kwargs):
        '''
        Runs an action by its name and returns the value 
        if the action returns a value 
        '''
        return self.actions[name](*args, **kwargs)

    def __repr__(self):
        return self.name


class Agent(object):

    def __init__(self, options):
        ''' A new agent object '''

        self.uuid = os.getenv('AGENT_UUID')
        self.access_token = os.getenv('ACCESS_TOKEN')
        self.console_url = os.getenv('CONSOLE_URL')
        self.ip = self.agent_ip()
        self.hostname = socket.gethostname()
        self.config = {}
        self.options = options

    def agent_ip(self):
        '''
        Fetches the IP address of the machine
        '''

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # doesn't even have to be reachable
            s.connect(('10.255.255.255', 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP

    def call_mgmt_api(self, endpoint, data=None, method='GET', token=None):
        '''
        Makes calls to the management console
        '''

        try:
            # Create a requests session
            s = Session()
            if self.options and self.options.ignore_tls:
                s.verify = False
            if self.options and self.options.cacert:
                s.verify = self.options.cacert

            # Get some configuration values to make them easier
            # to access
            CONSOLE_URL = self.console_url
            CONSOLE_URL = CONSOLE_URL + "/api/v2.0"
            ACCESS_TOKEN = self.access_token
            if token:
                ACCESS_TOKEN = token

            # Set the HTTP headers
            headers = {
                'Authorization': 'Bearer %s' % (ACCESS_TOKEN),
                'Content-Type': 'application/json'
            }

            # Dynamically create the request
            request_data = {
                'url': "%s/%s" % (CONSOLE_URL, endpoint),
                'headers': headers
            }

            if data:
                request_data['json'] = data

            req = Request(method, **request_data)
            prepared_req = req.prepare()

            # Send the request
            # TODO: ADD PROXY SUPPORT
            # TODO: ADD CUSTOM CA SUPPORT
            resp = s.send(prepared_req)

            return resp
        except Exception as e:
            logging.error("An error occured while trying to connect to the management API. {}".format(str(e)))
            return None


    def fetch_credentials(self, uuid):
        '''
        Fetches credentials from the API
        '''

        username = ""
        secret = ""
        logging.info('Fetching credentials')

        # Fetch the username
        response = self.call_mgmt_api('credential/%s' % uuid)
        if response and response.status_code == 200:
            username = response.json()['username']
        else:
            logging.error('Failed to get credentials from management API. {}'.format(response.content))

        # Fetch the secret
        response = self.call_mgmt_api('credential/decrypt/%s' % uuid)
        if response and response.status_code == 200:
            secret = response.json()['secret']
        else:
            logging.error('Failed to get credentials from management API. {}'.format(response.content))
        
        return (username, secret)

    def get_config(self):
        '''
        Fetches the entire agent config including
        inputs and playbooks to run, credentials, etc.
        '''

        response = self.call_mgmt_api('agent/{}'.format(self.uuid))
        if response and response.status_code == 200:
            self.config = response.json()
            return

    def download_plugins(self):
        '''
        Downloads plugins from the API so they can be 
        loaded and run actions via playbook steps
        '''

        plugins = []
        response = self.call_mgmt_api('plugin')
        if response and response.status_code == 200:
            plugins = response.json()

        for plugin in plugins:
            hasher = hashlib.sha1()
            response = self.call_mgmt_api(
                'plugin/download/%s' % plugin['filename'])
            logging.info(f"Downloading {plugin['name']} plugin...")
            if response and response.status_code == 200:

                # Compute the hash of the file that was just downloaded
                hasher.update(response.content)
                checksum = hasher.hexdigest()
                if plugin['file_hash'] == checksum:
                    with ZipFile(io.BytesIO(response.content)) as z:
                        logging.info(f"Extracting ZIP file {plugin['filename']}")
                        for item in z.infolist():
                            if item.filename.endswith(".py"):
                                item.filename = os.path.basename(item.filename)
                                z.extract(item, './plugins')
                else:
                    logging.error("Plugin %s failed signature checking and will not be downloaded.  Expected %s, got %s" % (
                        plugin['name'], plugin['file_hash'], checksum))

    def heartbeat(self):
        '''
        Pings the API to update the last_heartbeat timestamp of 
        the agent
        '''

        response = self.call_mgmt_api('agent/heartbeat/{}'.format(self.uuid))
        if response and response.status_code == 200:
            return response

    def get_nested(self, message, *args):
        ''' Iterates over nested fields to get the final desired value '''
        if args and message:
            element = args[0]
            if element:
                value = message.get(element)
                return value if len(args) == 1 else self.get_nested(value, *args[1:])


    def process_events(self, events):
        ''' 
        Splits all the events into multiple pusher processes based on the size
        of the number of chunks
        '''

        event_queue = Queue()

        # Set the bulk_size based on the agent configuration, if not set default to 100
        bulk_size = self.config['bulk_size'] if 'bulk_size' in self.config else 100
        chunks =  [events[i * bulk_size:(i + 1) * bulk_size] for i in range((len(events) + bulk_size - 1) // bulk_size)]

        # Queue all the events
        for events in chunks:
            event_queue.put(events)
        
        # Create the bulk pushers
        bulk_workers = self.config['bulk_workers'] if 'bulk_workers' in self.config else 5
        workers = []
        
        for i in range(bulk_workers+1):
            event_queue.put(None)

        for i in range(bulk_workers+1):
            p = Process(target=self.push_events, args=(event_queue,))
            workers.append(p)
        
        [x.start() for x in workers]
        [x.join() for x in workers]

    def push_events(self, queue):
        '''
        Pushes events to the bulk ingest API
        '''

        try:
            while True:
                events = queue.get()
                if events is None:
                  break
                  
                payload = {
                    'events': []
                }
                
                [payload['events'].append(json.loads(e.jsonify())) for e in events]

                if len(events) > 0:
                    # TODO: FIX LOGGING
                    logging.info('Pushing %s events to bulk ingest...' % len(events))
                
                    response = self.call_mgmt_api('event/_bulk', data=payload, method='POST')
                    if response and response.status_code == 207:
                        logging.info('Finishing pushing events in {} seconds'.format(response.json()['process_time']))
        except Exception as e:
            logging.error('An error occurred while trying to push events to the _bulk API. {}'.format(str(e)))


    def pair(self):
        '''
        Pairs an agent with the console, this only needs to be run
        once per agent
        '''

        # Check that the bare minimum parameters are available
        # add an error if they are missing
        errors = []
        if not self.options.token:
            errors.append('Missing argument --token')

        if not self.options.console:
            errors.append('Missing argument --console')

        if not self.options.roles:
            errors.append('Missing argument --roles')

        roles = self.options.roles.split(',')
        token = self.options.token
        console = self.options.console

        # Determine if the roles supplied in the CLI pair command
        # are valid roles supported by the tool
        for role in roles:
            if role not in ('poller', 'runner'):
                errors.append(f'Invalid role "{role}"')

        # If there are any errors, return them to STDOUT
        # and exit the agent
        if len(errors) > 0:
            logging.info('\n'.join(errors))
            exit(1)

        agent_data = {
            "name": self.hostname,
            "ip_address": self.ip,
            "roles": roles
        }

        # Check if any agent groups are defined and
        # split them out into an array if they are
        if self.options.groups:
            agent_data['groups'] = self.options.groups.split(',')

        headers = {
            'Authorization': 'Bearer %s' % token,
            'Content-Type': 'application/json'
        }

        # If the user has opted to ignore certificate names
        verify = self.options.ignore_tls if self.options.ignore_tls else False

        response = requests.post(
            '%s/api/v2.0/agent' % self.options.console, json=agent_data, headers=headers, verify=verify)
        if response and response.status_code == 200:
            data = response.json()
            env_file = """CONSOLE_URL='{}'
ACCESS_TOKEN='{}'
AGENT_UUID='{}'""".format(console, data['token'], data['uuid'])

            self.uuid = data['uuid']
            self.access_token = data['token']
            self.console_url = console

            with open('config.txt', 'w+') as f:
                f.write(env_file)

        elif response.status_code == 409:
            logging.info('Agent already paired with console.')
            return False
        else:
            error = json.loads(response.content)['message']
            logging.info('Failed to pair agent. %s' % error)
            return False
        logging.info('Pairing complete')
        return True
