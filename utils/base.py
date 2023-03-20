import os
import socket
import logging
import hashlib
import datetime
import json
import io
from threading import Thread
import time
from functools import partial
from retry import retry
import requests
from zipfile import ZipFile
from requests import Session, Request
from pluginbase import PluginBase
from queue import Queue
from loguru import logger
#from multiprocessing import Process, Queue

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)

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
        self.value = str(value)
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
        self.detection_id = None
        self.risk_score = None
        self.input_uuid = None
        self.metrics = {
            'agent_pickup_time': None,
            'agent_bulk_start': None,
        }


    def get_nested_field(self, message, field):
        '''
        Iterates over nested fields to get the final desired value
        e.g signal.rule.name should return the value of name

        Paramters:
            message (dict): A dictionary of values you want to iterate over
            field (str): The field you want to extract from the message in dotted format

        Return:
            value: The extracted value, may be the response from this function calling itself again
        '''

        if isinstance(field, str):
            if field in message:
                return message[field]

            args = field.split('.')
        else:
            args = field

        if args and message:
            element = args[0]
            if element:
                if isinstance(message, list):
                    values = []
                    value = [m for m in message if m is not None]
                    if any(isinstance(i, list) for i in value):
                        for l in value:
                            if isinstance(l, list):
                                values += [v for v in l if v is not None]
                    else:
                        values += [v for v in value if not isinstance(v, list)]
                    value = values                    
                else:
                    if isinstance(message, dict):
                        value = message.get(element)
                    else:
                        value = message

                if isinstance(value, list):
                    if len(value) > 0 and isinstance(value[0], dict):
                        if len(args) > 1:
                            value = [self.get_nested_field(item, args[1:]) for item in value]

                return value if len(args) == 1 else self.get_nested_field(value, args[1:])
    

    def generate_signature(self, source, fields=[], signature_values=[]):
        '''
        Generates an event signature based on a set of supplied
        fields
        '''

        # Always include the title
        signature_values.append(self.title)

        # Compute the signature for the event based on the signature_fields configuration item
        if fields != []:
            for signature_field in sorted(fields):
                value = self.get_nested_field(source, signature_field)
                if value:
                    signature_values.append(value)
        else:
            signature_values.append(datetime.datetime.utcnow())

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

    def __init__(self, options, log_level="ERROR"):
        ''' A new agent object '''

        self.uuid = os.getenv('AGENT_UUID')
        self.healthy = True
        self.health_issues = []
        self.access_token = os.getenv('ACCESS_TOKEN')
        self.console_url = os.getenv('CONSOLE_URL')
        self.ip = self.agent_ip()
        self.VERSION_NUMBER = "2022.08.00"

        log_levels = {
            'DEBUG': logging.DEBUG,
            'ERROR': logging.ERROR,
            'INFO': logging.INFO
        }

        log_handler = logging.StreamHandler()
        log_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

        self.logger = logger
        #self.logger = logging.getLogger(self.__class__.__name__)
        #self.logger.addHandler(log_handler)
        #self.logger.setLevel(log_levels[log_level])
        self.log_level = log_level

        if not options.name:
            self.hostname = socket.gethostname()
        else:
            self.hostname = options.name
            
        self.config = {
            'roles': [],
            'policy': {
                'revision': 0,
                'uuid': '00000000-0000-0000-0000-000000000000',
                'roles': [],
                'runner_config': {},
                'poller_config': {},
                'detector_config': {}
            }
        }
        self.options = options
        self.event_cache = {}
        self.cache_key = 'signature'
        self.cache_ttl = 30 # Number of minutes an item should be in the cache
        self.detection_rules = []
        self.health_check_interval = 30 # Number of seconds between health checks

        # Set a role health state, 0 = disabled, 1 = degraded, 2 = healthy
        self.role_health = {
            'detector': 0,
            'runner': 0,
            'poller': 0
        }

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
            self.logger.error("Unable to determine IP address")
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP


    @retry(delay=30)
    def call_mgmt_api(self, endpoint, data=None, method='GET', token=None):
        '''
        Makes calls to the management console
        '''

        try:
            # Create a requests session
            s = Session()
            s.verify = self.options.ignore_tls

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
                'Content-Type': 'application/json',
                'User-Agent': f'reflexsoar-agent/{self.VERSION_NUMBER}'
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
            self.logger.error("An error occured while trying to connect to the management API. {}".format(str(e)))
            return None
        
    def get_list_values(self, uuid):

        # Fetch the list values
        response = self.call_mgmt_api(f'list/values?list={uuid}&page_size=10000')
        if response and response.status_code == 200:
            return [v['value'] for v in response.json()['values']]
        else:
            if response:
                self.logger.error('Failed to get list values from management API. {}'.format(response.content))
            return []


    def fetch_credentials(self, uuid):
        '''
        Fetches credentials from the API
        '''

        username = ""
        secret = ""
        self.logger.info('Fetching credentials')

        # Fetch the username
        response = self.call_mgmt_api('credential/%s' % uuid)
        if response and response.status_code == 200:
            username = response.json()['username']
        else:
            if response:
                self.logger.error('Failed to get credentials from management API. {}'.format(response.content))

        # Fetch the secret
        response = self.call_mgmt_api('credential/decrypt/%s' % uuid)
        if response and response.status_code == 200:
            secret = response.json()['secret']
        else:
            if response:
                self.logger.error('Failed to get credentials from management API. {}'.format(response.content))
        
        return (username, secret)

    def get_config(self):
        '''
        Fetches the entire agent config including
        inputs and playbooks to run, credentials, etc.
        '''

        response = self.call_mgmt_api('agent/{}'.format(self.uuid))
        if response and response.status_code == 200:
            self.config = response.json()

            # If the policy has roles configured to override, override the direct assigned roles
            # on the agent
            if 'policy' in self.config:
                
                if 'roles' in self.config['policy']:
                    if len(self.config['policy']['roles']) > 0:
                        self.config['roles'] = self.config['policy']['roles']

                if 'health_check_interval' in self.config['policy']:
                    self.health_check_interval = self.config['policy']['health_check_interval']

            #self.logger.setLevel(self.config['policy']['logging_level'])

            if len(self.config['groups']) > 0:
                for group in self.config['groups']:
                    self.config['inputs'] += group['inputs']

            self.config['inputs'] = [json.loads(i) for i in set([
                    json.dumps(d, sort_keys=True) for d in self.config['inputs']
                ])]

            return

    def get_input(self, uuid):
        '''
        Fetches an inputs configuration from the API
        '''
        response = self.call_mgmt_api(f"input/{uuid}")
        if response and response.status_code == 200:
            _input = response.json()
            return _input


    def update_detection(self, uuid, payload={}):
        '''
        Updated a detection via PUT request to the API
        '''
        payload = json.loads(json.dumps(payload, default=str))
        response = self.call_mgmt_api(f"detection/{uuid}", data=payload, method='PUT')
        if response and response.status_code != 200:
            self.logger.error(f"Failed to update detection {uuid}. API response code {response.status_code}, {response.text}")


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
            self.logger.info(f"Downloading {plugin['name']} plugin...")
            if response and response.status_code == 200:

                # Compute the hash of the file that was just downloaded
                hasher.update(response.content)
                checksum = hasher.hexdigest()
                if plugin['file_hash'] == checksum:
                    with ZipFile(io.BytesIO(response.content)) as z:
                        self.logger.info(f"Extracting ZIP file {plugin['filename']}")
                        for item in z.infolist():
                            if item.filename.endswith(".py"):
                                item.filename = os.path.basename(item.filename)
                                z.extract(item, './plugins')
                else:
                    self.logger.error("Plugin %s failed signature checking and will not be downloaded.  Expected %s, got %s" % (
                        plugin['name'], plugin['file_hash'], checksum))
        return plugins

    def heartbeat(self):
        '''
        Pings the API to update the last_heartbeat timestamp of 
        the agent as well as the current health of the agent
        '''

        self.logger.info("Sending heartbeat to API")

        recovered = False

        if any([self.role_health[role] == 1 for role in self.role_health]):
            self.logger.error('Agent is unhealthy, one or more roles are degraded')
            self.healthy = False
            for role in self.role_health:
                if self.role_health[role] == 1:
                    self.health_issues.append(f'{role} is degraded')
        else:
            if self.healthy == False:
                self.healthy = True
                self.health_issues = []
                recovered = True
                
            self.logger.info('Agent is healthy')

        data = {'healthy': self.healthy, 'health_issues': self.health_issues, 'recovered': recovered, 'version': self.VERSION_NUMBER}
        

        response = self.call_mgmt_api('agent/heartbeat/{}'.format(self.uuid), method='POST', data=data)
        if response and response.status_code == 200:
            return response
        else:
            return None


    def get_nested(self, message, *args):
        ''' Iterates over nested fields to get the final desired value '''
        if args and message:
            element = args[0]
            if element:
                value = message.get(element)
                return value if len(args) == 1 else self.get_nested(value, *args[1:])

    
    def push_intel(self, items: list, intel_list_config: dict) -> None:
        '''
        Pushes a list of values to an intel list based on the configuration
        provided in intel_list_config
        
        Parameters:
            items (list): The list of items to add to the list
            intel_list_config (dict): The details about where to send the intel and how

        Example Intel Config
            intel_list_config = {
                'intel_list_uuid': 'xxxxx-xxxx-xxx-xxxx-xxxx',
                'action': 'replace'
            }
        
        Returns: None
        '''

        if intel_list_config['action'] not in ['replace','append']:
            raise ValueError('The Intel list action must be "replace" or "append"')

        #if intel_list_config['action'] == 'append':

            # Call /api/v2.0/
            #response = self.call_mgmt_api('agent/heartbeat/{}'.format(self.uuid))


    def process_events(self, events, skip_cache_check=False):
        ''' 
        Splits all the events into multiple pusher processes based on the size
        of the number of chunks
        '''

        event_queue = Queue()

        # Set the bulk_size based on the agent configuration, if not set default to 100
        bulk_size = self.config['bulk_size'] if 'bulk_size' in self.config else 250
        chunks =  [events[i * bulk_size:(i + 1) * bulk_size] for i in range((len(events) + bulk_size - 1) // bulk_size)]

        # Queue all the events
        if events:
            for events in chunks:
                event_queue.put(events)
            
            # Create the bulk pushers
            bulk_workers = self.config['bulk_workers'] if 'bulk_workers' in self.config else 5
            workers = []
            
            for i in range(bulk_workers+1):
                event_queue.put(None)

            for i in range(bulk_workers+1):
                p = Thread(target=self.push_events, args=(event_queue,skip_cache_check,))
                workers.append(p)
            
            [x.start() for x in workers]
            [x.join() for x in workers]


    def push_events(self, queue, skip_cache_check=False):
        '''
        Pushes events to the bulk ingest API
        '''

        try:
            while True:
                events = queue.get()

                if events is None:
                    break

                if len(events) > 0:
                    payload = {
                        'events': []
                    }

                    if skip_cache_check == False:
                        events = self.check_cache(events, self.cache_ttl)
                        if events is None:
                            self.logger.info('All events in this bulk request were found in the cache, skipping...')
                            break

                    bulk_start = datetime.datetime.utcnow().isoformat()
                    for event in events:
                        event.metrics['agent_bulk_start'] = bulk_start
                        payload['events'].append(json.loads(event.jsonify()))
                                                 
                    # TODO: FIX LOGGING
                    self.logger.info('Pushing %s events to bulk ingest...' % len(events))
                
                    response = self.call_mgmt_api('event/_bulk', data=payload, method='POST')
                    if response and response.status_code == 207:
                        self.logger.info('Finishing pushing events in {} seconds'.format(response.json()['process_time']))
                        
        except Exception as e:
            self.logger.error('An error occurred while trying to push events to the _bulk API. {}'.format(str(e)))


    def expire_cache(self):
        '''
        Clears the cache of expired items
        '''

        self.logger.info('Checking for expired items in the cache')
        expired_items = []
        for item in self.event_cache:
            if ((datetime.datetime.utcnow() - self.event_cache[item]).seconds/60) > self.options.event_realert_ttl:
                expired_items.append(item)

        for item in expired_items:
            del self.event_cache[item]

    def check_cache(self, events: list, ttl: int, cache_key: str = None) -> list:
        '''
        Pushes new items to the cache so they are not sent again unless the
        TTL on the item has expired

        Parameters:
            - events (list): A list of events
            - ttl (int): The number of minutes an item should be in cache
            - cache_key (str): The attribute to cache

        Return:
            - events (list): A trimmed list of events that already exist in cache
        '''

        events_to_send = []

        if cache_key is None:
            cache_key = self.options.event_cache_key

        # Clear expired items from the cache
        #for item in self.event_cache:

            # If the item has been in the cache longer than the TTL remove it
        #    if ((datetime.datetime.utcnow() - self.event_cache[item]).seconds/60) > self.options.event_realert_ttl:
        #        self.event_cache.pop(item)

        # Check each event to see if it is in the cache
        if events:
            for event in events:
                # Compute the cache key based on the cache_key parameter
                key = getattr(event, cache_key)

                # Check if the event is in the cache already
                if key not in self.event_cache:
                    self.event_cache[key] = datetime.datetime.utcnow()
                    events_to_send.append(event)

            if len(events_to_send) == 0:
                return None

            return events_to_send
        return None


    @retry(delay=30)
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

        #if not self.options.roles:
        #    errors.append('Missing argument --roles')

        if self.options.roles != None and isinstance(self.options.roles, str):
            roles = self.options.roles.split(',')
        else:
            roles = []
        token = self.options.token
        console = self.options.console

        # Determine if the roles supplied in the CLI pair command
        # are valid roles supported by the tool
        for role in roles:
            if role not in ('poller', 'runner', 'detector'):
                errors.append(f'Invalid role "{role}"')

        # If there are any errors, return them to STDOUT
        # and exit the agent
        if len(errors) > 0:
            self.logger.info('\n'.join(errors))

        agent_data = {
            "name": self.hostname,
            "ip_address": self.ip,
            "roles": roles            
        }

        if self.options.groups:
            agent_data['groups'] = self.options.groups

        # Check if any agent groups are defined and
        # split them out into an array if they are
        if self.options.groups:
            agent_data['groups'] = self.options.groups.split(',')

        headers = {
            'Authorization': 'Bearer %s' % token,
            'Content-Type': 'application/json',
            'User-Agent': f'reflexsoar-agent/{self.VERSION_NUMBER}'
        }

        # If the user has opted to ignore certificate names
        verify = self.options.ignore_tls

        try:
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
                self.logger.info('Agent already paired with console.')
                return False
            else:
                error = json.loads(response.content)['message']
                self.logger.info('Failed to pair agent. %s' % error)
                return False
            time.sleep(5)
            self.logger.info('Pairing complete')
            return True
        except Exception as error:
            self.logger.info('Failed to pair agent. %s' % error)
