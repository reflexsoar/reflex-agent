import os
import socket
import logging
import hashlib
from functools import partial
import requests
from requests import Session, Request
from pluginbase import PluginBase

logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)

here = os.path.abspath(os.path.dirname(__file__))
get_path = partial(os.path.join, here)
plugin_base = PluginBase(package='plugins', searchpath=[get_path('../plugins')])

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

class Agent(object):

    def __init__(self):
        ''' A new agent object '''
        
        self.uuid = os.getenv('AGENT_UUID')
        self.access_token = os.getenv('ACCESS_TOKEN')
        self.console_url = os.getenv('CONSOLE_URL')
        self.ip = self.agent_ip()
        self.hostname = socket.gethostname()
        self.config = {}


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

        # Create a requests session
        s = Session()

        # Get some configuration values to make them easier
        # to access
        CONSOLE_URL = os.getenv('CONSOLE_URL')
        ACCESS_TOKEN = os.getenv('ACCESS_TOKEN')
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

        print(request_data)

        req = Request(method, **request_data)
        prepared_req = req.prepare()

        # Send the request
        # TODO: ADD PROXY SUPPORT
        # TODO: ADD CUSTOM CA SUPPORT
        resp = s.send(prepared_req)

        if resp.status_code == 200:
            return resp
        else:
            return None


    def get_config(self):
        '''
        Fetches the entire agent config including
        inputs and playbooks to run, credentials, etc.
        '''

        response = self.call_mgmt_api('/agent/{}'.format(self.uuid))
        if response.status_code == 200:
            self.config = response.json()
            return


    def download_plugins(self):
        '''
        Downloads plugins from the API so they can be 
        loaded and run actions via playbook steps
        '''

        hasher = hashlib.sha1()

        response = self.call_mgmt_api('plugin')
        if response.status_code == 200:
            plugins = response.json()
        
        for plugin in plugins:
            response = self.call_mgmt_api('plugin/download/%s' % plugin['filename'])
            if response.status_code == 200:

                # Save the file to disk
                with open(os.path.join('./plugins','%s' % plugin['filename']), 'w', newline='') as f:
                    hasher.update(response.text.encode())
                    if plugin['file_hash'] == hasher.hexdigest():
                        f.write(response.text)
                        f.close()                    


    def heartbeat(self):
        '''
        Pings the API to update the last_heartbeat timestamp of 
        the agent
        '''

        response = self.call_mgmt_api('/agent/heartbeat/{}'.format(self.uuid))
        if response.status_code == 200:
            return response


    def pair(self, options):

        errors = []
        if not options.token:
            errors.append('Missing argument --token')
        
        if not options.console:
            errors.append('Missing argument --console')
        
        if not options.roles:
            errors.append('Missing argument --roles')

        roles = options.roles.split(',')
        token = options.token
        console = options.console

        for role in roles:
            if role not in ('poller','runner'):
                errors.append(f'Invalid role "{role}"')

        if len(errors) > 0:
            logging.info('\n'.join(errors))
            exit(1)

        agent_data = {
            "name": self.hostname,
            "ip_address": self.ip,
            "roles": roles
        }

        headers = {
            'Authorization': 'Bearer %s' % token,
            'Content-Type': 'application/json'
        }

        response = requests.post('%s/agent' % options.console, json=agent_data, headers=headers)
        if response.status_code == 200:
            data = response.json()
            env_file = """CONSOLE_URL='{}'
ACCESS_TOKEN='{}'
AGENT_UUID='{}'""".format(console, data['token'], data['uuid'])

            with open('.env', 'w+') as f:
                f.write(env_file)
        elif response.status_code == 409:
            logging.info('Agent already paired with console.')
            return False
        else:
            logging.info('Failed to pair agent.')
            return False
        logging.info('Pairing complete, restart agent to start work.')
        return True