from argparse import Action
import time
import logging
import os
from functools import partial
from pluginbase import PluginBase
from multiprocessing import Process
from multiprocessing.pool import ThreadPool
from .errors import ActionError

here = os.path.abspath(os.path.dirname(__file__))
get_path = partial(os.path.join, here)
plugin_base = PluginBase(package='plugins', searchpath=[
                         get_path('../plugins')])


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
        try:
            return self.actions[name](*args, **kwargs)
        except Exception as e:
            raise ActionError(e)

    def __repr__(self):
        return self.name


class Runner(Process):
    '''
    A runner process runs plugin actions that are either steps
    in a playbook or individual actions that an analyst
    has triggered from the ReflexSOAR API
    '''

    def __init__(self, config, agent=None, log_level='INFO', *args, **kwargs):

        super(Runner, self).__init__(*args, **kwargs)

        if 'runner' in config:
            self.config = config['runner']
        else:
            self.config = {
                'concurrent_actions': 10,
                'graceful_exit': False,
                'wait_interval': 5,
                'plugin_poll_interval': 60
            }

        self.running = True

        log_levels = {
            'DEBUG': logging.DEBUG,
            'ERROR': logging.ERROR,
            'INFO': logging.INFO
        }

        log_handler = logging.StreamHandler()
        log_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.addHandler(log_handler)
        self.logger.setLevel(log_levels[log_level])
        self.log_level = log_level
        self.last_plugin_poll = None
        self.agent = agent
        self.actions = []
        self.plugins = []
        self.loaded_plugins = ['utilities']

    def download_plugins(self):
        '''
        Downloads plugins from the API
        '''
        self.plugins = self.agent.download_plugins()

    def load_plugins(self):
        '''
        Loads all the plugins in to self.plugins for tracking
        '''
        for _plugin in self.loaded_plugins:
            plugin = Plugin(_plugin)
            try:
                plugin.run_action('debug', f'Loading plugin: {plugin}')
            except ActionError as e:
                self.logger.error(f"Error running plugin {_plugin}. {e}")

    def run_action(self):
        '''
        Executes an action from the queue of actions
        '''
        raise NotImplementedError('run_action not implemented')

    def check_plugin_poll_time(self):
        '''
        Checks to see if it is time to poll for new plugins based on the configuration
        parameter `plugin_poll_interval`
        '''
        if self.last_plugin_poll is None:
            self.last_plugin_poll = time.time()
            return True
        else:
            if time.time() - self.last_plugin_poll > self.config['plugin_poll_interval']:
                self.last_plugin_poll = time.time()
                return True
            else:
                return False

    def run(self):
        '''
        Periodically checks for new actions from a queue and runs them
        '''
        while self.running:

            # If it is time to poll for new plugins then do so
            if self.check_plugin_poll_time():
                self.logger.info('Checking for new plugins')
                self.download_plugins()
                self.load_plugins()

            self.logger.info('Checking for new actions')
            if len(self.actions) > 0:
                self.logger.info(
                    'Run complete, sleeping for %s seconds', self.config['wait_interval'])
            else:
                self.logger.info(
                    'No actions to run, sleeping for %s seconds', self.config['wait_interval'])
            time.sleep(self.config['wait_interval'])
