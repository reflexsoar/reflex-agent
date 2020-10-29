import logging
import operator
from utils.base import Plugin, Event

logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)

CONDITIONAL_PLAYBOOK_STEP = 'condition'
PLUGIN_PLAYBOOK_STEP = 'playbook_action'


class ConditionalPlaybookStep(object):
    '''
    A conditional playbook step that executes another 
    playbook step depending on the condition
    '''

    def __init__(self, target, expected, condition, key=None, if_true=[], if_false=[]):
        '''
        Initializes a conditional playbook step
        '''

        self.target = target
        self.expected = expected
        self.condition = condition
        self.key = key
        self.if_true = if_true
        self.if_false = if_false


    def compare(self):
        if self.condition == 'eq':

            if isinstance(self.target, list):
                for item in self.target:
                    if isinstance(item, dict):
                        if self.key:
                            if item[self.key] == self.expected:
                                print('Execute action - List / Dict Key')

                    if isinstance(item, str):
                        if item == self.expected:
                            print('Execute action - List / String')

            if isinstance(self.target, dict):
                if self.key:
                    print('Execute action - Dict')
                    #return self.target[self.key] == self.expected

            if isinstance(self.target, str):
                print('Execute action - String')
                #return self.target == self.expected

            if isinstance(self.target, int):
                print('Execute action - Int')
                #return self.target == self.expected


class PluginPlaybookStep(object):
    '''
    A playbook step that is executed by a playbook runner
    '''

    def __init__(self, plugin, action, target, *args, **kwargs):
        '''
        Initializes the playbook step
        '''
        
        self.plugin = plugin
        self.action = action
        self.args = args
        self.kwargs = kwargs
        self.target = target


    def execute(self):
        '''
        Executes the step and the associated plugin action
        feeds required args/kwargs for the plugin action to the plugin
        '''

        logging.info('Running playbook step, plugin={}, action={}'.format(self.plugin, self.action))
        if isinstance(self.target, list):
            l = []
            for t in self.target:
                l.append(self.plugin.run_action(self.action, t, *self.args, **self.kwargs))
            return l
        else:
            return self.plugin.run_action(self.action, self.target, *self.args, **self.kwargs)


class PlaybookRunner(object):
    '''
    Runs a user defined playbook and all its associated steps
    '''

    def __init__(self, playbook):
        self.playbook = playbook
        self.plugins = {}
        self.event = None

    def check_playbook(self):
        self.plugins = {plugin: Plugin(plugin) for plugin in self.playbook['plugins']}


    def run(self, event):
        self.check_playbook()
        self.event = event
        for s in self.playbook['steps']:
            step_type = s.pop('step_type')
            if step_type == CONDITIONAL_PLAYBOOK_STEP:                
                step = ConditionalPlaybookStep(**s)
                print(step.compare())
            if step_type == PLUGIN_PLAYBOOK_STEP:
                step = PluginPlaybookStep(action=s.pop('action'), plugin=self.plugins[s.pop('plugin')], source=event, target=s.pop('target'), **s)
                self.event = step.execute()

        return self.event


if __name__ == "__main__":
    import json

    event = {
        'title': 'Whoami executed on NETSURGE-PC',
        'description': 'Someone did something with whoami.exe',
        'tags': [],
        'severity': 0,
        'tlp': 2,
        'reference': 'abc123',
        'observables': [
            {
                'value': 'BRIAN-PC',
                'dataType': 'host',
                'tlp': 0,
                'ioc': False,
                'spotted': False,
                'safe': False,
                'tags': ['source-workstation']
            },
            {
                'value': '192.168.1.221',
                'dataType': 'ip',
                'tlp': 0,
                'ioc': False,
                'spotted': False,
                'safe': False,
                'tags': ['rfc1918']
            }
        ],
        'raw_log': 'FOOBAR'
    }

    playbook = {
        'plugins': ['utilities'],
        'steps': [
            {
                'step_type': PLUGIN_PLAYBOOK_STEP,
                'plugin': 'utilities',
                'action': 'uppercase',
                'target': 'title'
            },
            {
                'step_type': PLUGIN_PLAYBOOK_STEP,
                'plugin': 'utilities',
                'action': 'uppercase',
                'target': 'observables',
                'key': 'dataType'
            }
        ]
    }

    p = PlaybookRunner(playbook=playbook)
    event = p.run(event)
    print(json.dumps(event, indent=2))
