import operator
from utils.base import Plugin, Event


class Item(object):

    def __init__(self, name):

        self.name = name

    def __repr__(self):
        return "<Item name='{}'>".format(self.name)

class Test(object):

    def __init__(self, title, items):
        self.title = title
        self.items = items

    def __repr__(self):
        return "<Test title='{}'>".format(self.title)


class PlaybookStep(object):

    def __init__(self, data, plugin, action, target, prop=None, *args, **kwargs):

        self.plugin = plugin
        self.action = action
        self.data = data
        self.target = target
        self.prop = prop
        self.args = args
        self.kwargs = kwargs

    def execute(self):
        inp = operator.attrgetter(self.target)(self.data)
        if isinstance(inp, list):
            for item in inp:
                if isinstance(item, str):
                    print(self.plugin.run_action(self.action, item, *self.args, **self.kwargs))
                    continue
                if isinstance(item, object):
                    print(self.plugin.run_action(self.action, getattr(item, self.prop), *self.args, **self.kwargs))                
        if isinstance(inp, str):
            print(self.plugin.run_action(self.action, inp, *self.args, **self.kwargs))


p = Plugin('utilities')

steps = [
    {
        'plugin': p,
        'action': 'uppercase',
        'target': 'tags'
    }
]

event = {
        'title': 'Whoami executed on NETSURGE-PC',
        'description': 'Someone did something with whoami.exe',
        'tags': ['awesome','sauce','foo','bar'],
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

e = Event()
e.from_dict(event)

for s in steps:
    step = PlaybookStep(data=e, **s)
    step.execute()

