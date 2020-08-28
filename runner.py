import json

def set_value(data, value):
    pass

def s1_tag_host(data):
    print('Tagging host {}'.format(data))
    return data

def run_action(data, action):

    if action['type'] == 'foreach':
        if isinstance(data[action['input']], list):
            for value in data[action['input']]:
                if action['steps']:
                    for step in action['steps']:
                        value = run_action(value, step)

    elif action['type'] == 'set':
        data[action['input']] = action['value']
    
    # If the action is an if conditional
    elif action['type'] == 'if':

        # If the condition is eq
        if action['condition'] == 'eq':
            if data[action['source']] == action['target_value']:
                for step in action['if_true']:
                    data = run_action(data, step)
            else:
                pass

        if action['condition'] == 'ne':
            pass

        if action['condition'] == 'gte':
            pass

        if action['condition'] == 'gt':
            pass

        if action['condition'] == 'lt':
            pass

        if action['condition'] == 'lte':
            pass

    return data
    
    

alert = {
        'title': 'test alert',
        'severity': 2,
        'observables': [
            {
                'value': 'BRIAN-PC',
                'dataType': 'host'
            },
            {
                'value': '192.168.1.221',
                'dataType': 'ip'
            }
        ]
    }


with open('playbook.json') as f:
    playbook = json.loads(f.read())

#print(json.dumps(playbook, indent=2))
print(json.dumps(alert, indent=2))
print('Running playbook: {}'.format(playbook['name']))
for step in playbook['steps']:   
    alert = run_action(alert,step)

print(json.dumps(alert, indent=2))
