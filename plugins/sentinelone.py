import json
import requests 

def headers(self):
    ''' Returns the HTTP headers required for making the API call '''
    return {
            "Authorization": "ApiToken {}".format(self.config['api_key']),
            "Content-Type": "application/json"
        }

def call_api(self, endpoint, data, *args, **kwargs):
    ''' Makes a cacheable call to the SentinelOne API '''

    try:
        response = requests.get(f"https://{self.config['tenant']}{endpoint}{data}", headers=self.headers())
        if response.status_code == 200:
            data = response.json()
            if data['pagination']['totalItems'] > 0:
                return response.json()
        else:
            return None
    except Exception:
        return None


def tag_host(self, data):
    ''' 
    Tags a host with certain data 
    
    data: the computerName of the machine
    '''

    artifact = data
    if artifact.dataType == 'host':
        result = self.call_api(endpoint='/web/api/v2.0/agents?computerName=', data=artifact.data)
        if result:
            result = json.loads(result)['data'][0]
            artifact.tags.append(f"s1:version={result['agentVersion']}")
            artifact.tags.append(f"s1:user={result['lastLoggedInUserName']}")
            artifact.tags.append(f"s1:domain={result['domain']}")
            artifact.tags.append(f"s1:os={result['operatingSystem']}")
        else:
            artifact.tags.append('s1:status=missing')
        
    return artifact


def agent_from_ip(self, data):
    ''' 
    Fetches an agent via its IP address 

    data: a network IP (IPv4)
    
    '''
    artifact = data
    if artifact.dataType == 'ip':
        result = self.call_api(endpoint='/web/api/v2.0/agents?networkInterfaceInet__contains=', data=artifact.data)
        if result:
            result = json.loads(result)['data'][0]
            artifact.tags.append(f"s1:agent={result['computerName']}")
    return artifact


def allow_hash(self, data, os="windows", site_id=None, tenant=False):
    '''
    Allows a hash on in the SentinelOne console

    data: the hash to allow
    site_id: the site to allow the hash in, could be the agents site
    global: is this a tenant wide allow?
    '''

    if os not in ['windows','mac','linux']:
        return False

    raise NotImplementedError


def block_hash(self, data, os="windows", site_id=None, tenant=False):
    '''
    Blocks a hash on in the SentinelOne console

    data: the hash to block
    site_id: the site to block the hash in, could be the agents site
    global: is this a tenant wide block?
    '''

    if os not in ['windows','mac','linux']:
        return False

    raise NotImplementedError


def isolate_host(self, data):
    '''
    Isolates a host from the network using the 
    SentinelOne disabled network functionality

    Expects a SentinelOne agent UUID
    '''

    raise NotImplementedError


def reboot_host(self, data):
    '''
    Reboots a host

    Expects a SentinelOne agent UUID
    '''
    raise NotImplementedError


def power_off_host(self, data):
    '''
    Shuts down a host

    Expects a SentinelOne agent UUID
    '''
    raise NotImplementedError


def setup(app):

    app.register_action('block_hash', block_hash)
    app.register_action('agent_from_ip', agent_from_ip)
    app.register_action('tag_host', tag_host)
    app.register_action('allow_hash', allow_hash)
    app.register_action('tag_host', tag_host)
    app.register_action('isolate_host', isolate_host)
    app.register_action('reboot_host', isolate_host)
    app.register_action('power_off_host', power_off_host)