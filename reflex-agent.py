import os
import ssl
import json
import urllib3
import logging
import time
from functools import partial
from optparse import OptionParser as op
from utils.base import Agent, Plugin
from multiprocessing import Process, Queue


logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    parser = op(description='Reflex Worker Agent')
    parser.add_option('--pair', dest='pair', action='store_true')
    parser.add_option('--token', dest='token', type=str, action="store", help='Token used to pair the agent with the console')
    parser.add_option('--console', dest='console', type=str, action="store", help='FQDN name of the Reflex console')
    parser.add_option('--roles', dest='roles', type=str, action="store", help='The roles that this worker will perform')
    parser.add_option('--proxy', dest='proxy', type=str, action="store", help='If the agent is running behind a proxy you may need to set this')
    parser.add_option('--groups', dest='groups', type=str, action="store", help="The groups this agent should be a part of")
    parser.add_option('--ignore-tls', dest='ignore_tls', action='store_true')
    (options,args) = parser.parse_args()

    agent = Agent(options=options)

    if options.pair:
        logging.info('Pairing agent..')
        if not agent.pair(options):
            exit(1)
    else:
        agent.download_plugins()
        
        logging.info('Running test plugin!')
        plugins = Plugin('utilities')
        
        while True:

            agent.get_config()
            agent.heartbeat()

            logging.info('Running agent')

            for i in agent.config['inputs']:

                username = ''
                secret = ''

                headers = {
                    'Authorization': 'Bearer {}'.format(os.getenv('ACCESS_TOKEN')),
                    'Content-Type': 'application/json'
                }

                logging.info('Running input %s' % (i['name']))

                # Fetch the credentials for the input
                if 'credential' in i:
                    username, secret = agent.fetch_credentials(i['credential']['uuid'])

                if i['plugin'] == "Elasticsearch":

                    context = ssl.create_default_context()

                    config = i['config']
                    if config['cafile'] != "":
                        # TODO: NEED TO FIGURE OUT WHERE TO STORE THE CAFILE, maybe as DER format in the input? - BC
                        pass
                    else:
                        context = ssl.create_default_context()

                    CONTEXT_VERIFY_MODES = {
                        "none": ssl.CERT_NONE,
                        "optional": ssl.CERT_OPTIONAL,
                        "required": ssl.CERT_REQUIRED
                    }
                
                    context.check_hostname = config['check_hostname']
                    context.verify_mode = CONTEXT_VERIFY_MODES[config['cert_verification']]

                    es_config = {
                        "scheme": config['scheme'],
                        "ssl_context": context
                    }
                    
                    logging.info('RUNNING ELASTICSEARCH PLUGIN')
                    if config['auth_method'] == 'http_auth':
                        es_config['http_auth'] = (username, secret)
                    else:
                        es_config['api_key'] = (username, secret)

                    es = Elasticsearch(config['hosts'], **es_config)
                    body = {'query': {'range': {"@timestamp": {"gt": "now-{}".format("60d")}}}, 'size':200}
                    events = []

                    # Try to query elasticsearch, if it doens't work
                    # skip processing until the next run
                    response = None
                    try:
                        response = es.search(index=config['index'], body=body)
                    except Exception as e:
                        logging.error('Failed to query input %s' % i['name'])

                    if response and response['hits']['total']['value'] > 0:                        
                        for record in response['hits']['hits']:
                            source = record['_source']
                            observables = agent.extract_observables(source, i['field_mapping'])
                            event = {
                                'title': source['signal']['rule']['name'],
                                'description': source['signal']['rule']['description'],
                                'reference': source['signal']['parent']['id'],
                                'tags': ['foo','bar'],
                                'raw_log': json.dumps(source)
                            }
                            if observables:
                                event['observables'] = observables
                            events.append(event)
                    headers = {
                        'content-type': 'application/json'
                    }

                    if len(events) > 0:
                        logging.info('Pushing %s events to bulk ingest...' % len(events))
                        response = agent.call_mgmt_api('event/_bulk', data={'events': events}, method='POST')
                        if response.status_code == 207:
                            logging.info(response.content)
            time.sleep(30)