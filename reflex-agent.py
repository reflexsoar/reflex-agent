import os
import ssl
import urllib3
import logging
import time
from functools import partial
from optparse import OptionParser as op
from utils.base import Agent, Plugin
from multiprocessing import Process, Queue
from elasticsearch import Elasticsearch

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
    (options,args) = parser.parse_args()

    agent = Agent()

    if options.pair:
        logging.info('Pairing agent..')
        if not agent.pair(options):
            exit(1)
    else:
        agent.download_plugins()
        
        logging.info('Running test plugin!')
        plugins = Plugin('utilities')
        plugins.actions['uppercase']('clay sux')

        
        while True:

            agent.get_config()
            agent.heartbeat()

            logging.info('Running agent')

            for i in agent.config['inputs']:

                headers = {
                    'Authorization': 'Bearer {}'.format(os.getenv('ACCESS_TOKEN')),
                    'Content-Type': 'application/json'
                }

                logging.info('Running input %s' % (i['name']))

                # Fetch the credentials for the input
                if 'credential' in i:
                
                    # Fetch the credential details
                    logging.info("Fetching credentials for %s" % (i['name']))
                    response = agent.call_mgmt_api('credential/%s' % i['credential']['uuid'])
                    if response.status_code == 200:
                        cred_details = response.json()

                    # Decrypt the secret
                    response = agent.call_mgmt_api('credential/decrypt/%s' % i['credential']['uuid'])
                    if response.status_code == 200:
                        cred_data = response.json()
                        secret = response.json()['secret']

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
                        es_config['http_auth'] = (cred_details['username'], secret)
                    else:
                        es_config['api_key'] = (cred_details['username'], secret)

                    es = Elasticsearch(config['hosts'], **es_config)
                    body = {'query': {'range': {"@timestamp": {"gt": "now-{}".format("30d")}}}, 'size':200}
                    response = es.search(index=config['index'], body=body)
                    if response['hits']['total']['value'] > 0:
                        events = []
                        for record in response['hits']['hits']:
                            source = record['_source']
                            observables = agent.extract_observables(source, i['field_mapping'])
                            event = {
                                'title': source['signal']['rule']['name'],
                                'description': source['signal']['rule']['description'],
                                'reference': source['signal']['parent']['id'],
                                'tags': ['foo','bar'],
                                'raw_log': source
                            }
                            if observables:
                                event['observables'] = observables
                            events.append(event)
                    headers = {
                        'content-type': 'application/json'
                    }

                    logging.info('Pushing %s events to bulk ingest...' % len(events))
                    response = agent.call_mgmt_api('event/_bulk', data={'events': events}, method='POST')
                    #if response.status_code == 207:
                    #    logging.info(response.content)
            time.sleep(30)