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
from utils.elasticsearch import Elastic


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
        if not agent.pair():
            exit(1)
    else:
        #agent.download_plugins()
        
        logging.info('Running test plugin!')
        plugin = Plugin('utilities')
        
        while True:

            agent.get_config()
            agent.heartbeat()

            logging.info('Running agent')

            if agent.config:
                for i in agent.config['inputs']:

                    credentials = ()

                    headers = {
                        'Authorization': 'Bearer {}'.format(os.getenv('ACCESS_TOKEN')),
                        'Content-Type': 'application/json'
                    }

                    logging.info('Running input %s' % (i['name']))

                    # Fetch the credentials for the input
                    if 'credential' in i:
                        credentials = agent.fetch_credentials(i['credential']['uuid'])

                    if i['plugin'] == "Elasticsearch":

                        e = Elastic(i['config'], i['field_mapping'], credentials)
                        events = e.run()

                        agent.process_events(events)

            time.sleep(30)