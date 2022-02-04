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
from dotenv import load_dotenv


logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":

    load_dotenv(dotenv_path="config.txt")
    load_dotenv()

    parser = op(description='Reflex Worker Agent')
    parser.add_option('--pair', dest='pair', action='store_true')
    parser.add_option('--token', dest='token', type=str, action="store", help='Token used to pair the agent with the console')
    parser.add_option('--console', dest='console', type=str, action="store", help='FQDN name of the Reflex console')
    parser.add_option('--roles', dest='roles', type=str, action="store", help='The roles that this worker will perform')
    parser.add_option('--proxy', dest='proxy', type=str, action="store", help='If the agent is running behind a proxy you may need to set this')
    parser.add_option('--groups', dest='groups', type=str, action="store", help="The groups this agent should be a part of")
    parser.add_option('--cacert', dest='cacert', type=str, action="store", default=False, help="Path to the certificate authority certificate used for the Reflex API")
    parser.add_option('--ignore-tls', dest='ignore_tls', action='store_false', default=True)
    (options,args) = parser.parse_args()

    # Override commandline arguments with environmental variables
    if not options.token and os.getenv('REFLEX_AGENT_PAIR_TOKEN'):
        options.token = os.getenv('REFLEX_AGENT_PAIR_TOKEN')

    if not options.console and os.getenv('REFLEX_API_HOST'):
        options.console = os.getenv('REFLEX_API_HOST')
    
    if not options.pair and os.getenv('REFLEX_AGENT_PAIR_MODE'):
        options.pair = True
            
    options.roles = os.getenv('REFLEX_AGENT_ROLES') if os.getenv('REFLEX_AGENT_ROLES') else options.roles
    options.groups = os.getenv('REFLEX_AGENT_GROUPS') if os.getenv('REFLEX_AGENT_GROUPS') else options.groups
    options.proxy = os.getenv('REFLEX_AGENT_PROXY') if os.getenv('REFLEX_AGENT_PROXY') else options.proxy
    options.cacert = os.getenv('REFLEX_AGENT_CA_CERT') if os.getenv('REFLEX_AGENT_CA_CERT') else options.cacert
    if options.ignore_tls and os.getenv('REFLEX_AGENT_IGNORE_TLS'):
        options.ignore_tls = False

    agent = Agent(options=options)
    
    if options.pair:
        paired = False
        logging.info('Pairing agent..')
        paired = agent.pair()
        if paired is not True:
            exit(1)

    if agent.uuid is None:
        logging.error('Agent .env file corrupt or missing.  Re-pair the agent')
        exit(1)
    
    agent.download_plugins()
    
    #logging.info('Running test plugin!')
    #plugin = Plugin('utilities')
   
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
                    credentials = agent.fetch_credentials(i['credential'])

                if i['plugin'] == "Elasticsearch":

                    e = Elastic(i['config'], i['field_mapping'], credentials)
                    events = e.run()

                    agent.process_events(events)

                if i['plugin'] == "MSExchange":
                    logging.error('MSExchange plugin not implemented yet.')
                    #e = MSExchange(i['config'], i['field_mapping'], credentials)
                    #events = e.poll_mailbox()

        logging.info('Agent sleeping for {} seconds'.format(30))
        time.sleep(30)
