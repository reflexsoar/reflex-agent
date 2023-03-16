import sys
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
from module import Detector, Runner
from loguru import logger


#logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logger.info)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":

    load_dotenv(dotenv_path="config.txt")
    load_dotenv()

    parser = op(description='Reflex Worker Agent')
    parser.add_option('--name', dest='name', type=str, action="store", help='A friendly name to call this agent.  Overrides the default system name.')
    parser.add_option('--pair', dest='pair', action='store_true')
    parser.add_option('--token', dest='token', type=str, action="store", help='Token used to pair the agent with the console')
    parser.add_option('--console', dest='console', type=str, action="store", help='FQDN name of the Reflex console')
    parser.add_option('--roles', dest='roles', type=str, action="store", help='The roles that this worker will perform')
    parser.add_option('--proxy', dest='proxy', type=str, action="store", help='If the agent is running behind a proxy you may need to set this')
    parser.add_option('--groups', dest='groups', type=str, action="store", help="The groups this agent should be a part of")
    parser.add_option('--cacert', dest='cacert', type=str, action="store", default=False, help="Path to the certificate authority certificate used for the Reflex API")
    parser.add_option('--ignore-tls', dest='ignore_tls', action='store_false', default=True)
    parser.add_option('--event-realert-ttl', dest='event_realert_ttl', type=int, action="store", default=300, help="The time before an event with the same signature should be sent again")
    parser.add_option('--event-cache-key', dest="event_cache_key", type=str, action="store", default=os.getenv('REFLEX_AGENT_CACHE_KEY', "signature"), help="The key used to store events in the cache")
    parser.add_option('--max-threshold-events', dest="max_threshold_events", type=int, action="store", default=100, help="The maximum number of events to send to the console when a threshold alarm matches")
    parser.add_option('--skip-cache-check', dest="skip_cache_check", action="store_true", default=False)
    (options,args) = parser.parse_args()

    # Override commandline arguments with environmental variables
    if not options.token and os.getenv('REFLEX_AGENT_PAIR_TOKEN'):
        options.token = os.getenv('REFLEX_AGENT_PAIR_TOKEN')

    if not options.console and os.getenv('REFLEX_API_HOST'):
        options.console = os.getenv('REFLEX_API_HOST')
    
    if not options.pair and os.getenv('REFLEX_AGENT_PAIR_MODE'):
        options.pair = True

    if not options.name and os.getenv('REFLEX_AGENT_NAME'):
        options.name = os.getenv('REFLEX_AGENT_NAME')

    if not options.skip_cache_check and os.getenv('REFLEX_AGENT_SKIP_CACHE_CHECK'):
        options.skip_cache_check = os.getenv('REFLEX_AGENT_SKIP_CACHE_CHECK')
            
    options.roles = os.getenv('REFLEX_AGENT_ROLES') if os.getenv('REFLEX_AGENT_ROLES') else options.roles
    options.groups = os.getenv('REFLEX_AGENT_GROUPS') if os.getenv('REFLEX_AGENT_GROUPS') else options.groups
    
    options.proxy = os.getenv('REFLEX_AGENT_PROXY') if os.getenv('REFLEX_AGENT_PROXY') else options.proxy
    options.cacert = os.getenv('REFLEX_AGENT_CA_CERT') if os.getenv('REFLEX_AGENT_CA_CERT') else options.cacert
    options.event_realert_ttl = int(os.getenv('REFLEX_AGENT_EVENT_REALERT_TTL')) if os.getenv('REFLEX_AGENT_EVENT_REALERT_TTL') else options.event_realert_ttl
    options.max_threshold_events = int(os.getenv('REFLEX_AGENT_MAX_THRESHOLD_EVENTS')) if os.getenv('REFLEX_AGENT_MAX_THRESHOLD_EVENTS') else options.max_threshold_events
    
    if options.ignore_tls and os.getenv('REFLEX_AGENT_IGNORE_TLS'):
        options.ignore_tls = False
    
    agent = Agent(options=options)
    
    # If trying to pair the agent
    if options.pair:

        # Start the process as not paired
        paired = False

        # If the agent picked up its UUID and a previous access_token via .env
        # try to heartbeat
        if agent.uuid and agent.access_token:
            logger.info('Existing UUID and access token found.  Attempting to heartbeat.')
            response = agent.heartbeat()

            # If the heartbeat succeeds set paired to True and skip the rest
            if response:
                paired = True
            else:
                logger.info('Heartbeat failed.  Attempting to pair.')

        if paired is not True:
            logger.info('Pairing agent..')
            paired = agent.pair()

        if paired is not True:
            logger.error('Failed to pair agent')
            exit(1)

    if agent.uuid is None:
        logger.error('Agent .env file corrupt or missing.  Re-pair the agent')
        exit(1)

    role_processes = {
        'runner': None,
        'detector': None
    }

    logger.info('Running agent')
   
    while True:

        try:
            restart_roles = False
            old_revision = agent.config['policy']['revision']
            policy_uuid = agent.config['policy']['uuid']
            agent.get_config()
            if agent.config['policy']['revision'] != old_revision or agent.config['policy']['uuid'] != policy_uuid:
                restart_roles = True

            if agent.config:

                agent_roles = {
                    'runner': Runner,
                    'detector': Detector,
                    #'poller': Poller,
                }

                role_configs = {
                    'runner': agent.config['policy'].get('runner_config', None),
                    'detector': agent.config['policy'].get('detector_config', None)
                }

                if restart_roles:
                    logger.info(f"Agent policy updated, restarting all roles with new configuration values")
                    for role in role_processes:
                        if role_processes[role]:
                            logger.info(f"Stopping {role} role")
                            role_processes[role].terminate()
                            role_processes[role].join()
                            role_processes[role] = None

                if agent.config['roles']:
                    for role in agent_roles:
                        if role in agent.config['roles'] and not role_processes[role]:

                            # Start up the role process
                            logger.info(f"Agent is a {role}, spawning {role} role")
                            role_processes[role] = agent_roles[role](config=role_configs[role], agent=agent)
                            role_processes[role].start()

                            # Set the role as healthy
                            agent.role_health[role] = 2

                        # If the agent should be a specific role and the role process was previously started
                        # check it's health and attempt to restart it if it has crashed
                        elif role in agent.config['roles'] and role_processes[role]:
                            logger.info(f"Checking {role} module status")
                            if not role_processes[role].is_alive():
                                logger.info(f"{role} module has is dead, restarting {role} role")
                                role_processes[role] = agent_roles[role](config=role_configs[role], agent=agent)
                                role_processes[role].start()
                                agent.role_health[role] = 1
                            else:
                                agent.role_health[role] = 2

                        # If the agent should not be a specific role and the role process was previously started
                        # close the role process and set the role as not running
                        elif not role in agent.config['roles'] and role_processes[role]:
                            logger.info(f"Agent is no longer a {role}, stopping {role} role")
                            role_processes[role].terminate()
                            role_processes[role].join()
                            agent.role_health[role] = 0
                            role_processes[role] = None                    


                    if 'poller' in agent.config['roles']:
                        for i in agent.config['inputs']:

                            credentials = ()

                            headers = {
                                'Authorization': 'Bearer {}'.format(os.getenv('ACCESS_TOKEN')),
                                'Content-Type': 'application/json'
                            }

                            logger.info('Running input %s' % (i['name']))

                            # Fetch the credentials for the input
                            if 'credential' in i:
                                credentials = agent.fetch_credentials(i['credential'])

                            if i['plugin'] == "Elasticsearch":

                                e = Elastic(i['config'], i['field_mapping'], credentials, input_uuid=i['uuid'])
                                events = e.run()

                                agent.process_events(events, agent.options.skip_cache_check)

                            if i['plugin'] == "MSExchange":
                                logger.error('MSExchange plugin not implemented yet.')
                                #e = MSExchange(i['config'], i['field_mapping'], credentials)
                                #events = e.poll_mailbox()

                            if i['plugin'] == "LDAP":
                                logger.error('LDAP plugin not implemented yet.')

                                #l = LDAPSource(i['config'], credentials)
                                #items = l.query()

                                """
                                threat_list_config = {
                                    'threat_list_uuid': 'xxxx-xxxx-xxxx-xxxx-xxxx',
                                    'action': 'append|replace'
                                }
                                """

                                #agent.push_intel(items, i['threat_list_config'])
                else:
                    logger.info('Agent is not configured to run any roles')
                    for role in role_processes:
                        if role_processes[role]:
                            logger.info(f"Agent is no longer a {role}, stopping {role} role")
                            role_processes[role].terminate()
                            role_processes[role].join(1)
                            role_processes[role] = None


            agent.heartbeat()
            agent.expire_cache()
            logger.info('Agent sleeping for {} seconds'.format(agent.health_check_interval))
            time.sleep(agent.health_check_interval)
        except Exception as e:
            exception_type, exception_object, exception_traceback = sys.exc_info()
            print("Exception type:", exception_type)
            print("Exception object:", exception_object)
            print("Exception traceback:", exception_traceback)
