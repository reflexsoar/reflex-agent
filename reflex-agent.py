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
from module.options import options
from utils.elasticsearch import Elastic
from dotenv import load_dotenv
from module import Detector, Runner, Poller as PollerNew, MitreMapper
from loguru import logger

# from integrations import LOADED_OUTPUTS

# logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logger.info)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    agent = Agent(options=options)

    # If trying to pair the agent
    if options.pair:

        # Start the process as not paired
        paired = False

        # If the agent picked up its UUID and a previous access_token via .env
        # try to heartbeat
        if agent.uuid and agent.access_token:
            logger.info(
                'Existing UUID and access token found.  Attempting to heartbeat.')
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
        'detector': None,
        'mitre': None,
        # 'poller': None
    }

    logger.info('Running agent')
    # logger.info(f"Loaded {len(LOADED_OUTPUTS)} outputs")

    while True:

        try:
            restart_roles = False
            old_revision = agent.config['policy']['revision']
            policy_uuid = agent.config['policy']['uuid']
            agent.get_config()

            if agent.config['policy']['revision'] != old_revision or agent.config['policy']['uuid'] != policy_uuid:
                restart_roles = True

            if agent.config:
                LOG_LEVEL = 'INFO'
                if options.debug:
                    LOG_LEVEL = 'DEBUG'

                if options.debug:
                    logger.debug(f"Agent config: {agent.config}")

                agent_roles = {
                    'runner': Runner,
                    'detector': Detector,
                    'mitre': MitreMapper,
                    # 'poller': PollerNew,
                }

                role_configs = {
                    'runner': {
                        'config': agent.config['policy'].get('runner_config', None),
                        'log_level': LOG_LEVEL,
                    },
                    'detector': {
                        'config': agent.config['policy'].get('detector_config', None),
                        'log_level': LOG_LEVEL,
                    },
                    'mitre': {
                        'config': agent.config['policy'].get('mitre_mapper_config', None),
                        'log_level': LOG_LEVEL,
                    },
                    # 'poller': {'config': agent.config['policy'].get('poller_config', None), 'log_level': log_level},
                }

                if restart_roles:
                    logger.info(
                        f"Agent policy updated, restarting all roles with new configuration values")
                    for role in role_processes:
                        if role_processes[role]:
                            logger.info(f"Stopping {role} role")
                            role_processes[role].terminate()
                            role_processes[role].join()
                            role_processes[role] = None

                if agent.config['roles']:
                    for role in agent_roles:
                        if role in agent.config['roles'] and (role not in role_processes or role_processes[role] is None):

                            # Start up the role process
                            logger.info(
                                f"Agent is a {role}, spawning {role} role")
                            role_processes[role] = agent_roles[role](
                                config=role_configs[role], agent=agent)
                            role_processes[role].start()

                            # Set the role as healthy
                            agent.role_health[role] = 2

                        # If the agent should be a specific role and the role process was previously started
                        # check it's health and attempt to restart it if it has crashed
                        elif role in agent.config['roles'] and role_processes[role]:
                            logger.info(f"Checking {role} module status")
                            if not role_processes[role].is_alive():
                                logger.info(
                                    f"{role} module has is dead, restarting {role} role")
                                role_processes[role] = agent_roles[role](
                                    config=role_configs[role], agent=agent)
                                role_processes[role].start()
                                agent.role_health[role] = 1
                            else:
                                agent.role_health[role] = 2

                        # If the agent should not be a specific role and the role process was previously started
                        # close the role process and set the role as not running
                        elif not role in agent.config['roles'] and role_processes[role]:
                            logger.info(
                                f"Agent is no longer a {role}, stopping {role} role")
                            role_processes[role].terminate()
                            role_processes[role].join()
                            agent.role_health[role] = 0
                            role_processes[role] = None

                    if 'poller' in agent.config['roles']:
                        for i in agent.config['inputs']:

                            # Don't poll input if it's set to detections_only
                            if 'detections_only' in i and i['detections_only'] is True:
                                continue

                            credentials = ()

                            headers = {
                                'Authorization': 'Bearer {}'.format(os.getenv('ACCESS_TOKEN')),
                                'Content-Type': 'application/json'
                            }

                            logger.info('Running input %s' % (i['name']))

                            # Fetch the credentials for the input
                            if 'credential' in i:
                                credentials = agent.fetch_credentials(
                                    i['credential'])

                            if i['plugin'] == "Elasticsearch":
                                config = i['config']
                                if options.debug:
                                    config['cafile'] = None
                                    config['check_hostname'] = False
                                    config['cert_verfication'] = 'none'

                                e = Elastic(
                                    config, i['field_mapping'], credentials, input_uuid=i['uuid'])
                                events = e.run()

                                agent.process_events(
                                    events, agent.options.skip_cache_check)

                            if i['plugin'] == "MSExchange":
                                logger.error(
                                    'MSExchange plugin not implemented yet.')
                                # e = MSExchange(i['config'], i['field_mapping'], credentials)
                                # events = e.poll_mailbox()

                            if i['plugin'] == "LDAP":
                                logger.error(
                                    'LDAP plugin not implemented yet.')

                                # l = LDAPSource(i['config'], credentials)
                                # items = l.query()

                                """
                                threat_list_config = {
                                    'threat_list_uuid': 'xxxx-xxxx-xxxx-xxxx-xxxx',
                                    'action': 'append|replace'
                                }
                                """

                                # agent.push_intel(items, i['threat_list_config'])
                else:
                    logger.info('Agent is not configured to run any roles')
                    for role in role_processes:
                        if role_processes[role]:
                            logger.info(
                                f"Agent is no longer a {role}, stopping {role} role")
                            role_processes[role].terminate()
                            role_processes[role].join(1)
                            role_processes[role] = None

            agent.heartbeat()
            agent.expire_cache()
            logger.info('Agent sleeping for {} seconds'.format(
                agent.health_check_interval))
            time.sleep(agent.health_check_interval)
        except Exception as e:
            exception_type, exception_object, exception_traceback = sys.exc_info()
            logger.error("Exception type:", exception_type)
            logger.error("Exception object:", exception_object)
            logger.error("Exception traceback:", exception_traceback)
            logger.error("Exception line number:",
                         exception_traceback.tb_lineno)
            logger.error('Agent failed with exception: {}'.format(e))
