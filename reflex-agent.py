import os
from functools import partial
from optparse import OptionParser as op
from utils.base import Agent, Plugin
from multiprocessing import Process, Queue


if __name__ == "__main__":
    parser = op(description='Reflex Worker Agent')
    parser.add_option('--pair', dest='pair', action='store_true')
    parser.add_option('--token', dest='token', type=str, action="store", help='Token used to pair the agent with the console')
    parser.add_option('--console', dest='console', type=str, action="store", help='FQDN name of the Reflex console')
    parser.add_option('--roles', dest='roles', type=str, action="store", help='The roles that this worker will perform')
    parser.add_option('--proxy', dest='proxy', type=str, action="store", help='If the agent is running behind a proxy you may need to set this')
    (options,args) = parser.parse_args()

    agent = Agent()

    if options.pair:
        if not agent.pair(options):
            exit(1)
    else:
        agent.download_plugins()

        plugins = Plugin('sentinelone')
        plugins.actions['hello'](plugins.actions['uppercase']('HELLO WORLD!'))
        #agent.heartbeat()
        #print(agent.get_agent_config().json())