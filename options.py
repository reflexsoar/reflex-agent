from optparse import OptionParser as op
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv(dotenv_path="config.txt")
load_dotenv()

# Define the parser and options globally
parser = op(description='Reflex Worker Agent')
parser.add_option('--name', dest='name', type=str, action="store",
                  help='A friendly name to call this agent. Overrides the default system name.')
parser.add_option('--pair', dest='pair', action='store_true')
parser.add_option('--token', dest='token', type=str, action="store",
                  help='Token used to pair the agent with the console')
parser.add_option('--console', dest='console', type=str,
                  action="store", help='FQDN name of the Reflex console')
parser.add_option('--roles', dest='roles', type=str, action="store",
                  help='The roles that this worker will perform')
parser.add_option('--proxy', dest='proxy', type=str, action="store",
                  help='If the agent is running behind a proxy you may need to set this')
parser.add_option('--debug', dest='debug', type=str, action="store",
                  help='Do you want to debug the agent? This is dangerous in production')
parser.add_option('--groups', dest='groups', type=str, action="store",
                  help="The groups this agent should be a part of")
parser.add_option('--cacert', dest='cacert', type=str, action="store", default=False,
                  help="Path to the certificate authority certificate used for the Reflex API")
parser.add_option('--ignore-tls', dest='ignore_tls',
                  action='store_false', default=True)
parser.add_option('--event-realert-ttl', dest='event_realert_ttl', type=int, action="store",
                  default=30, help="The time before an event with the same signature should be sent again")
parser.add_option('--event-cache-key', dest="event_cache_key", type=str, action="store", default=os.getenv(
    'REFLEX_AGENT_CACHE_KEY', "signature"), help="The key used to store events in the cache")
parser.add_option('--max-threshold-events', dest="max_threshold_events", type=int, action="store",
                  default=100, help="The maximum number of events to send to the console when a threshold alarm matches")
parser.add_option('--skip-cache-check', dest="skip_cache_check",
                  action="store_true", default=False)

# Parse the options
(options, args) = parser.parse_args()

# Override command-line arguments with environmental variables
if not options.token and os.getenv('REFLEX_AGENT_PAIR_TOKEN'):
    options.token = os.getenv('REFLEX_AGENT_PAIR_TOKEN')

if not options.console and os.getenv('REFLEX_API_HOST'):
    options.console = os.getenv('REFLEX_API_HOST')

if not options.pair and os.getenv('REFLEX_AGENT_PAIR_MODE'):
    options.pair = True

if not options.name and os.getenv('REFLEX_AGENT_NAME'):
    options.name = os.getenv('REFLEX_AGENT_NAME')

if not options.debug and os.getenv('REFLEX_AGENT_DEBUG'):
    options.debug = bool(os.getenv('REFLEX_AGENT_DEBUG'))
else:
    options.debug = False

if not options.skip_cache_check and os.getenv('REFLEX_AGENT_SKIP_CACHE_CHECK'):
    options.skip_cache_check = os.getenv('REFLEX_AGENT_SKIP_CACHE_CHECK')

options.roles = os.getenv('REFLEX_AGENT_ROLES') if os.getenv(
    'REFLEX_AGENT_ROLES') else options.roles
options.groups = os.getenv('REFLEX_AGENT_GROUPS') if os.getenv(
    'REFLEX_AGENT_GROUPS') else options.groups

options.proxy = os.getenv('REFLEX_AGENT_PROXY') if os.getenv(
    'REFLEX_AGENT_PROXY') else options.proxy
options.cacert = os.getenv('REFLEX_AGENT_CA_CERT') if os.getenv(
    'REFLEX_AGENT_CA_CERT') else options.cacert
options.event_realert_ttl = int(os.getenv('REFLEX_AGENT_EVENT_REALERT_TTL')) if os.getenv(
    'REFLEX_AGENT_EVENT_REALERT_TTL') else options.event_realert_ttl
options.max_threshold_events = int(os.getenv('REFLEX_AGENT_MAX_THRESHOLD_EVENTS')) if os.getenv(
    'REFLEX_AGENT_MAX_THRESHOLD_EVENTS') else options.max_threshold_events

if options.ignore_tls and os.getenv('REFLEX_AGENT_IGNORE_TLS'):
    options.ignore_tls = False

# Now, `options` is a global object that can be imported
