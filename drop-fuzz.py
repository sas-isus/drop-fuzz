#!/usr/bin/env python

"""
drop-fuzz.py: Generates a report containing the results of running a fuzzer
              on a specified Drupal module.
Usage:
    $ python drop-fuzz.py -t 127.0.0.1/drupal/ -a apikey -u brian -p password123
"""

__author__    = "Brian Jopling"
__copyright__ = "Copyright 2017, University of Pennsylvania School of " \
                "Arts and Sciences."
__credits__   = ["Brian Jopling", "Clay Wells"]
__license__   = "GNU GENERAL PUBLIC LICENSE"
__version__   = "1.0.0"
__status__    = "Development"


""" IMPORTS """


# Used for getting args.
from optparse import OptionParser
# Used for letting the script rest while ZAP functions are loaded.
import time
# Used for printing to the console nicely.
from pprint import pprint
# Used to access ZAP functionalities.
from zapv2 import ZAPv2
# Used for getting module files.
import os
# Used for parsing *.routing.yml.
import yaml
# Used for user-input tab completion.
import readline


""" GLOBALS """


# Get & Set Options / args
parser = OptionParser(usage="usage: %prog [options]", version="%prog 1.0")
parser.add_option("-t", "--target", dest="target", \
                  help="Target site containing Drupal module", metavar='<TARGET>')
parser.add_option("-a", "-k", "--api", "--key", dest="apikey", \
                  help="API Key obtained through ZAP", metavar='<APIKEY>')
parser.add_option("-m", "--module", "--path", dest="module", \
                  help="Path to module to fuzz", metavar='<PATH>')
parser.add_option("-u", "--username", "--user", dest="login_name", \
                  help="Drupal login username", metavar='<USERNAME>')
parser.add_option("-p", "--password", "--pass", dest="login_pass", \
                  help="Drupal login password", metavar='<PASSWORD>')
parser.add_option("-A", "--active", action="store_true", dest="active", \
                  help="Perform an Active Scan")
parser.add_option("-f", "--force", action="store_true", dest="force", \
                  help="Force default values for prompts")
(options, args) = parser.parse_args()


# Ensure target has been set properly.
target = options.target
if not target:
    if not options.force:
        ans = raw_input("Use http://127.0.0.1/drupal as target? [Y|N]: ")
        if ans.lower() == 'n' or ans.lower() == 'no':
            target = raw_input("Enter a URL to target: ")
        else:
            target = 'http://127.0.0.1/drupal'
    else:
        target = 'http://127.0.0.1/drupal'

# Ensure apikey has been set properly.
# Get an API key by opening ZAP, going to Tools -> Options, selecting "API",
# and copying the key on the right.
apikey = options.apikey
if not apikey:
    apikey = raw_input("Enter your ZAP API Key (Tools -> Options, select 'API'): ")

# Ensure login_name has been set properly.
login_name = options.login_name
if not login_name:
    if not options.force:
        ans = raw_input("Use admin as username? [Y|N]: ")
        if ans.lower() == 'n' or ans.lower() == 'no':
            login_name = raw_input("Enter your Drupal username: ")
        else:
            login_name = 'admin'
    else:
        login_name = 'admin'

# Ensure login_password has been set properly.
login_pass = options.login_pass
if not login_pass:
    if not options.force:
        ans = raw_input("Use admin as password? [Y|N]: ")
        if ans.lower() == 'n' or ans.lower() == 'no':
            login_pass = raw_input("Enter your Drupal password: ")
        else:
            login_pass = 'admin'
    else:
        login_pass = 'admin'

# Ensure module has been set properly.
module = options.module
if not module:
    readline.set_completer_delims(' \t\n')
    readline.parse_and_bind("tab: complete")
    module = raw_input("Enter module path (ex /home/brj424/metatag): ")

# Array containing routing paths for selected module.
module_routes = []

# Get current time and date for unique naming.
current_date = time.strftime("%y%m%d")
current_time = time.strftime("%H%M%S")

# Vars used in initializing and undergoing a ZAP session.
context        = 'Context-%s-%s' % (current_date, current_time)
contextid      = ''
userid         = ''
authmethodname = 'formBasedAuthentication'

# The below looks a bit confusing. That's because this string is a set of
# queries containing queries. The outer set uses &, =, etc, while the inner
# set uses the respective encodings of those special characters. This is how
# ZAP is able to distinguish the inner from the outer.
authmethodconfigparams = 'loginUrl=' + target + '/user/login/' + \
                         '&loginRequestData=name%3D{%25username%25}' + \
                         '%26pass%3D{%25password%25}' + \
                         '%26form_id%3Duser_login_form%26op%3DLog%2Bin'

# By default ZAP API client will connect to port 8080
zap = ZAPv2(apikey=apikey)
# If listening on port 8090, use:
# zap = ZAPv2(apikey=apikey, proxies={'http': 'http://127.0.0.1:8090',
# 'https': 'http://127.0.0.1:8090'})
# Should we ask the user for the port? Or just assume 8080? Maybe add an arg for it.


""" FUNCTIONS """


def display_banner():
    """Prints banner to console."""
    banner = """

                                                      .:`
                                                     .+++-`
                                                  .:+++++++/:.`
                                              `-/++++++++++++++/-`
                                            `:++++++++++++++++++++:`
________ __________ ________ __________    -++++++++++++++++++++++++-    _______________ _______________________
\\______ \\\\______   \\\\_____  \\\\______  \\\\  :++++++++++++++++++++++++++:   \\_   _____/    |   \\____    /\\____    /
 |    |  \\|       _/ /   |   \\|     ___/  .++++++++++++++++++++++++++++.  |    __) |    |   / /     /   /     /
 |    `   \    |   \\/    |    \\    |     /++++++++++++++++++++++++++++/   |     \\  |    |  / /     /_  /     /_
/_______  /____|_  /\\_______  /____|     ++++++++++////++++++++++++++++   \\___  /  |______/ /_______ \\/_______ \\
        \\/       \\/         \\/           +++++++/.      `-/+++++/-`  -+       \\/                    \\/        \\/
                                         -+++++/           `-:-`     `:
                                          /++++:          `-:/:`     .`
                                           :++++-     `.:/:---:+/.  .`
                                            ./+++++//++++//+++/++++-
                                              .:++++++/.-::::-::/-`
                                                 .-:/++++//::-.`

     """
    print banner


def attempt_banner_display():
    """If the console size is large enough, display our banner."""
    rows, columns = os.popen('stty size', 'r').read().split()
    if int(columns) > 112:
        display_banner()


def get_routing_paths():
    global module_routes
    routing_file = ''
    # Check every file in the specified directory.
    # See if a routing file exists.
    for f in os.listdir(module):
        if f.endswith(".routing.yml"):
            print "Routing file found at " + os.path.join(module, f) + \
                  "...OK"
            routing_file = f
    # If a routing file is found, then add all the routes to our list.
    if routing_file:
        with open(os.path.join(module, routing_file), 'r') as r_file:
            try:
                reading_routes = yaml.load(r_file)
                for l in reading_routes:
                    try:
                        # Note: this omits URLs that have a variable path ({x}).
                        # We'll probably want to include this, and fill in
                        # those variables for our spider in this code.
                        # For now, I'm leaving these out since every routing
                        # file I've seen so far had a path that encompassed
                        # these variable paths, making it pointless to scan
                        # them again. But, some of these paths could require
                        # a certain user action to reach, making them hard to
                        # find via spidering the "main" path... but I have yet
                        # to see any of these.
                        if '{' not in reading_routes[l]['path']:
                            module_routes.append(reading_routes[l]['path'])
                    except:
                        pass
            except yaml.YAMLError as exc:
                exit_program(exc)
    # No routes, so this module does not have its own unique paths.
    # Odds are, there's nothing that can be abused because of this.
    # Still, do a manual pen-test to make sure.
    else:
        exit_program("[!] Module does not have a routing file.")
    print 'Found the following routes: ' + str(module_routes) + '...OK'


def setup_zap():
    """Create a Context with our target and user info in ZAP."""
    global contextid, userid
    # Create a Context in ZAP to store our work in.
    contextid = zap.context.new_context(context)
    # Initialize the Context by adding our target to it.
    init_zap_context()
    # Add our Authentication info to the Context.
    init_zap_authentication()
    # Create a User to select from in ZAP.
    userid = zap.users.new_user(contextid, 'user1')
    # Initialize User with our custom username and password.
    init_zap_user()


def init_zap_context():
    """Create new Context in ZAP."""
    # Add Target site to our Context.
    print 'Including target in context...' + \
          zap.context.include_in_context(context, target + '.*')


def init_zap_authentication():
    """Add Authentication method info to our Context."""
    # Set auth method in Context with associated POST data.
    print 'Setting authentication method...' + \
          zap.authentication.set_authentication_method(
              contextid, authmethodname, authmethodconfigparams
          )
    # Set the logged in indicator so ZAP knows if user is logged in or not.
    print 'Setting logged in indicator...' + \
          zap.authentication.set_logged_in_indicator(
              contextid, '\Q<a href="/drupal/user/logout" ' + \
              'data-drupal-link-system-path="user/logout">Log out</a>\E'
          )


def init_zap_user():
    """Add custom credentials to ZAP User and enable it."""
    # Adds custom username and password to ZAP User in our Context.
    print 'Setting authentication credentials...' + \
          zap.users.set_authentication_credentials(
              contextid,
              userid,
              'username=%s&password=%s' % (login_name, login_pass)
          )
    # Enables the User for our current Context.
    print 'Enabling user for current session...' + \
          zap.users.set_user_enabled(contextid, userid, True)


def exit_program(reason):
    """Terminates program and displays reason why."""
    print reason + ' Aborting...'
    exit()


def spider_target():
    """Spiders Target as User in ZAP."""
    # Alert user.
    print '\nStarting Spider...\n'
    # Spider each route.
    for route in module_routes:
        # Alert user.
        print '\nSpidering target %s' % target + route
        # Start scanning in ZAP.
        # Params. (contextId, userId, url, maxChildren, recurse, subtreeOnly)
        scanid = zap.spider.scan_as_user(
                                         contextid,
                                         userid,
                                         target + route,
                                         0,
                                         True,
                                         True
                                        )
        # Give the Spider a chance to start.
        time.sleep(2)
        # Print out progress of Spider until it's at 100%.
        while (int(zap.spider.status(scanid)) < 100):
            print '\tSpider progress %: ' + zap.spider.status(scanid)
            time.sleep(2)
        print 'Spider completed for route ' + route + '...OK'
        # Give the passive scanner a chance to finish
        time.sleep(5)
    print 'Spider completed for all routes...OK'


def active_scan_target():
    """Performs Active Scan on Target in ZAP."""
    # Alert user.
    print '\nStarting Active Scanner...\n'
    # Scan each route.
    for route in module_routes:
        # Alert user.
        print 'Scanning target %s' % target + route
        # Start scanning in ZAP.
        # Params. (url, contextId, userId, recurse, scanPolicyName, method, postData)
        scanid = zap.ascan.scan_as_user(target + route, contextid, userid, True)
        # Print out progress of Scan until it's at 100%.
        while (int(zap.ascan.status(scanid)) < 100):
            print 'Scan progress %: ' + zap.ascan.status(scanid)
            time.sleep(5)
        print 'Scan completed for route ' + route + '...OK'
        # Give scanner a chance to finish.
        time.sleep(2)
    print 'Scan completed for all routes...OK'


def export_results():
    # Report the results
    print 'Hosts: ' + ', '.join(zap.core.hosts)
    print 'Alerts: '
    pprint (zap.core.alerts())


def main():
    attempt_banner_display()
    get_routing_paths()
    setup_zap()
    spider_target()
    if options.active:
        active_scan_target()
    #export_results()
    print 'Done.'


""" PROCESS """


if __name__ == "__main__":
    main()