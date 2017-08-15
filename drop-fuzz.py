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


""" GLOBALS """


# Get & Set Options / args
parser = OptionParser(usage="usage: %prog [options]", version="%prog 1.0")
parser.add_option("-t", "--target", dest="target", \
                  help="Target site containing Drupal module", metavar='<TARGET>')
parser.add_option("-a", "-k", "--api", "--key", dest="apikey", \
                  help="API Key obtained through ZAP", metavar='<APIKEY>')
parser.add_option("-u", "--username", "--user", dest="login_name", \
                  help="Drupal login username", metavar='<USERNAME>')
parser.add_option("-p", "--password", "--pass", dest="login_pass", \
                  help="Drupal login password", metavar='<PASSWORD>')
parser.add_option("-f", "--force", dest="force", \
                  help="Force default values for prompts", metavar='<FORCE>')
(options, args) = parser.parse_args()


# Ensure target has been set properly.
target = options.target
if not target:
    if not options.force:
        ans = raw_input("Use http://127.0.0.1/drupal/ as target? [Y|N]: ")
        if ans.lower() == 'n' or ans.lower() == 'no':
            target = raw_input("Enter a URL to target: ")
        else:
            target = 'http://127.0.0.1/drupal/'
    else:
        target = 'http://127.0.0.1/drupal/'

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
authmethodconfigparams = 'loginUrl=' + target + 'user/login/' + \
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
    # Print out Context to console so user can see that it actually exists.
    # Maybe make this verbose-only?
    print 'Checking context...' + \
          str(zap.context.context(context)) + ' OK'


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


def link_zap_to_target():
    print 'Accessing target %s' % target
    # Start a unique session...
    zap.urlopen(target)
    # Give the sites tree a chance to get updated
    time.sleep(2)


def spider_target():
    """Spiders Target as User in ZAP."""
    # Alert user.
    print 'Spidering target %s' % target
    # Start scanning in ZAP.
    scanid = zap.spider.scan_as_user(contextid, userid, target)
    # Give the Spider a chance to start.
    time.sleep(2)
    # Print out progress of Spider until it's at 100%.
    while (int(zap.spider.status(scanid)) < 100):
        print 'Spider progress %: ' + zap.spider.status(scanid)
        time.sleep(2)
    print 'Spider completed'
    # Give the passive scanner a chance to finish
    time.sleep(5)


def active_scan_target():
    print 'Scanning target %s' % target
    scanid = zap.ascan.scan(target)
    while (int(zap.ascan.status(scanid)) < 100):
        print 'Scan progress %: ' + zap.ascan.status(scanid)
        time.sleep(5)
    print 'Scan completed'


def export_results():
    # Report the results
    print 'Hosts: ' + ', '.join(zap.core.hosts)
    print 'Alerts: '
    pprint (zap.core.alerts())


def main():
    setup_zap()
    #link_zap_to_target() # probably don't need this anymore...
    spider_target()
    #active_scan_target()
    #export_results()
    print 'Done.'


""" PROCESS """


if __name__ == "__main__":
    main()
