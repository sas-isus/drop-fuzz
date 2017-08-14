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
# Get an API key by opening ZAP, going to Tools -> Options, selecting "API", and copying the key on the right.
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
                         '&loginRequestData=name%3D{%25username%25}%26pass%3D{%25password%25}%26form_id%3Duser_login_form%26op%3DLog%2Bin'
# By default ZAP API client will connect to port 8080
zap = ZAPv2(apikey=apikey)
# If listening on port 8090, use:
# zap = ZAPv2(apikey=apikey, proxies={'http': 'http://127.0.0.1:8090', 'https': 'http://127.0.0.1:8090'})
# Should we ask the user for the port? Or just assume 8080? Maybe add an arg for it.


""" FUNCTIONS """


def setup_zap():
    global contextid, userid
    contextid = zap.context.new_context(context)

    init_zap_context()
    init_zap_authentication()

    userid = zap.users.new_user(contextid, 'user1')

    init_zap_user()


def init_zap_context():
    print 'Including target in context...' + zap.context.include_in_context(context, target + '.*')
    print 'Checking context...' + str(zap.context.context(context)) + ' OK'


def init_zap_authentication():
    print 'Setting authentication method...' + zap.authentication.set_authentication_method(contextid, authmethodname, authmethodconfigparams)
    print 'Setting logged in indicator...' + zap.authentication.set_logged_in_indicator(contextid, '\Q<a href="/drupal/user/logout" data-drupal-link-system-path="user/logout">Log out</a>\E')


def init_zap_user():
    print 'Setting authentication credentials...' + zap.users.set_authentication_credentials(contextid, userid, 'username=%s&password=%s' % (login_name, login_pass))
    print 'Enabling user for current session...' + zap.users.set_user_enabled(contextid, userid, True)


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
    print 'Spidering target %s' % target
    # scanid = zap.spider.scan(target)
    scanid = zap.spider.scan_as_user(contextid, userid, target)
    # Give the Spider a chance to start
    time.sleep(2)
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
    #link_zap_to_target() # probably dont need this anymore...
    spider_target()
    #active_scan_target()
    #export_results()
    print 'Done.'


""" PROCESS """


if __name__ == "__main__":
    main()
