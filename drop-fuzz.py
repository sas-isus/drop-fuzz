#!/usr/bin/env python

"""
drop-fuzz.py: Generates a report containing the results of running a fuzzer
              on a specified Drupal module.
Usage:
        $ python drop-fuzz.py -t www.mydrupalsite.com
        $ python drop-fuzz.py -t 127.0.0.1/drupal/
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
(options, args) = parser.parse_args()


target = options.target
if not target:
    target = 'http://127.0.0.1'

# Get an API key by opening ZAP, going to Tools -> Options, selecting "API", and copying the key on the right.
apikey = options.apikey
if not apikey:
    apikey = 'blahblahblah'


# By default ZAP API client will connect to port 8080
zap = ZAPv2(apikey=apikey)
# Use the line below if ZAP is not listening on port 8080, for example, if listening on port 8090
# zap = ZAPv2(apikey=apikey, proxies={'http': 'http://127.0.0.1:8090', 'https': 'http://127.0.0.1:8090'})


""" FUNCTIONS """


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
    scanid = zap.spider.scan(target)
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
    link_zap_to_target()
    spider_target()
    active_scan_target()
    export_results()


""" PROCESS """

if __name__ == "__main__":
    main()
