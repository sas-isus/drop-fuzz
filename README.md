# drop-fuzz

An automated fuzzer designed for use with Drupal sites.


## Usage

    $ python drop-fuzz.py -A -t 127.0.0.1/drupal/ -a APIKEY -u brian -p password123

**Arguments:**

    -h, --help                                                   Show a help message and exit.

    -t TARGET_SITE, --target TARGET_SITE                         Target site containing Drupal module.

    -a API_KEY, -k API_KEY, --api API_KEY, --key API_KEY         API Key obtained through ZAP.

    -m MODULE_PATH, --module MODULE_PATH, --path MODULE_PATH     Path to module.

    -u USER, --username USER, --user USER                        Drupal login username.

    -p PASSWORD, --password PASSWORD, --pass PASSWORD            Drupal login password.

    -A, --active                                                 Perform an Active Scan.

    -f, --force                                                  Force default values for prompts.

Arguments are not required, as _drop-fuzz_ will prompt the user for any missing
info, aside from -A (Active Scanning) and -f (forcing the default values).


## Examples

By default, _drop-fuzz_ will prompt the user for any information it needs.

    $ python drop-fuzz.py

If you want _drop-fuzz_ to run without user input, you can specify what's
necessary via arguments.

    $ python drop-fuzz.py -A -t 127.0.0.1/drupal/ -a APIKEY -u brian -p password123

    $ python drop-fuzz.py -f


## Obtaining a ZAP API Key

Get an API key by opening ZAP, going to Tools -> Options, selecting "API",
and copying the key on the right.
