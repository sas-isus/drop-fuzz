# drop-fuzz

An automated fuzzer designed for use with Drupal sites.


## Usage

Before running this program, make sure ZAP is open.

    $ python drop-fuzz.py -S -t 127.0.0.1/drupal/ -a APIKEY -u brian -p password123

**Arguments:**

    -h, --help                                                   Show a help message and exit.

    -t TARGET_SITE, --target TARGET_SITE                         Target site containing Drupal module.

    -a API_KEY, -k API_KEY, --api API_KEY, --key API_KEY         API Key obtained through ZAP.

    -m MODULE_PATH, --module MODULE_PATH, --path MODULE_PATH     Path to module.

    -u USER, --username USER, --user USER                        Drupal login username.

    -p PASSWORD, --password PASSWORD, --pass PASSWORD            Drupal login password.

    -S, --spider                                                 Run a spider on the module's routes.

    -f, --force                                                  Force default values for prompts.

Arguments are not required, as _drop-fuzz_ will prompt the user for any missing
info, aside from -S (Spidering) and -f (forcing the default values).


## Examples

By default, _drop-fuzz_ will prompt the user for any information it needs.

    $ python drop-fuzz.py

Though, you can always specify this information to _drop-fuzz_ via arguments.

    $ python drop-fuzz.py -S -t 127.0.0.1/drupal/ -a APIKEY -u brian -p password123

    $ python drop-fuzz.py -f


## Obtaining a ZAP API Key

Get an API key by opening ZAP, going to Tools -> Options, selecting "API",
and copying the key on the right.


## Features Coming Soon

- [x] On-load Banner.
    - I like programs that are aesthetically pleasing, don't you?
- [ ] Custom Active Scan policies.
    - This means you'll be able to select the payloads used when fuzzing.
    - This also means you'll be able to select what else to scan for (not just fuzzing).
- [ ] Configuration file.
    - No more having to type all the same arguments every single time you run this.
- [ ] Exported results file and auto-closing of ZAP.
    - Why leave ZAP open for hours once it's done scanning?
    - Upon completion, save a full-blown report and close ZAP (maybe save the session, too, just in case).
- [ ] Automatically find the module's source code so you don't have to type in a local path every time.
    - You're already pointing _drop-fuzz_ to your site, which should have the module on it,
    so why not just grab the source code from the site?
