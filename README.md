# drop-fuzz

An automated fuzzer designed for use with Drupal sites.


## Usage

Before running this program, make sure ZAP is open.

    $ python drop-fuzz.py
        

**Arguments:** (not currently implemented)

    -h, --help                                                   Show a help message and exit.

    -t TARGET_SITE, --target TARGET_SITE                         Target site containing Drupal module.

    -a API_KEY, -k API_KEY, --api API_KEY, --key API_KEY         API Key obtained through ZAP.

    -m MODULE_PATH, --module MODULE_PATH, --path MODULE_PATH     Path to module.

    -u USER, --username USER, --user USER                        Drupal login username.

    -p PASSWORD, --password PASSWORD, --pass PASSWORD            Drupal login password.

    -n, --no-spider                                              Do not run a spider on the module's routes.

    -f, --force                                                  Force default values for prompts.

Arguments are not required, as _drop-fuzz_ will prompt the user for any missing
info, aside from -n (No Spidering) and -f (forcing the default values).


## Examples

By default, _drop-fuzz_ will prompt the user for any information it needs.

    $ python drop-fuzz.py

Though, you can always specify this information to _drop-fuzz_ via arguments.

    $ python drop-fuzz.py -t 127.0.0.1/drupal/ -a APIKEY -u brian -p password123

    $ python drop-fuzz.py -f


## Using `config.yml`

If you don't want to enter your ZAP API key, Drupal username, and Drupal
password every time you run this program, modify `config.yml` to support your
needs.


## Obtaining a ZAP API Key

Get an API key by opening ZAP, going to Tools -> Options, selecting "API",
and copying the key on the right.


## Dependencies

1. [OWASP ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)
2. [Python 2.7](https://www.python.org/downloads/)
3. All the Pip packages in `requirements.txt`

#### Installing from `requirements.txt`

Run the following command:
```
$ pip install -r requirements.txt
```


## Features Coming Soon

- [x] On-load Banner.
    - I like programs that are aesthetically pleasing, don't you?
- [x] Colored text.
    - It makes it easier for the user to digest what the program's doing.
- [ ] Custom Active Scan policies.
    - This means you'll be able to select the payloads used when fuzzing.
    - This also means you'll be able to select what else to scan for (not just fuzzing).
- [x] Configuration file.
    - No more having to type all the same arguments every single time you run this.
- [x] Exported results file.
    - Upon completion, save a full-blown report.
- [x] Automatically find the module's source code so you don't have to type in a local path every time.
    - You're already pointing _drop-fuzz_ to your site, which should have the module on it,
    so why not just grab the source code from the site?
- [ ] Scan an entire site.
    - Already have an existing site with plenty of modules enabled? Wouldn't it
    take forever to run Drop-Fuzz on _every single **one**_? Let's add a feature
    that lets the user specify nothing but a site to scan.
