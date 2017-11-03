# drop-fuzz

An automated fuzzer designed for use with Drupal sites.


## Usage

Before running this program, make sure ZAP is open.

    $ python drop-fuzz.py
        

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
