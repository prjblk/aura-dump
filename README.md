# Salesforce Aura Auditing Tool
This tool helps security teams and testers audit Salesforce environments for misconfigurations, excessive permissions, and common vulnerabilities like SOQL injection.

It's adapted from previous work here:
https://github.com/moniik/poc_salesforce_lightning

Modifications include:
* Minor refactoring
* Support for authentication
* Support for proxying
* Splitting out extraction of custom objects
* Support for page size behaviour when dumping all Apex Classes

# Usage
```
└─$ python3 aura_dump.py
usage: aura_dump.py [-h] -u URL -A AURA_CONTEXT -T TOKEN [-o [OBJECTS ...]] [-l] [-r RECORD_ID] [-d]
                    [--object-type {default,custom,both}] [-f] --cookie COOKIE [--proxy PROXY] [--apex]
                    [--output-dir OUTPUT_DIR]
aura_dump.py: error: the following arguments are required: -u/--url, -A/--aura-context, -T/--token, --cookie

└─$ python3 aura_dump.py -h
usage: aura_dump.py [-h] -u URL -A AURA_CONTEXT -T TOKEN [-o [OBJECTS ...]] [-l] [-r RECORD_ID] [-d]
                    [--object-type {default,custom,both}] [-f] --cookie COOKIE [--proxy PROXY] [--apex]
                    [--output-dir OUTPUT_DIR]

Exploit Salesforce via a user-supplied Aura endpoint, using a required aura_context and token.

options:
  -h, --help            show this help message and exit
  -u, --url URL         Set the *full* Aura endpoint URL, e.g. https://example.force.com/sfsites/aura
  -A, --aura-context AURA_CONTEXT
                        The full JSON/string for the aura.context field (no encoding).
  -T, --token TOKEN     The aura.token value (no encoding).
  -o, --objects [OBJECTS ...]
                        Specify object name(s) to dump. Default: ['User']. Other interesting objects: Case, Account,
                        User, Contact, Document, ContentDocument, ContentVersion, ContentBody, CaseComment, Note,
                        Employee, Attachment, EmailMessage, CaseExternalDocument, Lead, Name, EmailTemplate,
                        EmailMessageRelation
  -l, --listobj         Pull and print the object list from the given endpoint.
  -r, --record-id RECORD_ID
                        If specified, dumps the given recordId from the Aura endpoint.
  -d, --dump-objects    Dump objects accessible to current user (small subset of pages) and save to file.
  --object-type {default,custom,both}
                        When using -d, specify which type of objects to dump: default, custom, or both (default: both)
  -f, --full            If set with -d, attempts to dump *all pages* of objects.
  --cookie COOKIE       Specify a Cookie header for authentication (sid=).
  --proxy PROXY         Specify a proxy server, e.g. http://127.0.0.1:8080
  --apex                Dump all ApexClass entries.
  --output-dir OUTPUT_DIR
                        The directory to output the results
```

# Examples
Full usage guide at: https://projectblack.io/blog/salesforce-penetration-testing-fundamentals/

```
# Dump 1 page of all custom objects
python3 aura_dump.py  -u https://blah.com/aura --cookie 'sid=COOKIE' -A 'AURACONTEXTCOPIEDSTRAIGHTFROMBURP' -T 'AURATOKENSTRAIGHTFROMBURP' -d --object-type custom

# Dump 1 page of all objects including standard ones
python3 aura_dump.py  -u https://blah.com/aura --cookie 'sid=COOKIE' -A 'AURACONTEXTCOPIEDSTRAIGHTFROMBURP' -T 'AURATOKENSTRAIGHTFROMBURP' -d
```
