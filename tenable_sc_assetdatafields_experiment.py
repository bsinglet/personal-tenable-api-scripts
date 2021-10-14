#!/bin/python
__author__ = 'Benjamin M. Singleton'
__date__ = '14 Oct 2021'
__version__ = '0.0.2'

import time
import requests
import json
import urllib3
from urllib3.exceptions import InsecureRequestWarning

accessKey = ''
secretKey = ''
credentials = 'accesskey=' + accessKey + ';secretkey=' + secretKey
tenable_sc_host = "x.x.x.x"


def main():
    url = f'https://{tenable_sc_host}/rest/asset'

    # set up the headers and payload for a credentialed request
    request_payload = {"tags": "",
                       "name": "Assets with custom fields",
                       "description":"An asset group with strange fields",
                       "context": "",
                       "status": -1,
                       "createdTime": 0,
                       "modifiedTime": 0,
                       "groups": [],
                       "type": "static",
                       "definedIPs": "192.168.8.161",
                       # this is where you set your assetDataFields. Each custom field has to
                       # be a dict with the keys "fieldName" and "fieldValue"
                       # see /opt/sc/src/lib/AssetLib.php, line 5447
                       "assetDataFields": [{"fieldName": "my_custom_field", "fieldValue": "my_custom_value"},
                                           {"fieldName": "my_secrets", "fieldValue": "I have no secrets"}]}
    headers = {'accept': '*/*', 'content-type': 'application/json', 'x-apikey': credentials}

    # disable all SSL warnings in this script
    urllib3.disable_warnings(category=InsecureRequestWarning)

    # create the new asset list
    r = requests.post(url=url, headers=headers, json=request_payload, verify=False)
    d = json.loads(r.text)
    print(d)
    new_asset_id = d['response']['id']

    # wait 10 seconds so SC can finish calculating the IPs for the new asset
    # otherwise, our GET request on the asset will error out
    time.sleep(10)

    # we need to specify what fields we want back from the asset. I just took the
    # default list and appended "assetDataFields"
    fields = "fields=name%2Ctype%2Ctemplate%2CsourceType%2CviewableIPs%2CipCount%2Ctags%2Cdescription%2CcreatedTime%2CmodifiedTime%2CexcludeManagedIPs%2Cowner%2CownerGroup%2Cgroups%2CcanUse%2CcanManage%2CtypeFields%2CioSyncStatus%2CioFirstSyncTime%2CioLastSyncSuccess%2CioLastSyncFailure%2CioSyncErrorDetails%2CassetDataFields"
    new_url = url + '/' + new_asset_id + '?' + fields
    r = requests.get(url=new_url, headers=headers, verify=False)
    d = json.loads(r.text)
    print(d)

if __name__ == '__main__':
    main()
