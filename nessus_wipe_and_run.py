#!/usr/bin/python
__author__ = 'Benjamin M. Singleton'
__date__ = '26 July 2021'
__version__ = '0.1.0'

"""
This is a script for keeping Nessus streamlined. It deletes all previous 
results from a given scan and then launches that scan again. 
Use at your own risk.
"""

import requests
import json
import urllib3
from urllib3.exceptions import InsecureRequestWarning

# all the configuration values go here:
scan_id = '1'  # you can find this number in the URL in Nessus when viewing the scan history.
nessus_ip_or_hostname = 'x.x.x.x'
accessKey = ''
secretKey = ''
credentials = 'accessKey=' + accessKey + ';secretKey=' + secretKey


def main():
    # some useful variables
    base_url = 'https://' + nessus_ip_or_hostname + ':8834/scans/'
    url = base_url + scan_id + '?limit=2500&includeHostDetailsForHostDiscovery=true'
    headers = {'accept': '*/*', 'content-type': 'application/json', 'X-ApiKeys': credentials}

    # disable all SSL warnings in this script
    urllib3.disable_warnings(category=InsecureRequestWarning)

    # get the scan information, which includes the list of history IDs
    try:
        response = requests.get(url=url, headers=headers, verify=False)
        response = json.loads(response.text)
    except:
        print(f"Failed to get the information of scan ID {scan_id}. Are you sure this scan exists?")
        return

    # use the history IDs to find and delete all the old runs of this scan
    for each_run in response['history']:
        history_id = each_run['history_id']
        url = base_url + scan_id + '/history/' + str(history_id)
        print(f"Deleting history ID {history_id}.")
        requests.delete(url=url, headers=headers, verify=False)

    # finally, launch the scan again
    url = base_url + scan_id + '/launch'
    try:
        response = requests.post(url=url, headers=headers, verify=False)
        response = json.loads(response.text)
        print(f"New scan UUID is {response['scan_uuid']}")
    except:
        print(f"Failed to launch new scan, is it already running?")


if __name__ == '__main__':
    main()
