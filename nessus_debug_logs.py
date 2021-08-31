#!/bin/python
__author__ = 'Benjamin M. Singleton'
__date__ = '30 Aug 2021'
__version__ = '0.1.2'

import requests
import json
import urllib3
from urllib3.exceptions import InsecureRequestWarning

accessKey = ''
secretKey = ''
credentials = 'accessKey=' + accessKey + ';secretKey=' + secretKey


def download_all_attachments(base_url: str, credentials: str, scan_id: str, attachments_list: list[dict]) -> None:
    """
    Downloads debugging log report attachments from Nessus (Professional, Manager, or linked to Tenable.SC/Tenable.io)
    :param base_url: The URl in the form of `https://nessus-hostname:8834/scans/`
    :param credentials: The string `accessKey=1234;secretKey=5678` used in request headers.
    :param scan_id: The number of the scan result in Nessus, encoded as a string.
    :param attachments_list: A list of dicts, each dict contains the keys "id", "name", and "key".
    :return: n/a
    """
    url = base_url + scan_id + '/attachments/'

    headers = {
        "Accept": "text/plain",
        "X-ApiKeys": credentials
    }

    for each_attachment in attachments_list:
        # download the raw response for each attachment
        try:
            response = requests.get(url + str(each_attachment['id']) + '?key=' + each_attachment['key'], stream=True, verify=False)
            with open('temp/' + each_attachment['name'], 'wb') as out_file:
                for chunk in response:
                    out_file.write(chunk)
        except InsecureRequestWarning as i:
            pass


def main():
    # set URL and scan_id
    base_url = 'https://x.x.x.x:8834/scans/'
    scan_id = '11'
    list_url = base_url + scan_id + '/hosts/2/plugins/84239'

    # set up the headers and payload for a credentialed request
    request_payload = {"format": "csv"}
    headers = {'accept': '*/*', 'content-type': 'application/json', 'X-ApiKeys': credentials}

    # disable all SSL warnings in this script
    urllib3.disable_warnings(category=InsecureRequestWarning)

    # get the list of debugging log report attachments
    r = requests.get(url=list_url, params='limit=2500', headers=headers, json=request_payload, verify=False)
    d = json.loads(r.text)
    attachments_list = d['outputs'][0]['ports']['0 / tcp / '][0]['attachments']

    # download each of the attachments to ./temp/
    download_all_attachments(base_url, credentials, scan_id, attachments_list)


if __name__ == '__main__':
    main()
