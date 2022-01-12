#!/usr/bin/python
__author__ = 'Benjamin M. Singleton'
__date__ = '11 January 2022'
__version__ = '0.1.0'

import time
from tenable.sc import TenableSC
import requests
import json

SC_HOST_IP = '192.168.8.141'  # the IP address of the Tenable.SC server
access_key = ''
secret_key = ''
TARGET_REPOSITORY_ID = 1


def upload_file(target_filename):
    with open(target_filename, 'r') as myfile:
        sc = TenableSC(SC_HOST_IP)
        sc.login(access_key=access_key, secret_key=secret_key)
        file_uploaded = sc.files.upload(myfile)
        print(file_uploaded)
    return file_uploaded


def import_scan(file_uploaded):
    headers = {
        "Accept": "application/json",
        "Accept-Encoding": "gzip, deflate, br",
        "X-ApiKey": f"accessKey={access_key};secretKey={secret_key}"
    }
    request_payload = {"filename": file_uploaded,
                       "repository": {
                           "id": TARGET_REPOSITORY_ID
                       }}
    r = requests.post(url=f'https://{SC_HOST_IP}/rest/scanResult/import', headers=headers, json=request_payload,
                      verify=False)


def main():
    # first API call is to upload the actual file
    target_filename = 'scan_result.nessus'
    file_uploaded = upload_file(target_filename)

    # tell Tenable.SC to import the file we just uploaded
    import_scan(file_uploaded)


if __name__ == '__main__':
    main()
