#!/usr/bin/python
__author__ = 'Benjamin M. Singleton'
__date__ = '31 August 2021'
__version__ = '0.1.0'

import time
from tenable.sc import TenableSC

SC_HOST_IP = '192.168.50.201'  # the IP address of the Tenable.SC server
sc_accessKey = ''
sc_secretKey = ''

active_scan_id = '1'
target_ip = 'x.x.x.x'
diagnostic_password = 'Tenable123'
SCAN_MAX_WAIT_SECONDS = 3600
SCAN_REFRESH_DELAY_SECONDS = 30


def is_scan_completed(sc, scan_result_id):
    scan_result = sc.scan_instances.details(id=int(scan_result_id))
    return scan_result['status'] == 'Completed'


def main():
    # create an instance of the API and login
    sc = TenableSC(SC_HOST_IP)
    sc.login(access_key=sc_accessKey, secret_key=sc_secretKey)

    # run the diagnostic scan
    scan_result_id = sc.scans.launch(id=active_scan_id, diagnostic_target=target_ip,
                                     diagnostic_password=diagnostic_password)['scanResult']['id']
    print(f"Launched diagnostic scan run of Active Scan {active_scan_id}, with Scan Result ID {scan_result_id}.")

    # wait until the scan is finished
    wait_time_seconds = 0
    while wait_time_seconds < SCAN_MAX_WAIT_SECONDS:
        if is_scan_completed(sc, scan_result_id):
            print(f"Scan finished running after waiting {wait_time_seconds} seconds.")
            break
        else:
            print(f"Waited {wait_time_seconds} seconds, scan is still running.")
            time.sleep(SCAN_REFRESH_DELAY_SECONDS)
            wait_time_seconds += SCAN_REFRESH_DELAY_SECONDS

    if wait_time_seconds > SCAN_MAX_WAIT_SECONDS:
        print("ERROR: Script timed out waiting for the scan to complete.")
        exit(-1)


if __name__ == '__main__':
    main()
