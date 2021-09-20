#!/usr/bin/python
__author__ = 'Benjamin M. Singleton'
__date__ = '19 August 2021'
__version__ = '0.1.2'

import logging
import time
from tenable.sc import TenableSC

# basic configuration info for our setup
SC_HOST_IP = 'x.x.x.x'  # the IP address of the Tenable.SC server
accessKey = ''
secretKey = ''
unwanted_scan_names = ["Host Discovery", "Example Scan Name"]
RETAIN_SCANS_FOR_DAYS = 2
TIME_TO_WAIT_BEFORE_VERIFICATION = 60  # seconds
SECONDS_PER_DAY = 60 * 60 * 24

# set up logging. It's a good idea to keep a record of which scan results
# you've deleted: their names, IDs, and ages.
logging.basicConfig(filename='example.log',
                    level=logging.DEBUG,
                    # date_format="%Y-%m-%d %H:%M:%S",
                    format="%(asctime)-15s [%(levelname)s]: %(message)s",
                    )

# create an instance of the API and login
sc = TenableSC(SC_HOST_IP)
sc.login(access_key=accessKey, secret_key=secretKey)

# we're going to track which scans we try to delete so we can verify later
deleted_ids = list()

# check scan results for all time (start_time=1), and include the non-default
# importFinish field so we can determine when the scan finished
for each_result in sc.scan_instances.list(start_time=1, fields=["name", "id", "description", "status", "importFinish"])['usable']:
    if each_result['name'] in unwanted_scan_names:
        # calculate how many days ago this scan finished
        time_difference = int((time.time() - float(each_result['importFinish'])) / SECONDS_PER_DAY)
        if time_difference > RETAIN_SCANS_FOR_DAYS:
            logging.info(f"Deleting scan result {each_result['name']} (id {each_result['id']}) because it's {time_difference} days old")
            deleted_ids.append(each_result['id'])
            sc.scan_instances.delete(each_result['id'])

# give Tenable.SC some time to process the deletions
time.sleep(TIME_TO_WAIT_BEFORE_VERIFICATION)

# now, verify that all of the scans were actually deleted
new_scan_result_list = sc.scan_instances.list(start_time=1, fields=["name", "id", "description", "status", "importFinish"])['usable']
for each_id in deleted_ids:
    for each_result in new_scan_result_list:
        if each_id == each_result['id']:
            logging.warning(f"Uh-oh, ID {each_id} is still showing in the scan results.")
            break
    else:
        logging.info(f"ID {each_id} deleted successfully.")
