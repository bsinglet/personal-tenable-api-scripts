#!/usr/bin/python
__author__ = 'Benjamin M. Singleton'
__date__ = '14 January 2022'
__version__ = '0.1.0'

import logging
import time
from tenable.sc import TenableSC
from zipfile import ZipFile

SC_HOST_IP = '192.168.50.12'  # the IP address of the Tenable.SC server
accessKey = ''
secretKey = ''

"""
    This script takes a given plugin ID and source_hostname/IP. It then uses the Tenable.SC
     API to find the last observed date for the vuln on that target, and identifies the
      exact scan result it's from, as well as information on the Active Scan, Scan Policy,
      and Audit File, if applicable.
"""

# create an instance of the API and login
sc = TenableSC(SC_HOST_IP)
sc.login(access_key=accessKey, secret_key=secretKey)

SCAN_TIME_THRESHOLD = 600  # the number of seconds before or after the timestamp to look for a Scan finish/import time

logging.basicConfig(filename='last_observed.log',
                    level=logging.DEBUG,
                    format="%(asctime)-15s [%(levelname)s]: %(message)s",
                    )
logging.getLogger('requests').setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)


def get_last_observed(sc, plugin_id: str, ip: str) -> str:
    filters = [("pluginID", "=", plugin_id),
               ("ip", "=", ip)]

    result = sc.analysis.vulns(filters=filters, tool="vulndetails", source="cumulative")
    for each in result:
        return each['lastSeen']


def list_scan_results_near_time(sc, timestamp: str) -> list:
    applicable_scans = list()
    start_time = str(int(timestamp) - int(SCAN_TIME_THRESHOLD))
    end_time = str(int(timestamp) + int(SCAN_TIME_THRESHOLD))
    results = sc.scan_instances.list(start_time=start_time, end_time=end_time)
    for each in results['manageable']:
        applicable_scans.append(each['id'])
    for each in results['usable']:
        applicable_scans.append(each['id'])
    return list(set(applicable_scans))


def scan_contains_result(sc, scan_instance_id: str, plugin_id: str, ip: str) -> bool:
    results = sc.analysis.scan(scan_id=scan_instance_id, tool="listvuln",
                      filters=[("pluginID", "=", plugin_id),
                        ("ip", "=", ip)])
    try:
        return any(True for _ in results)
    except Exception as ex:
        print(f'Failed to find the vulnerability in {scan_instance_id} plugin id {plugin_id} on IP {ip} because {ex}.')
        return False


def get_original_severity(sc, scan_instance_id: str, plugin_id: str, ip: str) -> str:
    """
    Exports the scan results for the given scan instance ID, and checks what
    severity was found for the given plugin for a particular host. This is the
    only way I know of to get the actual severity found when a risk recast rule
    is in place. For Active plugins, you can simply check the CVSSv2 Score, but
    Compliance plugins can have any severity from Info to High, depending on the
    findings, so that doesn't work for those.
    :param sc:
    :param scan_instance_id:
    :param plugin_id:
    :param ip:
    :return:
    """
    with open('temp.zip', 'wb') as temp_file:
        sc.scan_instances.export_scan(scan_instance_id, temp_file)
    with ZipFile('temp.zip', 'w') as myzip:
        myzip.write('temp.nessus')
    print("ERROR: This function is unfinished.")
    return ""


def get_scan_name_and_policy_name(sc, scan_instance_id: str):
    results = sc.scan_instances.details(id=scan_instance_id)
    return results['name'], results['details']


def get_active_scan(sc, scan_name, policy_name):
    my_id = -1
    my_scans = sc.scans.list()['usable']
    for each_scan in my_scans:
        if each_scan['name'] == scan_name:
            my_id = each_scan['id']
            break

    if my_id == -1:
        print(f"Failed to find an active scan matching name {scan_name}.")
        return None

    if sc.scans.details(id=my_id)['policy']['name'] == policy_name:
        print(f'Found active scan named {scan_name} with policy named {policy_name} under active scan ID {my_id}.')
        return my_id
    else:
        print(f"Found active scan with correct name {scan_name} under active scan ID {my_id}, "
              "but policy name {sc.scans.details(id=my_id)['policy']['name']} does not match expected {policy_name}.")
        return None


def run_active_scan(sc, target_scan_id):
    scan_result_id = sc.scans.launch(id=target_scan_id)['scanResult']['id']
    print(f'Launched new instance of Active Scan ID {target_scan_id} with scan result ID {scan_result_id}.')
    return scan_result_id


def main():
    plugin_id = '19506'
    ip = '192.168.8.161'

    timestamp = get_last_observed(sc, plugin_id, ip)

    scans = list_scan_results_near_time(sc, timestamp)
    # we could sort these as strings instead of ints, but that won't work if some IDs
    # have more digits than other (e.g., '89' > '791')
    scans = [int(x) for x in scans]
    scans.sort(reverse=True)
    scans = [str(x) for x in scans]

    for each_scan in scans:
        if scan_contains_result(sc=sc, scan_instance_id=each_scan, plugin_id=plugin_id, ip=ip):
            print(f"Scan Instance ID {each_scan} was the last to observe plugin {plugin_id} on host {ip}.")
            scan_name, policy_name = get_scan_name_and_policy_name(sc, scan_instance_id=each_scan)
            print(f"This is an instance of Scan name \"{scan_name}\", policy name \"{policy_name}\".")
            break
    else:
        print(f"Could not find a scan containing {plugin_id} on host {ip} within {str(SCAN_TIME_THRESHOLD)} seconds of {timestamp}.")
        exit(-1)

    target_scan_id = get_active_scan(sc, scan_name, policy_name)

    if target_scan_id is None:
        exit(-1)

    # launch the scan we found
    result_id = run_active_scan(sc, target_scan_id)

    # wait 5 minutes, then check on the status of the scan
    time.sleep(5 * 60)
    print(sc.scans.details(id=result_id))


if __name__ == '__main__':
    main()
