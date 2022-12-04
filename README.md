# personal-tenable-api-scripts
Some of the API scripts I've written for Nessus, Tenable.SC, and Tenable.io.

These tools are not an officially-supported Tenable project.
Use of this tool is subject to the terms and conditions identified below, and is not subject to any license agreement you may have with Tenable.

## Audit Files
- [cli_audit_parser.py](https://github.com/bsinglet/personal-tenable-api-scripts/blob/main/cli_audit_parser.py) - A script for parsing Nessus' CLI compliance scans.

## Nessus
- [nessus_debug_logs.py](https://github.com/bsinglet/personal-tenable-api-scripts/blob/main/nessus_debug_logs.py) - Pulls the debugging logs from a scan in Nessus.
- [nessus_wipe_and_run.py](https://github.com/bsinglet/personal-tenable-api-scripts/blob/main/nessus_wipe_and_run.py) - Wipes the scan history of a given scan in Nessus and starts a fresh run of it. USE AT YOUR OWN RISK.

## Tenable.SC
- [tenable_sc_assetdatafields_experiment.py](https://github.com/bsinglet/personal-tenable-api-scripts/blob/main/tenable_sc_assetdatafields_experiment.py) - Experimental script that assigns custom data fields to an Asset list and demonstrates its success by then retrieving that information.
- [tenable_sc_delete_old_scan_results.py](https://github.com/bsinglet/personal-tenable-api-scripts/blob/main/tenable_sc_delete_old_scan_results.py) - Deletes ALL scan results in Tenable.SC. USE AT YOUR OWN RISK.
- [tenable_sc_get_last_observed.py](https://github.com/bsinglet/personal-tenable-api-scripts/blob/main/tenable_sc_get_last_observed.py) - A better way to see if a vulnerability has been resolved. Given a particular IP address and Plugin ID, identifies the most recent scan to observe that combination and reruns that scan. Can be taxing if the original scan had too many targets. Improvement idea: Change the rerun to a diagnostic scan, which would ensure that only the single IP is rescanned.
- [tenable_sc_run_diagnostic.py](https://github.com/bsinglet/personal-tenable-api-scripts/blob/main/tenable_sc_run_diagnostic.py) - Run a diagnostic scan. Nothing special about this, but sometimes you need to automate this process for troubleshooting.
- [tenable_sc_upload_scan.py](https://github.com/bsinglet/personal-tenable-api-scripts/blob/main/tenable_sc_upload_scan.py) - Imports scan results into Tenable.SC. Again, this is perfectly doable in the UI, but it can be useful to automate the process.

## Tenable.io
- [get_all_was_files.py](https://github.com/bsinglet/personal-tenable-api-scripts/blob/main/get_all_was_files) - Pulls the plugin outputs as well as the attached files and images for a given Tenable.io WAS scan.
- [tenable_io_scan_updater.py](https://github.com/bsinglet/personal-tenable-api-scripts/blob/main/tenable_io_scan_updater) - Reconfigures all existing scans in Tenable.io to switch the selected scanner to autorouted and change the Target Network UUID.
