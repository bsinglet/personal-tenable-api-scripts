#!/usr/bin/python
__author__ = 'Benjamin M. Singleton'
__date__ = '04 December 2022'
__version__ = '0.1.0'

"""
This is a script that parses the output of Nessus' CLI compliance scanning
feature. It transforms each check result into a Python dict and then outputs
them to a CSV file. SSHing into a Nessus scanner provides a method to run an
audit file directly without initiating a full scan through the UI 
(see: https://community.tenable.com/s/article/CLI-Compliance-Scanning ).
"""

import re
import csv

# this is the regex used at the start of each new check in the output. It
# contains the check name ("description") in double-quotes, followed by the
# result (PASS/FAIL/WARNING/ERROR) in square brackets.
check_name_regex = r'^\s*"([^\\"]+)"\s+:\s+\[(\w+)\]\s*$'
solution_header_regex = r'^Solution:\s*$'
policy_header_regex = r'^Policy Value:\s*$'
actual_header_regex = r'^Actual Value:\s*$'

def main():
    with open('out.txt', 'r') as my_file:
        raw_text = my_file.read()
        checks = list()
    last_header_pos = -1

    # split the raw output into a list of checks.
    for match in re.finditer(check_name_regex, raw_text, re.MULTILINE):
        # skip the first match, because we're copying from the beginning of the
        # previous match to the beginning of the current one.
        if last_header_pos == -1:
            last_header_pos = 0
            continue
        checks.append(raw_text[last_header_pos:match.start()-1])
        last_header_pos = match.start()

    # now, actually parse the checks into various fields.
    for check_num, each_check in enumerate(checks):
        checks[check_num] = dict()
        header_match = re.search(check_name_regex, each_check, re.MULTILINE)
        checks[check_num]['name'] = header_match.group(1)
        checks[check_num]['result'] = header_match.group(2)
        solution_match = re.search(solution_header_regex, each_check, re.MULTILINE)
        policy_match = re.search(policy_header_regex, each_check, re.MULTILINE)
        actual_match = re.search(actual_header_regex, each_check, re.MULTILINE)
        # if a check has a "Solution:" line, then the text before it is the
        # info field and the check after it is the solution field
        if solution_match:
            checks[check_num]['info'] = each_check[header_match.end()+1:solution_match.start()-1]
            # if this is a WARNING check, then there's no policy value or
            # actual value, so just grab all the remaining text
            if policy_match:
                checks[check_num]['solution'] = each_check[solution_match.end()+1:policy_match.start()-1]
            else:
                checks[check_num]['solution'] = each_check[solution_match.end()+1:]
        else:
            if policy_match:
                checks[check_num]['info'] = each_check[header_match.end()+1:policy_match.start()-1]
            else:
                checks[check_num]['info'] = each_check[header_match.end()+1:]
        # if this check actually checked something, then get the original
        # command and its output (the policy value and the actual value)
        if policy_match and actual_match:
            checks[check_num]['policy_value'] = each_check[policy_match.end()+1:actual_match.start()-1]
            checks[check_num]['actual_value'] = each_check[actual_match.end()+1:]
        print(f"Added check {checks[check_num]}")

    # create a CSV file showing the audit file results.
    with open('out.csv', 'w') as csvfile:
        csvwriter = csv.DictWriter(csvfile, fieldnames=['name', 'result', 'info', 'solution', 'policy_value', 'actual_value'])
        csvwriter.writeheader()
        for each_check in checks:
            csvwriter.writerow(each_check)


if __name__ == '__main__':
    main()
