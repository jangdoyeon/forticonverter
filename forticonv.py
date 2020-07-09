# get firewall policy from conf-file to excel

__author__ = "dyjang"

import re
import sys
import csv
from collections import defaultdict


_FNAME = sys.argv[1]


# get fw policy
def get_policy(_FNAME):
    policy_dict = defaultdict(dict)
    ops = []  # set [op] value LIST
    policies = []  # policies LIST
    # config firewall policy > policies LIST
    with open(_FNAME, "r", encoding='UTF8') as f:
        in_policy = False
        for line in f:
            line = line.strip()
            if in_policy and line != "next":
                if line == "end":
                    break
                policies.append(line)
            else:
                if line == "config firewall policy":
                    in_policy = True

    # set [op] > set(ops) : Deduplication
    for ln in policies:
        if re.match('set\s(\w+)\s', ln):
            op_name = re.match('set\s(\w+)\s', ln).group(1)
            ops.append(op_name)
    ops = set(ops)
    print(ops)

    if policies:
        for idx, statement in enumerate(policies):
            print(statement)
            # sum comments including '\n'
            if not re.match('(edit|set|next)', statement):
                sum_text = policy_dict[last_valid_policy_id][last_valid_policy_param] + \
                    ", " + statement
                policy_dict[last_valid_policy_id][last_valid_policy_param] = sum_text
                continue

            op, param, *val = statement.split()
            if op == "edit":
                policy_id = str(param)
            if op == "set" and param in ops:
                policy_dict[policy_id][param] = ' '.join(val)
            last_valid_policy_id = policy_id
            last_valid_policy_param = param

    return policy_dict, ops

# convert policy to csv


def set_csv(pol_dic, ops):
    # define fieldnames
    # ops = ['edit','uuid', 'srcintf','srcaddr','dstintf','dstaddr','service','action','schedule','comments','logtraffic']
    with open('{0}.csv'.format(_FNAME), 'w', newline='') as f:
        ops = list(ops)
        ops.append('edit')
        w = csv.DictWriter(f, fieldnames=ops)
        w.writeheader()
        for edit_num in pol_dic.keys():
            pol_dic[edit_num]['edit'] = edit_num
            w.writerow(pol_dic[edit_num])


if __name__ == '__main__':
    pol_dic, ops = get_policy(_FNAME)
    set_csv(pol_dic, ops)
