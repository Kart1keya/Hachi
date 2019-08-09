def table_creation(sig_json, mitre_json):
    mitre_table_json = [
        {"Initial Access": {}},
        {"Execution": {}},
        {"Persistence": {}},
        {"Privilege Escalation": {}},
        {"Defense Evasion": {}},
        {"Credential Access": {}},
        {"Discovery": {}},
        {"Lateral Movement": {}},
        {"Collection": {}},
        {"Command and Control": {}},
        {"Exfiltration": {}},
        {"Impact": {}}
    ]

    keys = list()
    total_table_entry = 0
    for matched_tid in sig_json:
        for tactic in mitre_json:
            if matched_tid in mitre_json[tactic]:
                for i in range(0, len(mitre_table_json)):
                    if tactic in mitre_table_json[i]:
                        mitre_table_json[i][tactic][matched_tid] = mitre_json[tactic][matched_tid]
                        total_table_entry = total_table_entry + 1

    tid_len = []
    for i in range(0, len(mitre_table_json)):
        for tactic in mitre_table_json[i]:
            tid_len.append(len(mitre_table_json[i][tactic]))

    table_code = []
    for i in range(0, len(mitre_table_json)):
        for key in mitre_table_json[i]:
            keys.append(key)
    table_code.append(keys)
    added_count = 0
    for i in range(0, len(sig_json.keys())):
        row = []
        for j in range(0, len(mitre_table_json)):
            if tid_len[j] != 0:
                for key in mitre_table_json[j]:
                    counter = 0
                    for tid in mitre_table_json[j][key]:
                        if i == counter:
                            row.append({"name": mitre_table_json[j][key][tid]["name"], "id": tid})
                            added_count = added_count + 1
                            tid_len[j] = tid_len[j] - 1
                            break
                        else:
                            counter = counter + 1
            else:
                row.append("")
        table_code.append(row)
        if added_count == total_table_entry:
            break
    return table_code
