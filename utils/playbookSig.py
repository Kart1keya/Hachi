import json


def playbooksig(playbook_json, matched_sig_file, outputfile_campaign):
    with open(matched_sig_file) as fp:
        matched_json = json.load(fp)
        with open(playbook_json) as fs:
            playbook_sig = json.load(fs)
            max = 0
            matched_campaign_name = "Not Matched"
            max_campaign_per = 0
            for campaign in list(playbook_sig.keys()):
                matched_tid_count = 0
                for tid_name in playbook_sig[campaign]:
                    if tid_name in list(matched_json.keys()):
                        matched_tid_count = matched_tid_count + 1
                if matched_tid_count > max:
                    matched_campaign_name = campaign
                    max_campaign_per = matched_tid_count * 100 / len(playbook_sig[campaign])
                else:
                    if matched_tid_count == max:
                        macthed_wrt_campaign = max * 100 / len(playbook_sig[campaign])
                        if macthed_wrt_campaign > max_campaign_per:
                            max_campaign_per = macthed_wrt_campaign
                            matched_campaign_name = campaign
                max = matched_tid_count if matched_tid_count > max else max
            json_data = {"Matched campaign": "Not Matched"}
            if matched_campaign_name != "Not Matched":
                json_data["Matched campaign"] = matched_campaign_name
                macthed_wrt_campaign = max * 100 / len(playbook_sig[matched_campaign_name])
                matched_wrt_sample = max * 100 / len(list(matched_json.keys()))
                json_data["Activity matching percent with campaign"] = str(macthed_wrt_campaign)
                json_data["Activity matching percent with Sample"] = str(matched_wrt_sample)

            with open(outputfile_campaign, 'w') as fw:
                json_report = json.dumps(json_data, sort_keys=True, indent=4)
                fw.write(json_report)

