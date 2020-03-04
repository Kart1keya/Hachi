import os
import yara
import time
import lief
import json
import pefile
import zipfile
import hashlib
import pythoncom
import win32com.client
from utils import db_comm
from utils import peparser
from utils import get_malicious
from utils.config import Config
from utils.yarascan import YaraScan
from utils.MSMQCustom import MSMQCustom
from utils.playbookSig import playbooksig
from utils.digicheck import DigitalSignatureCheck
from utils.graphity.graphity import get_behaviors

RE_EMBEDDED_FILE = r'0x([A-F0-9]+)\s+([0-9]+)\s+([^,:\(\.]+)'

opts = Config().read_config()

if opts["config"]["ENABLE_AV_OTX"] == 1:
    from utils import lookup

if opts["config"]["ENABLE_EMULATION"] == 1:
    from utils import binee


def zipdir(path, ziph):
    for root, dirs, files in os.walk(path):
        for file in files:
            ziph.write(os.path.join(root, file))


def threat_intel_lookup_file(md5, sha1, sha2):
    try:
        final_alerts = {}
        final_av_alerts = []
        exception_found = False
        md5_alert = lookup.alienvault_otx("hash", md5)
        sha1_alert = lookup.alienvault_otx("hash", sha1)
        sha2_alert = lookup.alienvault_otx("hash", sha2)
        if "AV Detections" in md5_alert:
            final_av_alerts = md5_alert["AV Detections"]
        elif "AV Detections" in sha1_alert:
            final_av_alerts = sha1_alert["AV Detections"]
        elif "AV Detections" in sha2_alert:
            final_av_alerts = sha2_alert["AV Detections"]
        if len(final_av_alerts) > 0:
            final_alerts["AV Detections"] = final_av_alerts
        pulse_alert_md5 = []
        pulse_alert_sha1 = []
        pulse_alert_sha2 = []
        if "Pulse Alerts" in md5_alert:
            pulse_alert_md5 = md5_alert["Pulse Alerts"]
        if "Pulse Alerts" in sha1_alert:
            pulse_alert_sha1 = sha1_alert["Pulse Alerts"]
        if "Pulse Alerts" in sha2_alert:
            pulse_alert_sha2 = sha2_alert["Pulse Alerts"]
        final_pulse_alerts = pulse_alert_md5
        if len(pulse_alert_sha1) > 0:
            for alertsh1 in pulse_alert_sha1:
                found = False
                for pulse_id in alertsh1.keys():
                    for alert_final in final_pulse_alerts:
                        for final_pulse_id in alert_final.keys():
                            if pulse_id == final_pulse_id:
                                found = True
                                break
                        if found:
                            break
                    if found:
                        break
                if not found:
                    final_pulse_alerts.append(alertsh1)
        if len(pulse_alert_sha2) > 0:
            for alertsh2 in pulse_alert_sha2:
                found = False
                for pulse_id in alertsh2.keys():
                    for alert_final in final_pulse_alerts:
                        for final_pulse_id in alert_final.keys():
                            if pulse_id == final_pulse_id:
                                found = True
                                break
                        if found:
                            break
                    if found:
                        break
                if not found:
                    final_pulse_alerts.append(alertsh2)
        if len(final_pulse_alerts) > 0:
            final_alerts["Pulse Alerts"] = final_pulse_alerts
    except Exception as e:
        print("Error: %s" %str(e))
        exception_found = True

    return (final_alerts, exception_found)

def tip_lookup(dst_file_static):
    tip_json = {}
    exception_found = False
    try:
        with open(dst_file_static, 'rb') as fp:
            suspicious_strings = json.load(fp)
            if "Yara Matched" in suspicious_strings:
                for tag in list(suspicious_strings["Yara Matched"].keys()):
                    if tag == "URL" or tag == "domain" or tag == "IP" or tag == "URL":
                        for rule_name in list(suspicious_strings["Yara Matched"][tag].keys()):
                            if "indicators_matched" in suspicious_strings["Yara Matched"][tag][rule_name]:
                                for indicator in suspicious_strings["Yara Matched"][tag][rule_name]["indicators_matched"]:
                                    
                                    otx_alerts = lookup.alienvault_otx(tag, indicator)
                                    if len(otx_alerts) > 0:
                                        if tag not in tip_json.keys():
                                            tip_json[tag] = {}
                                        if indicator not in tip_json[tag].keys():
                                            tip_json[tag][indicator] = {}
                                        tip_json[tag][indicator]["AlienVault"] = otx_alerts

                                    alerts_hphosts = lookup.hphosts_spamhaus(indicator)
                                    if len(alerts_hphosts) > 0:
                                        for ti in alerts_hphosts:
                                            if tag not in tip_json.keys():
                                                tip_json[tag] = {}
                                            if indicator not in tip_json[tag].keys():
                                                tip_json[tag][indicator] = {}
                                            tip_json[tag][indicator][ti] = "Found malicious on " + ti
    except Exception as e:
        print("Error: %s" %str(e))
        exception_found = True
    
    return (tip_json, exception_found)


def process_file(yara_scan, yara_rules, yara_id_rules, yara_mitre_rules, input_file, output_file_static,
                 outputfile_mitre):
    try:
        with open(input_file, 'rb') as f:
            file_data = f.read()

            yara_mitre_rules.match(data=file_data, callback=yara_scan.yara_callback_desc,
                                   which_callbacks=yara.CALLBACK_MATCHES)
            json_data = yara_scan.yara_sig_matched
            with open(outputfile_mitre, 'w') as fw:
                json_report = json.dumps(json_data, sort_keys=True, indent=4)
                fw.write(json_report)

            json_data = {}
            yara_id_rules.match(data=file_data, callback=yara_scan.yara_callback, which_callbacks=yara.CALLBACK_MATCHES)
            json_data['File Type Information'] = yara_scan.yara_idsig_matched

            yara_scan.yara_sig_matched = {}
            yara_rules.match(data=file_data, callback=yara_scan.yara_callback_desc, which_callbacks=yara.CALLBACK_MATCHES)
            json_data['Yara Matched'] = yara_scan.yara_sig_matched
            with open(output_file_static, 'w') as fw:
                json_report = json.dumps(json_data, sort_keys=True, indent=4)
                fw.write(json_report)
    except Exception as e:
        print("Error while parsing for mitre and yara")
        print((str(e)))


def process_dir(src_dir, dst_dir, sample_type):

    print(("Processing: " + src_dir + " ..."))
    md5 = ""
    sha1 = ""
    sha2 = ""
    yara_scan = YaraScan()
    yara_rules = yara.compile('./yara_sigs/index.yar')
    yara_idrules = yara.compile('./yara_sigs/index_id.yar')
    yara_mitre_rules = yara.compile('./yara_sigs/index_mitre.yar')

    for root_dir, dirs, files in os.walk(src_dir):
        for filename in files:
            failed = False
            src_file = os.path.join(root_dir, filename)
            try:
                with open(src_file, 'rb') as f:
                    contents = f.read()
                    file_size = len(contents)
                    sha1 = hashlib.sha1(contents).hexdigest()
                    sha2 = hashlib.sha256(contents).hexdigest()
                    md5_obj = hashlib.md5()
                    for i in range(0, len(contents), 8192):
                        md5_obj.update(contents[i:i + 8192])
                    md5 = md5_obj.hexdigest()
                    basic_info = {'MD5': md5, 'SHA1': sha1, 'SHA256': sha2, 'File Size': file_size}
                    with open(os.path.join(dst_dir, filename) + ".basic_info.json", 'w') as fw:
                        json.dump(basic_info, fw)
                    print("basic info done")
            except Exception as e:
                print(("Error: " + str(e)))
                failed = True

            try:
                if md5 != "" and sha1 != "" and sha2 != "" and opts["config"]["ENABLE_AV_OTX"] == 1:
                    retrun_val = threat_intel_lookup_file(md5, sha1, sha2)
                    final_alerts = retrun_val[0]
                    if retrun_val[1] == True:
                        failed = True
        
                    if len(final_alerts.keys()) > 0:
                        with open(os.path.join(dst_dir, filename) + ".threat_intel_file.json", 'w') as fw:
                            json.dump(final_alerts, fw)
                    else:
                        print("No, Threat Data found")
                    print("Threat Intel File done")
            except Exception as e:
                print(("Error: " + str(e)))
                failed = True

            if sample_type == "PE":            
                try:
                    peparsed = peparser.parse(src_file)
                    with open(os.path.join(dst_dir, filename) + ".static.json", 'w') as fp:
                        json.dump(peparsed, fp)
                    print("Static done")
                    with open(os.path.join(dst_dir, filename) + ".cert.json", 'w') as fp:
                        digiSig = DigitalSignatureCheck()
                        digiSig.run(src_file)
                        json.dump(digiSig._REQ_DATA_FIELD, fp)
                    print("Cert done")
                except Exception as e:
                    print((str(e)))
                    print("No static data.. !!")
                    failed = True
            elif sample_type == "ELF":
                try:
                    binary = lief.parse(src_file)
                    elfparsed = json.loads(lief.to_json(binary))
                    with open(os.path.join(dst_dir, filename) + ".static.json", 'w') as fp:
                        json.dump(elfparsed, fp)
                    print("Linux Static done")
                except Exception as e:
                    print((str(e)))
                    print("No static data.. !!")
                    failed = True

            try:
                dst_file_static = os.path.join(dst_dir, filename) + ".yara.json"
                dst_file_mitre = os.path.join(dst_dir, filename) + ".mitre.json"
                # run yara rules on file
                process_file(yara_scan, yara_rules, yara_idrules, yara_mitre_rules, src_file, dst_file_static,
                                        dst_file_mitre)

            except Exception as e:
                print((str(e)))
                print("Yara Part did not run")
                failed = True

            try:
                tip_file = os.path.join(dst_dir, filename) + ".tip.json"
                tip_json = {}
                if opts["config"]["ENABLE_AV_OTX"] == 1 and os.path.exists(dst_file_static):
                    ret_val = tip_lookup(dst_file_static)
                    tip_json = ret_val[0]
                    if ret_val[1]:
                        failed = True
                    if (len(tip_json.keys()) > 0):
                        with open(tip_file, 'w') as fw:
                            json.dump(tip_json, fw)

            except Exception as e:
                print((str(e)))
                print("Lookup Part did not run")

            try:
                if opts["config"]["ENABLE_EMULATION"] == 1 and sample_type == "PE":
                    dst_binee_file = os.path.abspath(os.path.join(dst_dir, filename) + ".binee.json")
                    report_emulation_json = binee.emulate(os.path.abspath(src_file), dst_binee_file)
                    if len(report_emulation_json.keys()) > 0:
                        report_emulation_file = os.path.abspath(os.path.join(dst_dir, filename) + ".emulation.json")
                        with open(report_emulation_file, 'w') as fw:
                            json.dump(report_emulation_json, fw)
            except Exception as e:
                print((str(e)))
                print("Emulation part did not run")

            try:
                dst_file = os.path.join(dst_dir, filename) + ".behav.json"
                get_behaviors(src_file, dst_file, dst_dir)
            except Exception as e:
                print((str(e)))
                print("Behavior part did not run..!!")
                failed = True

            try:
                if os.path.exists(os.path.join(dst_dir, filename) + ".behav.json"):
                    with open(os.path.join(dst_dir, filename) + ".behav.json", 'rb') as fp:
                        file_data = fp.read()
                        json_data = {}
                        yara_mitre_api = yara.compile('.\\yara_sigs\\mitre\\api_based.yar')
                        yara_scan.yara_sig_matched = {}
                        yara_mitre_api.match(data=file_data, callback=yara_scan.yara_callback_desc,
                                             which_callbacks=yara.CALLBACK_MATCHES)
                        json_data['API_MITRE'] = yara_scan.yara_sig_matched
                        dst_file_mitre = os.path.join(dst_dir, filename) + ".mitre.json"
                        try:
                            with open(dst_file_mitre, 'rb') as fs:
                                mitre_matched_json = json.loads(fs.read())
                                dump_mitre = mitre_matched_json
                                for matched_tid in list(json_data['API_MITRE'].keys()):
                                    if matched_tid in mitre_matched_json.keys():
                                        dump_mitre[matched_tid].update(json_data['API_MITRE'][matched_tid])
                                    else:
                                        dump_mitre[matched_tid] = json_data['API_MITRE'][matched_tid]
                        except:
                            dst_file_mitre = os.path.join(dst_dir, filename) + ".mitre.json"
                            with open(dst_file_mitre, 'rb') as fs:
                                dump_mitre = json.loads(fs.read())
                        with open(dst_file_mitre, 'wb') as fs:
                            fs.write(json.dumps(dump_mitre, sort_keys=True, indent=4).encode('utf-8'))
                        dst_campaign_file = os.path.join(dst_dir, filename) + ".campaign.json"
                        playbooksig(opts["config"]["PLAYBOOK_JSON"], dst_file_mitre, dst_campaign_file)
                        print("Playbook part done")
                else:
                    dst_file_mitre = os.path.join(dst_dir, filename) + ".mitre.json"
                    with open(dst_file_mitre, 'rb') as fs:
                            mitre_matched_json = json.loads(fs.read())
                    with open(dst_file_mitre, 'wb') as fs:
                        fs.write(json.dumps(mitre_matched_json, sort_keys=True, indent=4).encode('utf-8'))
                    dst_campaign_file = os.path.join(dst_dir, filename) + ".campaign.json"
                    playbooksig(opts["config"]["PLAYBOOK_JSON"], dst_file_mitre, dst_campaign_file)
                    print("Playbook part done")

            except Exception as e:
                print((str(e)))
                print("MITRE and Playbook part did not work properly")
                failed = True

            try:
                report_folder_name = dst_dir.split("\\")[-1]
                zipf = zipfile.ZipFile(os.path.join(opts["config"]["OUTPUT_DIR"], report_folder_name+'.zip'), 'w',
                                       zipfile.ZIP_DEFLATED)
                zipdir(dst_dir, zipf)
                zipf.close()
            except Exception as e:
                print((str(e)))
                failed = True

            if failed:
                return False
            return True


def check_queue():
    try:
        print("Running..")
        print("Checking for New Sample..")
        msmq_queue_obj = MSMQCustom(opts["config"]["QUEUE_NAME"])
        msmq_queue_obj.open_queue(1, 0)  # Open a ref to queue to read(1)
        #queue = qinfo.Open(1, 0) 
        while True:
            #if queue.Peek(pythoncom.Empty, pythoncom.Empty,  1000):
            if msmq_queue_obj.peek(1000):
                msg = msmq_queue_obj.recv_from_queue()
                if msg:
                    print("Found new sample:")
                    print("Label:", msg.Label)
                    print("Body :", msg.Body)
                    bDone = process_dir(os.path.join(opts["config"]["INPUT_DIR"], msg.Body),
                                        os.path.join(opts["config"]["OUTPUT_DIR"], msg.Body), msg.Label)
                    if bDone:
                        db_comm.update(msg.Body, "COMPLETED")
                    else:
                        db_comm.update(msg.Body, "FAILED")
    except Exception as e:
        print((str(e)))


if __name__ == '__main__':
    check_queue()
