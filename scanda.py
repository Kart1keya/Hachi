import os
import yara
import json
import pefile
import zipfile
import hashlib
import win32com.client
from utils import db_comm
from utils import peparser
from utils.config import Config
from utils.yarascan import YaraScan
from utils.playbookSig import playbooksig
from utils.digicheck import DigitalSignatureCheck
from utils.graphity.graphity import get_behaviors

RE_EMBEDDED_FILE = r'0x([A-F0-9]+)\s+([0-9]+)\s+([^,:\(\.]+)'

opts = Config().read_config()


def zipdir(path, ziph):
    for root, dirs, files in os.walk(path):
        for file in files:
            ziph.write(os.path.join(root, file))


def process_file(yara_scan, yara_rules, yara_id_rules, yara_mitre_rules, input_file, output_file_static,
                 outputfile_mitre):
    with open(input_file, 'rb') as f:
        file_data = f.read()

        yara_mitre_rules.match(data=file_data, callback=yara_scan.yara_callback_desc,
                               which_callbacks=yara.CALLBACK_MATCHES)
        json_data = yara_scan.yara_sig_matched
        with open(outputfile_mitre, 'w') as fw:
            json_report = json.dumps(json_data, sort_keys=True, indent=4)
            fw.write(json_report.encode('utf-8'))

        json_data = {}
        yara_id_rules.match(data=file_data, callback=yara_scan.yara_callback, which_callbacks=yara.CALLBACK_MATCHES)
        json_data['File Type Information'] = yara_scan.yara_idsig_matched

        yara_scan.yara_sig_matched = {}
        yara_rules.match(data=file_data, callback=yara_scan.yara_callback_desc, which_callbacks=yara.CALLBACK_MATCHES)
        json_data['Yara Matched'] = yara_scan.yara_sig_matched

        with open(output_file_static, 'w') as fw:
            json_report = json.dumps(json_data, sort_keys=True, indent=4)
            fw.write(json_report.encode('utf-8'))
        return json_data


def process_dir(src_dir, dst_dir):

    print("Processing: " + src_dir + " ...")
    yara_scan = YaraScan()
    yara_rules = yara.compile('./yara_sigs/index.yar')
    yara_idrules = yara.compile('./yara_sigs/index_id.yar')
    yara_mitre_rules = yara.compile('./yara_sigs/index_mitre.yar')

    for root_dir, dirs, files in os.walk(src_dir):
        for filename in files:
            print(filename)
            src_file = os.path.join(root_dir, filename)
            try:
                pefile.PE(src_file)
                print "PE File loaded"
                with open(src_file, 'rb') as f:
                    contents = f.read()
                    file_size = len(contents)
                    sha1 = hashlib.sha1(contents).hexdigest()
                    sha2 = hashlib.sha256(contents).hexdigest()
                    # md5 accepts only chunks of 128*N bytes
                    md5_obj = hashlib.md5()
                    for i in range(0, len(contents), 8192):
                        md5_obj.update(contents[i:i + 8192])
                    md5 = md5_obj.hexdigest()
            except Exception as e:
                print("Skipping: " + src_file)
                print("Error: " + str(e))
                return

            basic_info = {'MD5': md5, 'SHA1': sha1, 'SHA256': sha2, 'File Size': file_size}

            with open(os.path.join(dst_dir, filename) + ".basic_info.json", 'wb') as fw:
                json.dump(basic_info, fw)
            peparsed = peparser.parse(src_file)
            with open(os.path.join(dst_dir, filename) + ".static.json", 'wb') as fp:
                json.dump(peparsed, fp)
            dst_file_static = os.path.join(dst_dir, filename) + ".yara.json"
            dst_file_mitre = os.path.join(dst_dir, filename) + ".mitre.json"
            # run yara rules on file
            process_file(yara_scan, yara_rules, yara_idrules, yara_mitre_rules, src_file, dst_file_static,
                                    dst_file_mitre)

            dst_file = os.path.join(dst_dir, filename) + ".behav.json"
            get_behaviors(src_file, dst_file, dst_dir)
            if os.path.exists(os.path.join(dst_dir, filename) + ".behav.json"):
                with open(os.path.join(dst_dir, filename) + ".behav.json", 'rb') as fp:
                    file_data = fp.read()

                    json_data = {}
                    yara_mitre_api = yara.compile('.\\yara_sigs\\mitre\\api_based.yar')
                    yara_scan.yara_sig_matched = {}
                    yara_mitre_api.match(data=file_data, callback=yara_scan.yara_callback_desc,
                                         which_callbacks=yara.CALLBACK_MATCHES)
                    json_data['API_MITRE'] = yara_scan.yara_sig_matched
                    with open(dst_file_mitre, 'rb') as fs:
                        mitre_matched_json = json.loads(fs.read())
                        for matched_tid in mitre_matched_json.keys():
                            if matched_tid in json_data['API_MITRE']:
                                mitre_matched_json[matched_tid].update(json_data['API_MITRE'][matched_tid])
                    with open(dst_file_mitre, 'wb') as fs:
                        fs.write(json.dumps(mitre_matched_json, sort_keys=True, indent=4).encode('utf-8'))
            dst_campaign_file = os.path.join(dst_dir, filename) + ".campaign.json"
            playbooksig(opts["config"]["PLAYBOOK_JSON"], dst_file_mitre, dst_campaign_file)

            with open(os.path.join(dst_dir, filename) + ".cert.json", 'wb') as fp:
                DigiSig = DigitalSignatureCheck()
                DigiSig.run(src_file)
                json.dump(DigiSig._REQ_DATA_FIELD, fp)
            report_folder_name = dst_dir.split("\\")[-1]
            zipf = zipfile.ZipFile(os.path.join(opts["config"]["OUTPUT_DIR"], report_folder_name+'.zip'), 'w',
                                   zipfile.ZIP_DEFLATED)
            zipdir(dst_dir, zipf)
            zipf.close()
            return True


def check_queue():
    qinfo = win32com.client.Dispatch("MSMQ.MSMQQueueInfo")
    computer_name = os.getenv('COMPUTERNAME')
    qinfo.FormatName = "direct=os:" + computer_name + "\\PRIVATE$\\" + opts["config"]["QUEUE_NAME"]
    queue = qinfo.Open(1, 0)  # Open a ref to queue to read(1)
    while True:
        msg = queue.Receive()
        if msg:
            print("Found new sample:")
            print "Label:", msg.Label
            print "Body :", msg.Body
            bDone = process_dir(os.path.join(opts["config"]["INPUT_DIR"], msg.Body.encode('utf-8')),
                                os.path.join(opts["config"]["OUTPUT_DIR"], msg.Body.encode('utf-8')))
            if bDone:
                db_comm.update(msg.Body.encode('utf-8'), "COMPLETED")
            else:
                db_comm.update(msg.Body.encode('utf-8'), "FAILED")
    queue.Close()


if __name__ == '__main__':
    check_queue()