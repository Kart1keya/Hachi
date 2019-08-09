import os
import web
import uuid
import json
import hashlib
import pythoncom
import win32com.client
from utils import db_comm
from utils.config import Config
from utils.mitre_table import table_creation

urls = ('/', 'Upload',
        '/report/download/(.+)', 'Images',
        '/report/images/(.+)', 'Images',
        '/report/(.+)', 'Reporting',
        '/images/(.*)', 'Images'
        )

opts = Config().read_config()
pythoncom.CoInitialize()
qinfo = win32com.client.Dispatch("MSMQ.MSMQQueueInfo")
computer_name = os.getenv('COMPUTERNAME')
queue_name = opts["config"]["QUEUE_NAME"]
qinfo.FormatName = "direct=os:" + computer_name + "\\PRIVATE$\\" + queue_name


class Reporting:

    def __init__(self):
        pass

    def GET(self, uid):
        render = web.template.frender('templates/reporting.html')
        filename = db_comm.get_column_val('uid', uid, 'filepath')
        anomalies = []
        file_info = {}
        cert_info = {}
        table_data = {}
        static_info = {}
        campaign_info = {}
        suspicious_api_seq = []
        report_path = os.path.join(opts["config"]["OUTPUT_DIR"], uid)
        if os.path.exists(os.path.join(report_path, uid + '.campaign.json')):
            with open(os.path.join(report_path, uid + '.campaign.json'), 'rb') as fp:
                campaign_info = json.load(fp)
        if os.path.exists(os.path.join(report_path, uid + '.basic_info.json')):
            with open(os.path.join(report_path, uid+'.basic_info.json'), 'rb') as fp:
                file_info = json.load(fp)
        if os.path.exists(os.path.join(report_path, uid + '.static.json')):
            with open(os.path.join(report_path, uid + '.static.json'),
                      'rb') as fp:
                static_info = json.load(fp)
        if os.path.exists(os.path.join(report_path, uid + '.cert.json')):
            with open(os.path.join(report_path, uid + '.cert.json'),
                      'rb') as fp:
                cert_info = json.load(fp)
        if os.path.exists(os.path.join(report_path, uid + '.yara.json')):
            with open(os.path.join(report_path, uid + '.yara.json'),
                      'rb') as fp:
                suspicious = json.load(fp)
                if "Yara Matched" in suspicious:
                    for tag in suspicious["Yara Matched"].keys():
                        for rule_name in suspicious["Yara Matched"][tag].keys():
                            if "description" in suspicious["Yara Matched"][tag][rule_name]:
                                anomalies.append(suspicious["Yara Matched"][tag][rule_name]["description"])
        if os.path.exists(os.path.join(report_path, uid + '.behav.json')):
            with open(os.path.join(report_path, uid + '.behav.json'),
                      'rb') as fp:
                behav_json = json.load(fp)
                if "Suspicious Behaviors" in behav_json:
                    for api_seq in behav_json["Suspicious Behaviors"].keys():
                        suspicious_api_seq.append(api_seq)
        if os.path.exists('utils\mitre.json'):
            with open('utils\mitre.json', 'rb') as fp:
                mitre_json = json.load(fp)
                if os.path.exists(os.path.join(report_path, uid + '.mitre.json')):
                    with open(os.path.join(report_path, uid+'.mitre.json'), 'rb') as fs:
                        sig_json = json.load(fs)
                        table_data = table_creation(sig_json, mitre_json)
        if os.path.exists(os.path.join(report_path, uid + '.png')):
            png_name = uid + '.png'
        else:
            png_name = 'Hachi-Logo.png'
        html_data = render(uid, filename, file_info, campaign_info, table_data, static_info, cert_info, anomalies,
                           suspicious_api_seq, png_name)
        return html_data


class Upload:
    def __init__(self):
        pass

    def GET(self):
        render = web.template.frender('templates/hachi.html')
        row = db_comm.get_data()
        sample_count = db_comm.count('uid')
        pending_count = db_comm.count_condition('uid', 'STATUS', 'PENDING')
        complete_count = db_comm.count_condition('uid', 'STATUS', 'COMPLETED')
        fail_count = db_comm.count_condition('uid', 'STATUS', 'FAILED')
        status_count = [complete_count, pending_count, fail_count]
        html_data = render(row, sample_count, status_count)
        return html_data

    def POST(self):
        x = web.input(myfile={})
        filename = x['myfile'].filename
        if filename != "" and filename is not None:
            uid = uuid.uuid4()
            folderpath = os.path.join(opts["config"]["INPUT_DIR"], str(uid))
            os.mkdir(folderpath)
            out_folderpath = os.path.join(opts["config"]["OUTPUT_DIR"], str(uid))
            os.mkdir(out_folderpath)
            with open(os.path.join(folderpath, str(uid)), 'wb') as fp:
                fp.write(x['myfile'].file.read())

            queue = qinfo.Open(2, 0)  # Open a ref to queue
            msg = win32com.client.Dispatch("MSMQ.MSMQMessage")
            msg.Label = "TestMsg"
            msg.Body = str(uid)
            msg.Send(queue)
            queue.Close()
            with open(os.path.join(folderpath, str(uid)), 'rb') as fp:
                sha2 = hashlib.sha256(fp.read()).hexdigest()
            db_comm.insert(str(uid), sha2, filename, "PENDING")
        raise web.seeother('/')


class Images:
    def __init__(self):
        pass

    def GET(self, name):
        ext = name.split(".")[-1]  # Gather extension

        cType = {
            "png": "image/png",
            "jpg": "image/jpeg",
            "gif": "image/gif",
            "ico": "image/x-icon",
            "zip": "application/octet-stream"
        }

        if name in os.listdir('images'):  # Security
            web.header("Content-Type", cType[ext])  # Set the Header
            return open('images/%s' % name, "rb").read()  # Notice 'rb' for reading images
        else:
            for root, dir, filenames in os.walk(opts["config"]["OUTPUT_DIR"]):
                if name in filenames:
                    png_path = os.path.join(root, name)
                    web.header("Content-Type", cType[ext])
                    return open(png_path, "rb").read()
        raise web.notfound()


if __name__ == "__main__":
   app = web.application(urls, globals())
   app.run()