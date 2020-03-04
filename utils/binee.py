import os
import json
from .config import Config

opts = Config().read_config()

BINEE_FOLDER_PATH = opts["config"]["BINEE_FOLDER"]

def emulate(src_path, dest_path):

    null_artifact = {}
    suspicious_artifact = {
            "CreateFileA": {"description": "Creates File",
            "values": []
            },
            "WriteFile": {"description": "Writes File",
            "values": []
            },
            "DeleteFileA": {"description": "Deletes File",
            "values": []
            },
            "RegCreateKeyA": {"description": "Creates Registry Keys",
            "values": []
            },
            "RegOpenKeyA": {"description": "Opens Registry Keys",
            "values": []
            },
            "RegSetValueA": {"description": "Sets Registry Values",
            "values": []
            },
        }

    try:
        binee_path = "binee.exe"

        org_path = os.getcwd()
        os.chdir(BINEE_FOLDER_PATH)
        cmd_line = binee_path + " -j " + src_path  + " > "  + dest_path
        os.system(cmd_line)
        os.chdir(org_path)
        
    except Exception as e:
        print("Couldn't emulate %s" % e)
        return null_artifact

    try:
        found_artifacts = 0
        with open(dest_path, 'r') as fp:
            lines = fp.readlines()
            reg_created = False
            file_created = False
            reg_path = ""
            file_path = ""
            file_handle = ""
            for line in lines:
                one_api_call = line.strip('\r\n')
                api_json = json.loads(one_api_call)
                if 'fn' in api_json:
                    if api_json['fn'] == "CreateFileA":
                        if 'values' in api_json:
                            file_path = api_json['values'][0]
                            file_created = True
                            suspicious_artifact["CreateFileA"]["values"].append(file_path)
                            if 'return' in api_json:
                                file_handle = api_json['return']
                            found_artifacts = found_artifacts + 1
                    
                    if api_json['fn'] == "WriteFile":
                        if 'values' in api_json:
                            f_handle = api_json['values'][0]
                            if f_handle == file_handle and file_created and file_path != "":
                                suspicious_artifact["WriteFile"]["values"].append(file_path)
                            
                            found_artifacts = found_artifacts + 1

                    if api_json['fn'] == "DeleteFileA":
                        if 'values' in api_json:
                            del_file_path = api_json['values'][0]
                            suspicious_artifact["DeleteFileA"]["values"].append(del_file_path)
                            if file_created and file_path == del_file_path:
                                file_created = False
                                file_path = ""
                            found_artifacts = found_artifacts + 1
                        
                    
                    if api_json['fn'] == "RegCreateKeyA":
                        if 'values' in api_json:
                            reg_path = api_json['values'][0] + "\\"  +api_json['values'][1]
                            reg_created = True
                            suspicious_artifact["RegCreateKeyA"]["values"].append(reg_path)
                            found_artifacts = found_artifacts + 1

                    if api_json['fn'] == "RegOpenKeyA":
                        if 'values' in api_json:
                            reg_path = api_json['values'][0] + "\\"  +api_json['values'][1]
                            suspicious_artifact["RegOpenKeyA"]["values"].append(reg_path)
                            found_artifacts = found_artifacts + 1

                    if api_json['fn'] == "RegSetValueA":
                        if 'values' in api_json:
                            setvaluename = api_json['values'][1]
                            regvalue = str(api_json['values'][2])
                            if reg_created == True and reg_path != "":
                                full_key_path = reg_path + "___" + setvaluename + "___" + regvalue
                                suspicious_artifact["RegSetValueA"]["values"].append(full_key_path)
                                reg_created = False
                                reg_path = ""
                                found_artifacts = found_artifacts + 1
                            else:
                                valuename_value = setvaluename + "___" + regvalue
                                suspicious_artifact["RegSetValueA"]["values"].append(valuename_value)
                                found_artifacts = found_artifacts + 1

    except Exception as e:
        print("Issue while Parsing %s" % e)
        return null_artifact

    if found_artifacts > 0:
        return suspicious_artifact
    else:
        return null_artifact
