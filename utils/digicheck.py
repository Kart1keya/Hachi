import subprocess
from .config import Config


class DigitalSignatureCheck:
    def __init__(self):
        pass

    opts = Config().read_config()
    # Commandline input
    _SIGCHECK_EXE = opts["config"]["SIG_CHECK_EXE"]
    _SIGCHECK_ARGS = ' -i -h'

    # extract record information
    _DIGISIG_KEY_LIST = ["Verified", "Link date", "Signing date", "Catalog", "Signers", "Cert Status", "Valid Usage",
                         "Cert Issuer", "Serial Number", "Thumbprint", "Algorithm", "Valid from", "Valid to", "Company",
                         "Description", "Product", "Prod version", "File version", "MachineType", "MD5", "SHA1",
                         "SHA256", "IMP", ]
    _DIGISIG_DATA_RECORD = {
        "Verified": "n/a", "Link date": "n/a", "Signing date": "n/a", "Catalog": "n/a", "Signers": "n/a",
        "Cert Status": "n/a",
        "Valid Usage": "n/a", "Cert Issuer": "n/a", "Serial Number": "n/a", "Thumbprint": "n/a", "Algorithm": "n/a",
        "Valid from": "n/a",
        "Valid to": "n/a", "Company": "n/a", "Description": "n/a", "Product": "n/a", "Prod version": "n/a",
        "File version": "n/a",
        "MachineType": "n/a", "MD5": "n/a", "SHA1": "n/a", "SHA256": "n/a", "IMP": "n/a"
    }

    _REQ_DATA_FIELD = {"Verified": "n/a",
                       "Signing date": "n/a",
                       "Signers": "n/a",
                       "Cert Issuer": "n/a",
                       "Valid from": "n/a",
                       "Valid to": "n/a",
                       "Company": "n/a",
                       "Description": "n/a"
                       }
    _DIGISIG_DATA = {}

    Delimiter = "|"

    def parse_sigcheck_output(self, output):
        self._DIGISIG_DATA = dict(self._DIGISIG_DATA_RECORD)
        result = output.split("\r\n")
        signers_sig_flag = 0
        key = ""
        for line in result:
            if len(line.split(":")) == 2:
                # Key value pair is present
                key = line.split(":")[0].strip("\t")
                value = line.split(":")[1].strip("\t")
                if key in self._DIGISIG_KEY_LIST:
                    if self._DIGISIG_DATA[key] == "n/a":
                        if key == "Signers":
                            signers_sig_flag = signers_sig_flag + 1
                        else:
                            self._DIGISIG_DATA[key] = value
            elif (line.strip(" ") != "") and len(line.split(":")) == 1 and signers_sig_flag == 1:

                # Get Signers information
                publisher_value = line.strip("\t").strip(" ")
                self._DIGISIG_DATA[key] = publisher_value

                signers_sig_flag = signers_sig_flag + 1
            elif len(line.split(":")) > 2:
                other_fields = ["Catalog", "Valid from", "Valid to", "Link date", "Signing date"]

                key = line.split(":")[0].strip("\t")
                if key in other_fields:
                    value = ":".join(line.split(":")[1:]).strip("\t")
                    self._DIGISIG_DATA[key] = value

    def run(self, filetoscan):

        ExceptionOccured = False
        cmd = ("%s %s \"%s\"") % (self._SIGCHECK_EXE, self._SIGCHECK_ARGS, filetoscan)
        result = ""
        try:
            result = subprocess.check_output(cmd, shell=True)
            
        except subprocess.CalledProcessError as e:
            if e.returncode < 0:
                ExceptionOccured = True
            else:
                result = e.output
        if not ExceptionOccured:
            try:
                self.parse_sigcheck_output(result.decode('utf-8'))
                for key in self._DIGISIG_DATA:
                    if key in self._REQ_DATA_FIELD:
                        self._REQ_DATA_FIELD[key] = self._DIGISIG_DATA[key]
            except Exception as e:
                print((str(e)))
                self._DIGISIG_DATA = {}

        else:
            self._DIGISIG_DATA = {}
