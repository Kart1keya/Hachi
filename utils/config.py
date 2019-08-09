import ConfigParser
import sys
from ConfigParser import SafeConfigParser

# import warnings
# warnings.filterwarnings("error")


# http://stackoverflow.com/a/21190382
reload(sys)
sys.setdefaultencoding("utf8")


class Config:
    def __init__(self, filename=".\\utils\\Hachi.config"):

        self.parser = SafeConfigParser()
        self.parser.read(filename)
        self.opts = dict({
            "config": dict(),
            "logging": dict()
        })

    def read_config(self):

        self.opts["config"]["INPUT_DIR"] = self.parser.get("config", "input_dir")
        self.opts["config"]["OUTPUT_DIR"] = self.parser.get("config", "output_dir")
        self.opts["config"]["PLAYBOOK_JSON"] = self.parser.get("config", "PLAYBOOK_JSON")
        self.opts["config"]["MITRE_JSON"] = self.parser.get("config", "MITRE_JSON")
        self.opts["config"]["DB_PATH"] = self.parser.get("config", "DB_PATH")
        self.opts["config"]["SIG_CHECK_EXE"] = self.parser.get("config", "SIG_CHECK_EXE")
        self.opts["config"]["QUEUE_NAME"] = self.parser.get("config", "QUEUE_NAME")

        self.opts["logging"]["log_verbosity"] = self.parser.get("logging", "log_verbosity")
        self.opts["logging"]["log_backup_count"] = self.parser.get("logging", "log_backup_count")
        self.opts["logging"]["log_date_format"] = self.parser.get("logging", "log_date_format")
        self.opts["logging"]["log_rotate_at"] = self.parser.get("logging", "log_rotate_at")

        return self.opts

    def get_var(self, section, var):
        try:
            return self.parser.get(section, var)
        except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
            return None

    def get_section(self, section):
        try:
            options = self.parser.items(section)
        except ConfigParser.NoSectionError:
            return None

        opt_dict = dict()
        for pairs in options:
            opt_dict[pairs[0]] = pairs[1]

        return opt_dict

    def set_var(self, section, var, value):
        try:
            return self.parser.set(section, var, value)
        except ConfigParser.NoSectionError:
            return None

    def list_config(self):
        print "Configuration Options:"
        for section in self.parser.sections():
            print "%s" % (section)
            for (name, value) in self.parser.items(section):
                print "\t%s:\t%s" % (name, value)
        return
