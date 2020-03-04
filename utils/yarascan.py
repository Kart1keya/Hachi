import yara


class YaraScan:
    def __init__(self):
        self.yara_sig_matched = {}
        self.yara_idsig_matched = {}

    def yara_callback_desc(self, data):
        if data['matches']:
            tag = ""
            if len(data['tags']) > 0:
                for tag in data['tags']:
                    if tag not in list(self.yara_sig_matched.keys()):
                        self.yara_sig_matched[tag] = {}
                    if data['rule'] not in list(self.yara_sig_matched[tag].keys()):
                        self.yara_sig_matched[tag][data['rule']] = {}
                        if 'description' in data['meta']:
                            self.yara_sig_matched[tag][data['rule']]['description'] = data['meta']['description']
                        self.yara_sig_matched[tag][data['rule']]['indicators_matched'] = []
                    for string in data['strings']:
                        try:
                            if string[2].decode('windows-1252') \
                                    not in self.yara_sig_matched[tag][data['rule']]['indicators_matched']:
                                    self.yara_sig_matched[tag][data['rule']]['indicators_matched'].\
                                        append(string[2].decode('windows-1252'))
                        except:
                            continue
        yara.CALLBACK_CONTINUE

    def yara_callback(self, data):
        if data['matches']:
            tag = ""
            if len(data['tags']) > 0:
                tag = data['tags'][0]
            if tag not in list(self.yara_idsig_matched.keys()):
                self.yara_idsig_matched[tag] = []
            if data['rule'] not in self.yara_idsig_matched[tag]:
                self.yara_idsig_matched[tag].append(data['rule'])
        yara.CALLBACK_CONTINUE