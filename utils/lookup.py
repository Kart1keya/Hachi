import os
import sqlite3
from OTXv2 import OTXv2
from .config import Config
from . import get_malicious
from spam_lists.clients import SPAMHAUS_ZEN, SPAMHAUS_DBL, HpHosts

opts = Config().read_config()

API_KEY = opts["config"]["API_KEY"]
OTX_SERVER = opts["config"]["OTX_SERVER"]
otx = OTXv2(API_KEY, server=OTX_SERVER)
domain_whitelist = opts["config"]["DOMAIN_WHITELIST"]
print("OTX object created")

def check_whitelist(indicator):
    with open(domain_whitelist, 'r') as fp:
        lines = fp.readlines()
        for line in lines:
            if indicator.lower() == line.strip("\r\n").lower():
                return True
    
    return False

def alienvault_otx(tag, indicator):
    #print(tag)
    alerts = []
    if not check_whitelist(indicator):
        if tag == "IP":
            alerts = get_malicious.ip(otx, indicator)
        if tag == "domain":
            alerts = get_malicious.hostname(otx, indicator)
        if tag == "URL":
            alerts = get_malicious.url(otx, indicator)
        if tag == "hash":
            alerts = get_malicious.file(otx, indicator)
    
    return alerts

def hphosts_spamhaus(indicator):
    result = []
    try:
        if not check_whitelist(indicator):
            hpHost = HpHosts('spam-lists-test-suite')
            if hpHost.lookup(indicator) is not None:
                result.append('HpHost')
            if SPAMHAUS_DBL.lookup(indicator) is not None:
                result.append('SPAMHAUS')
            if SPAMHAUS_ZEN.lookup(indicator) is not None:
                result.append('SPAMHAUS_ZEN')

            # Return list of tags where dns is found
    except:
        pass
    return result    
    
if __name__ == '__main__':
    print(hphosts_spamhaus('facebook.com'))
    print(alienvault_otx("hash", '76ce130d2447f71bea8ed902959fd7e0aeac86b55f9e44a327c1f1c1bd73ba3f'))