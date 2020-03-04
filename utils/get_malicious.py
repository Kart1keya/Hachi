#!/usr/bin/env python

import IndicatorTypes

# Get a nested key from a dict, without having to do loads of ifs
def getValue(results, keys):
    if type(keys) is list and len(keys) > 0:

        if type(results) is dict:
            key = keys.pop(0)
            if key in results:
                return getValue(results[key], keys)
            else:
                return None
        else:
            if type(results) is list and len(results) > 0:
                return getValue(results[0], keys)
            else:
                return results
    else:
        return results

def hostname(otx, hostname):
    try:
        alerts = []
        result = otx.get_indicator_details_by_section(IndicatorTypes.HOSTNAME, hostname, 'general')


        # Return nothing if it's in the whitelist
        validation = getValue(result, ['validation'])
        if not validation:
            pulses = getValue(result, ['pulse_info', 'pulses'])
            if pulses:
                for pulse in pulses:
                    if 'name' in pulse:
                        alerts.append({pulse['id']: pulse['name']})

        result = otx.get_indicator_details_by_section(IndicatorTypes.DOMAIN, hostname, 'general')
        # Return nothing if it's in the whitelist

        validation = getValue(result, ['validation'])
        if not validation:
            pulses = getValue(result, ['pulse_info', 'pulses'])
            if pulses:
                for pulse in pulses:
                    if 'name' in pulse:
                        alerts.append({pulse['id']: pulse['name']})
    except Exception as e:
        print(e)
        pass

    return alerts


def ip(otx, ip):
    alerts = []
    try:
        result = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, ip, 'general')

        # Return nothing if it's in the whitelist
        validation = getValue(result, ['validation'])
        if not validation:
            pulses = getValue(result, ['pulse_info', 'pulses'])
            if pulses:
                for pulse in pulses:
                    if 'name' in pulse:
                        alerts.append({pulse['id']: pulse['name']})
    except Exception as e:
        print(e)
        pass

    return alerts



def url(otx, url):
    alerts = []
    try:
        result = otx.get_indicator_details_by_section(IndicatorTypes.URL, url, 'general')
        validation = getValue(result, ['validation'])
        if not validation:
            pulses = getValue(result, ['pulse_info', 'pulses'])
            if pulses:
                for pulse in pulses:
                    if 'name' in pulse:
                        alerts.append({pulse['id']: pulse['name']})
    except Exception as e:
        print(e)
        pass

    return alerts

def file(otx, hash):

    alerts = {}
    av_alerts = []
    pulse_alerts = []
    hash_type = IndicatorTypes.FILE_HASH_MD5
    if len(hash) == 64:
        hash_type = IndicatorTypes.FILE_HASH_SHA256
    if len(hash) == 40:
        hash_type = IndicatorTypes.FILE_HASH_SHA1
    result = otx.get_indicator_details_full(hash_type, hash)

    if result:
        avg = getValue( result, ['analysis','analysis','plugins','avg','results','detection'])
        if avg:
            av_alerts.append({'avg': avg})

        clamav = getValue( result, ['analysis','analysis','plugins','clamav','results','detection'])
        if clamav:
            av_alerts.append({'clamav': clamav})

        avast = getValue( result, ['analysis','analysis','plugins','avast','results','detection'])
        if avast:
            av_alerts.append({'avast': avast})

        microsoft = getValue( result, ['analysis','analysis','plugins','cuckoo','result','virustotal','scans','Microsoft','result'])
        if microsoft:
            av_alerts.append({'microsoft': microsoft})

        symantec = getValue( result, ['analysis','analysis','plugins','cuckoo','result','virustotal','scans','Symantec','result'])
        if symantec:
            av_alerts.append({'symantec': symantec})

        kaspersky = getValue( result, ['analysis','analysis','plugins','cuckoo','result','virustotal','scans','Kaspersky','result'])
        if kaspersky:
            av_alerts.append({'kaspersky': kaspersky})

        suricata = getValue( result, ['analysis','analysis','plugins','cuckoo','result','suricata','rules','name'])
        if suricata and 'trojan' in str(suricata).lower():
            av_alerts.append({'suricata': suricata})
        
        validation = getValue(result, ['general', 'validation'])
        if not validation:
            pulses = getValue(result, ['general', 'pulse_info', 'pulses'])
            if pulses:
                for pulse in pulses:
                    if 'name' in pulse:
                        pulse_alerts.append({pulse['id']: pulse['name']})

        if len(av_alerts) > 0:
            alerts["AV Detections"] = av_alerts
        if len(pulse_alerts) > 0:
            alerts["Pulse Alerts"] = pulse_alerts

    return alerts
