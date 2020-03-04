import math
import time
import pefile
import struct
from io import open
from hashlib import sha1, md5
from collections import Counter
from os.path import basename, getsize



# receives a string, containing a symbol a la radare2
# returns the sole API name

def gimmeDatApiName(wholeString):
    separators = ['.dll_', '.sys_', '.exe_', '.sym_']

    for sep in separators:

        if sep in wholeString:
            apiName = wholeString.split(sep)[1].replace(']', '')
            return apiName

        elif sep.upper() in wholeString:
            apiName = wholeString.split(sep.upper())[1].replace(']', '')
            return apiName

    return wholeString


# checks whether a string is pure ascii

def is_ascii(myString):
    try:
        myString.decode('ascii')
        return True
    except UnicodeDecodeError:
        return False





def stringCharVariance(seString):
    charFrequs = Counter(seString)
    total = 0
    for letter in charFrequs:
        if charFrequs[letter] < 4:
            total += (charFrequs[letter] - 1)
        elif charFrequs[letter] < 5:
            total += (charFrequs[letter] - 0.75)
        elif charFrequs[letter] < 6:
            total += (charFrequs[letter] - 0.5)
        elif charFrequs[letter] < 7:
            total += (charFrequs[letter] - 0.25)
        else:
            total += charFrequs[letter]

        # print (seString, total)

    return total / float(len(seString) * 2)


# Check for PE header, return false if not a PE
def check_pe_header(filepath):
    try:
        with open(filepath, 'rb') as fp:
            if (fp.read(2) == b'MZ'):
                fp.read(58)
                peoff = struct.unpack('i', fp.read(4))
                advance = peoff[0] - 64
                fp.read(advance)
                if (fp.read(2) == b'PE'):
                    return True
        return False

    except(Exception) as e:
        print("LOG - PE Parsing Error, sure this is a PE file?")
        return False
    return False


# SAMPLE ATTRIBUTE GETTERS

# MD5
# filename
# filetype
# ssdeep
# imphash
# size
# compilationTS
# address of EP
# EP section
# number of section
# original filename
# number TLS sections

def sha1hash(path):
    with open(path, 'rb') as f:
        return sha1(f.read()).hexdigest()


def md5hash(path):
    with open(path, 'rb') as f:
        return md5(f.read()).hexdigest()


def getFilename(path):
    return basename(path)


def getFiletype(path):
    return ""


#	return magic.from_file(path)

def getFilesize(path):
    return getsize(path)


def getPeSubsystem(path):
    pass


def getSsdeep(path):
    return ""  # pydeep.hash_file(path)


def getImphash(pe):
    return pe.get_imphash()


def getCompilationTS(pe):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(pe.FILE_HEADER.TimeDateStamp))


def getEPAddress(pe):
    return pe.OPTIONAL_HEADER.AddressOfEntryPoint


def getSectionCount(pe):
    return pe.FILE_HEADER.NumberOfSections


def getOriginalFilename(pe):
    oriFilename = ""
    if hasattr(pe, 'VS_VERSIONINFO'):
        if hasattr(pe, 'FileInfo'):
            for entry in pe.FileInfo:
                if hasattr(entry, 'StringTable'):
                    for st_entry in entry.StringTable:
                        ofn = st_entry.entries.get(b'OriginalFilename')
                        if ofn:
                            if isinstance(ofn, bytes):
                                oriFilename = ofn.decode()
                            else:
                                oriFilename = ofn
    return oriFilename


def getEPSection(pe):
    name = ''
    if hasattr(pe, 'OPTIONAL_HEADER'):
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    else:
        return False
    pos = 0
    for sec in pe.sections:
        if (ep >= sec.VirtualAddress) and (ep < (sec.VirtualAddress + sec.Misc_VirtualSize)):
            name = sec.Name.replace(b'\x00', b'')
            break
        else:
            pos += 1
    if name:
        return (name.decode('utf-8', 'ignore') + "|" + pos.__str__())
    return ''


def getTLSSectionCount(pe):
    idx = 0
    if (hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS and pe.DIRECTORY_ENTRY_TLS.struct
            and pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks):
        callback_array_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase

        while True:
            func = pe.get_dword_from_data(pe.get_data(callback_array_rva + 4 * idx, 4), 0)
            if func == 0:
                break
            idx += 1
    return idx


# Returns Entropy value for given data chunk
def Hvalue(data):
    if not data:
        return 0.0

    occurences = Counter(bytearray(data))

    entropy = 0
    for x in list(occurences.values()):
        p_x = float(x) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)

    return entropy


def getCodeSectionSize(pe):
    for section in pe.sections:
        print(section)


def getSectionInfo(pe):
    # Section info: names, sizes, entropy vals
    sects = []
    vadd = []
    ent = []
    secnumber = getSectionCount(pe)

    for i in range(12):

        if (i + 1 > secnumber):
            strip = ""
            strap = ""
            entropy = ""

        else:
            stuff = pe.sections[i]
            strip = stuff.Name.replace(b'\x00', b'')
            strap = stuff.SizeOfRawData

            entropy = Hvalue(stuff.get_data())

        section_name = ""
        try:
            if strip != "":
                section_name = strip.decode()
        except:
            section_name = "PARSINGERR"

        sects.append(section_name)
        ent.append(entropy)
        vadd.append(strap)

    secinfo = sects + vadd + ent
    return secinfo


# ATTRIBUTES: md5, sha1, filename, filetype, ssdeep, filesize, imphash, compilationts, addressep, sectionep,
# sectioncount, sectioninfo, tlssections, originalfilename

def getAllAttributes(path):
    allAtts = {'md5': md5hash(path), 'sha1': sha1hash(path), 'filename': getFilename(path),
               'filetype': getFiletype(path), 'ssdeep': getSsdeep(path), 'filesize': getFilesize(path)}

    try:
        pe = pefile.PE(path)
        if (pe.DOS_HEADER.e_magic == int(0x5a4d) and pe.NT_HEADERS.Signature == int(0x4550)):
            allAtts['imphash'] = getImphash(pe)
            allAtts['compilationts'] = getCompilationTS(pe)
            allAtts['addressep'] = getEPAddress(pe)
            allAtts['sectionep'] = getEPSection(pe)
            allAtts['sectioncount'] = getSectionCount(pe)
            allAtts['sectioninfo'] = getSectionInfo(pe)
            allAtts['tlssections'] = getTLSSectionCount(pe)
            allAtts['originalfilename'] = getOriginalFilename(pe)

    except (pefile.PEFormatError):
        allAtts['imphash'] = ''
        allAtts['compilationts'] = ''
        allAtts['addressep'] = ''
        allAtts['sectionep'] = ''
        allAtts['sectioncount'] = ''
        allAtts['sectioninfo'] = ''
        allAtts['tlssections'] = ''
        allAtts['originalfilename'] = ''

    return allAtts
