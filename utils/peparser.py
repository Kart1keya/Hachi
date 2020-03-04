#!/usr/bin/env python
import os
import time
import zlib
import string
import pefile
import hashlib

Win32 = False
Win64 = False
isDll = False
Highlights = list()


def hashes(data, algo="sha256"):
  if not data:
    return None
  algo = algo.lower()
  if algo == "crc32":
    return int("%d" % (zlib.crc32(data) & 0xffffffff))
  elif algo == "adler32":
    return "%d" % (zlib.adler32(data) & 0xffffffff)
  elif algo == "md5":
    hasher = hashlib.md5()
  elif algo == "sha128":
    hasher = hashlib.sha1()
  elif algo == "sha224":
    hasher = hashlib.sha224()
  elif algo == "sha256":
    hasher = hashlib.sha256()
  elif algo == "sha384":
    hasher = hashlib.sha384()
  elif algo == "sha512":
    hasher = hashlib.sha512()
  else:
    return None

  hasher.update(data)
  return hasher.hexdigest()


def get_metadata(filename, pe):
  metadata = dict()
  metadata["size"] = os.path.getsize(filename)
  metadata["imphash"] = pe.get_imphash()
  with open(filename, "rb") as f:
    filedata = f.read()
    metadata["crc32"] = hashes(data=filedata, algo="crc32")
    metadata["md5"] = hashes(data=filedata, algo="md5")
    metadata["sha128"] = hashes(data=filedata, algo="sha128")
    metadata["sha256"] = hashes(data=filedata, algo="sha256")
    metadata["ssdeep"] = hashes(data=filedata, algo="ssdeep")
  return metadata


def get_imagefileheader(pe):
  global Win32, Win64, isDll
  imagefileheader = dict()
  imagefileheader["Machine"] = hex(pe.FILE_HEADER.Machine if pe and hasattr(pe, "FILE_HEADER") and pe.FILE_HEADER and
                                                             hasattr(pe.FILE_HEADER, "Machine") and pe.FILE_HEADER.Machine else 0)
  imagefileheader["NumberOfSections"] = hex(pe.FILE_HEADER.NumberOfSections if pe and hasattr(pe, "FILE_HEADER") and
                                                                               pe.FILE_HEADER and
                                                                               hasattr(pe.FILE_HEADER, "NumberOfSections") and pe.FILE_HEADER.NumberOfSections else 0)
  imagefileheader["TimeDateStamp"] = pe.FILE_HEADER.TimeDateStamp if pe and hasattr(pe, "FILE_HEADER") and pe.FILE_HEADER and hasattr(pe.FILE_HEADER, "TimeDateStamp") and pe.FILE_HEADER.TimeDateStamp else 0
  if imagefileheader["TimeDateStamp"] != 0:
    pe_year = int(time.ctime(imagefileheader["TimeDateStamp"]).split()[-1])
    this_year = int(time.gmtime(time.time())[0])
    if pe_year > this_year or pe_year < 2000:
      Highlights.append("TimeDateStamp of the file is Suspicious.")   
    imagefileheader["TimeDateStamp"] = time.ctime(imagefileheader["TimeDateStamp"])
  else:
    Highlights.append("TimeDateStamp of the file is zero.")
  imagefileheader["Characteristics"] = pe.FILE_HEADER.Characteristics if pe and hasattr(pe, "FILE_HEADER") and pe.FILE_HEADER and hasattr(pe.FILE_HEADER, "Characteristics") and pe.FILE_HEADER.Characteristics else 0
  if (imagefileheader["Characteristics"] & 0x0100) == 0x0100:
    Win32 = True
  elif (imagefileheader["Characteristics"] & 0x0020) == 0x0020:
    Win64 = True
  if (imagefileheader["Characteristics"] & 0x2000) == 0x2000:
    isDll = True
  imagefileheader["Characteristics"] = hex(imagefileheader["Characteristics"])
  return imagefileheader


def get_imageoptionalheader(pe):
  global Win32, Win64, isDll
  imageoptionalheader = dict()
  imageoptionalheader["Magic"] = hex(pe.OPTIONAL_HEADER.Magic if pe and hasattr(pe, "OPTIONAL_HEADER") and pe.OPTIONAL_HEADER and hasattr(pe.OPTIONAL_HEADER, "Magic") and pe.OPTIONAL_HEADER.Magic else 0)
  imageoptionalheader["AddressOfEntryPoint"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint if pe and hasattr(pe, "OPTIONAL_HEADER") and pe.OPTIONAL_HEADER and hasattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint") else 0)
  if pe and hasattr(pe, "OPTIONAL_HEADER") and pe.OPTIONAL_HEADER and hasattr(pe.OPTIONAL_HEADER, "CheckSum"):
    if pe.OPTIONAL_HEADER.CheckSum == 0:
      imageoptionalheader["CheckSum"] = pe.OPTIONAL_HEADER.CheckSum      
    else:
      imageoptionalheader["CheckSum"] = hex(pe.OPTIONAL_HEADER.CheckSum)
  else:
    imageoptionalheader["CheckSum"] = None
  imageoptionalheader["Subsystem"] = pe.OPTIONAL_HEADER.Subsystem if pe and hasattr(pe, "OPTIONAL_HEADER") and pe.OPTIONAL_HEADER and hasattr(pe.OPTIONAL_HEADER, "Subsystem") and pe.OPTIONAL_HEADER.Subsystem else None
  bitVal = None
  if Win32:
    bitVal = "Win32"
  elif Win64:
    bitVal = "Win64"
  if isDll:
    file_type = "DLL"
  else:
    file_type = "EXE"
  if imageoptionalheader["Subsystem"] == 0x03:
    Highlights.append("The file being analysed is a Portable executable file! More sepecifically, it is a "+bitVal+" "+file_type+" file for the Windows Console Subsystem.")
  elif imageoptionalheader["Subsystem"] == 0x02:
    Highlights.append("The file being analysed is a Portable executable file! More sepecifically, it is a "+bitVal+" "+file_type+" file for the Windows GUI Subsystem.")
  elif imageoptionalheader["Subsystem"] == 0x01:
    Highlights.append("The file being analysed is a Portable executable file! More sepecifically, it is a "+bitVal+" "+file_type+" file for the Windows Native Subsystem.")
  
  imageoptionalheader["DllCharacteristics"] = hex(pe.OPTIONAL_HEADER.DllCharacteristics if pe and hasattr(pe, "OPTIONAL_HEADER") and pe.OPTIONAL_HEADER and hasattr(pe.OPTIONAL_HEADER, "DllCharacteristics") and pe.OPTIONAL_HEADER.DllCharacteristics else 0)
  return imageoptionalheader


def get_imagesections(pe):
  if len(pe.sections):
    imagesections = list()
    for section in pe.sections:
      if section and hasattr(section, "Characteristics") and section.Characteristics:
        perms = list()
        perms += "R" if section.Characteristics & 0x40000000 else "-"
        perms += "W" if section.Characteristics & 0x80000000 else "-"
        perms += "X" if section.Characteristics & 0x20000000 else "-"
        perms = "".join(perms)
      else:
        perms = None
      imagesections.append({
        #"Name": "".join([c for c in section.Name if c in string.printable]),
        "Name": section.Name.decode('utf-8'),
        "VirtualSize": hex(section.Misc_VirtualSize if section and hasattr(section, "Misc_VirtualSize") and
                                                       section.Misc_VirtualSize else 0),
        "SizeOfRawData": hex(section.SizeOfRawData if section and hasattr(section, "SizeOfRawData") and
                                                      section.SizeOfRawData else 0),
        "entropy": section.get_entropy(),
        "permissions": perms,
      })
  else:
    imagesections = None
  return imagesections


def parse(filename):
  peparsed = dict()
  pe = pefile.PE(filename)
  peparsed["metadata"] = get_metadata(filename, pe)
  peparsed["IMAGE_FILE_HEADER"] = get_imagefileheader(pe)
  peparsed["IMAGE_OPTIONAL_HEADER"] = get_imageoptionalheader(pe)
  peparsed["IMAGE_SECTIONS"] = get_imagesections(pe)
  return peparsed


