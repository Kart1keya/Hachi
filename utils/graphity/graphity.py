#!/usr/bin/env python

import re
import json
import r2pipe
import graphityFunc
from time import time
import networkx as nx
from base64 import b64decode
from datetime import datetime
from collections import Counter
from graphityOps import patternScan, graphvizPlot
from graphityUtils import gimmeDatApiName, getAllAttributes, check_pe_header


# Checks whether an address is located in an executable section
def isValidCode(callAddress, sectionsList):
    # sectionsList contains executable sections as 2-element lists, containing start and end of each section
    for execSection in sectionsList:
        if execSection[0] <= int(callAddress, 16) < execSection[1]:
            return True
    return False


# Returns a list of executable sections
def getCodeSections():
    returnSections = []

    # regular expression to pick out the executable section(s)
    execSection = re.compile("perm=....x")

    # will return the section table from radare2
    sections = R2PY.cmd("iS")

    sectionData = {}

    for line in sections.splitlines():
        if re.search(execSection, line):
            for element in line.split():
                items = element.split('=')
                sectionData[items[0]] = items[1]

            start = int(sectionData['vaddr'], 16)
            end = start + int(sectionData['vsz'])
            psize = int(sectionData['sz'])
            returnSections.append([start, end, psize])

    return returnSections


# Returns an executables imports as a list
def getIat():
    iatlist = []
    cmd = "iij"
    iatjson = json.loads(R2PY.cmd(cmd))
    # print(iatjson)
    for item in iatjson:
        iatlist.append(hex(item['plt']))
    return iatlist


# Returns a dictionary of xrefs to symbols
def crossRefScan():
    cmd = "axtj @@ sym.*"
    finalCalls = {}

    # fixing the JSON... issue reported to radare2, keep in mind to remove workaround
    out = R2PY.cmd(cmd)
    out = out.strip("\n")
    temp = out.replace("]", "],")
    temp = temp.replace(",,", ",")
    temp = temp.rstrip("\r\n")
    if temp.endswith(","):
        temp = temp[:-1]
    temp = "[" + temp + "]"
    xrefj = json.loads(temp)
    # TODO check!!

    for xrefitem in xrefj:
        for xreflevel2 in xrefitem:

            # not data xref means its code or call
            if xreflevel2['type'] != 'd':
                finalCalls[hex(xreflevel2['from'])] = xreflevel2['opcode']
                pass

            # data potentially means API referenced by register; please note these are rather uncommon in the long list of symbol refs
            # thus, bottelneck in parsing speed lies in number of refs
            if xreflevel2['type'] == 'd' and (
                    xreflevel2['opcode'].startswith('mov') or xreflevel2['opcode'].startswith('lea')):

                # 'grepping' out the register from mov/lea operation
                register = xreflevel2['opcode'].split()[1].replace(',', '')

                # disassemble downwards; mmmaybe smarter to disassemble until end of function, but possible that there is no function at all
                # TODO find end of function, just in case
                cmd = "pd 300 @ " + hex(xreflevel2['from'])
                moreDisasm = R2PY.cmd(cmd)

                # possible branches towards target
                realCall = "call %s" % register
                aJmp = "jmp %s" % register

                for disasmLine in moreDisasm.splitlines()[1:]:
                    if realCall in disasmLine or aJmp in disasmLine:
                        # found a call!!
                        temp = disasmLine + ";" + xreflevel2['opcode'].split(',')[1].rstrip()
                        tempSplit = temp.split()
                        finalCalls[hex(int(tempSplit[0], 16))] = ' '.join(tempSplit[1:])

                    elif register in disasmLine:
                        # TODO if mov dword abc, reg is found -> follow abc?
                        # TODO could be parsed in more detail, e.g. mov dword, reg won't change the reg
                        # print disasmLine

                        break
                    # pass
    return finalCalls


# Parses the binary for strings and their references to nodes
def stringScan(debugDict):
    # Workflow is: get string, get xrefs to string if any, get functions of xrefs if any; fit node in graph with the string
    allMyStrings = []
    return allMyStrings

    # izzj parses entire binary
    stringCmd = "izzj"
    strings = R2PY.cmd(stringCmd)

    parsedStrings = json.loads(strings)

    debugDict['stringsDangling'] = []
    debugDict['stringsNoRef'] = []

    i = 0
    j = 1
    while i < len(parsedStrings["strings"]):
        stringItem = parsedStrings["strings"][i]

        # Strings when retrieved through izzj command are BASE64 encoded
        thatOneString = b64decode(stringItem['string']).replace(b'\\', b' \\\\ ')
        thatOneString.replace(b'\'', b'')

        try:

            thatOneString = thatOneString.decode()

            xrefCmd = "axtj @ " + hex(stringItem['vaddr'])
            stringXrefsJ = R2PY.cmd(xrefCmd)
            # RN
            stringXrefsJ = stringXrefsJ.replace("\"\"", "\"")
            # print(stringXrefsJ)
            # TODO this should be a list, but is returned as a string now?
            # if stringXrefsJ != []:
            if len(stringXrefsJ) > 2:
                stringXrefs = json.loads(stringXrefsJ)

                # check whether string item is root of list of strings
                j = 1
                lastItem = stringItem
                while (i + j) < len(parsedStrings["strings"]):
                    nextStringItem = parsedStrings["strings"][i + j]
                    lastAddr = lastItem['vaddr']
                    lastSize = lastItem['size']

                    # string offsets are 4 byte aligned, TODO check whether this is always the case
                    padding = 4 - (lastSize % 4)
                    if padding == 4:
                        padding = 0
                    nextAddr = lastAddr + lastSize + padding

                    if nextAddr != nextStringItem['vaddr'] or hasXref(hex(nextStringItem['vaddr'])):
                        # end.. exit here
                        break
                    else:
                        thatOneString = thatOneString + "|" + b64decode(nextStringItem['string']).decode()
                        j = j + 1
                        lastItem = nextStringItem

                # iterate refs on string, if any
                for ref in stringXrefs:

                    # sort out strings with code ref, i.e. non-strings
                    if ref['type'] != 'c' and ref['type'] != 'C':
                        stringAddr = hex(ref['from'])
                        stringFuncRef = gimmeRespectiveFunction(stringAddr)
                        if stringFuncRef != '0x0':
                            allMyStrings.append([stringAddr, stringFuncRef, thatOneString])
                        else:
                            # TODO this is merely still useful strings, see how to fit them in the graphs and db
                            # RN print("DANGLING STRING NO FUNCREF %s %s" % (stringAddr, thatOneString))
                            debugDict['stringsDangling'].append(thatOneString)

            else:
                debugDict['stringsNoRef'].append(thatOneString)


        except UnicodeDecodeError:
            pass
        if j > 1:
            i = i + j
        else:
            i = i + 1

    debugDict['stringsDanglingTotal'] = len(debugDict['stringsDangling'])
    debugDict['stringsNoRefTotal'] = len(debugDict['stringsNoRef'])
    return allMyStrings


# Text whether xrefs exist for given address
def hasXref(vaddr):
    refs = R2PY.cmd("axtj @ " + vaddr)
    if refs:
        return True
    else:
        return False


# Creating the NetworkX graph, nodes are functions, edges are calls or callbacks
def createRawGraph():
    graphity = nx.DiGraph()
    debugDict = {}

    functions = R2PY.cmd("aflj")
    # print("Functions")
    # print(functions)
    # return {},{}
    if functions:
        functionList = json.loads(functions)
    # print json.dumps(functionList, indent=4, sort_keys=True)
    else:
        functionList = []

    # figuring out code section size total
    sectionsList = getCodeSections()
    xlen = 0
    for execSec in sectionsList:
        xlen = xlen + execSec[2]
    debugDict['xsectionsize'] = xlen

    # CREATING THE GRAPH

    refsGlobalVar = 0
    refsUnrecognized = 0
    refsFunc = 0
    debugDict['functions'] = len(functionList)

    ### NetworkX Graph Structure ###

    # FUNCTION as node, attributes: function address, size, calltype, list of calls, list of strings, count of calls; functiontype[Callback, Export], alias (e.g. export name), mnemonic distribution
    # FUNCTIoN REFERENCE as edge (function address -> target address), attributes: ref offset (at)
    # INDIRECT REFERENCE as edge (currently for threads and Windows hooks, also indirect code and indirect data references)
    # API CALLS (list attribute of function node): address, API name
    # STRINGS (list attribute of function node): address, string, evaluation

    ####

    # TODO add count of refs from A to B as weights to edges
    # TODO count calls to global vars, to indirect targets

    for item in functionList:
        # print hex(item['offset'])
        graphity.add_node(hex(item['offset']), size=item['realsz'], calltype=item['calltype'], calls=[], apicallcount=0,
                          strings=[], stringcount=0, functiontype='')

    for item in functionList:

        # TODO look into new values provided by aflj
        # print(item)
        if 'callrefs' in item:
            for xref in item['callrefs']:

                if xref['type'] == 'C':

                    # If an edge is added, that includes a non-existent node, the node will be added, but w/o the necessary attributes
                    # Thasss why we iterate twice, can theoretically be speeded up but needs testing
                    if hex(xref['addr']) in graphity:
                        if item['offset'] != xref['addr']:
                            graphity.add_edge(hex(item['offset']), hex(xref['addr']), pos=hex(xref['at']))
                            refsFunc = refsFunc + 1

                    elif hex(xref['addr']) in getIat():
                        pass

                    elif not isValidCode(hex(xref['addr']), sectionsList):
                        # TODO do something
                        '''print(
                            "DANGLING call to address outside code section, glob var, dynamic API loading %s -> %s" % (
                            hex(item['offset']), hex(xref['addr'])))'''
                        refsGlobalVar = refsGlobalVar + 1

                    else:
                        print(
                                "FAIL: Call to code thats not a function, an import/symbol or otherwise recognized. Missed function perhaps. %s -> %s" % (
                            hex(item['offset']), hex(xref['addr'])))
                        refsUnrecognized = refsUnrecognized + 1

    print('* %s Graph created with NetworkX ' % str(datetime.now()))
    debugDict['refsFunctions'] = refsFunc
    debugDict['refsGlobalVar'] = refsGlobalVar
    debugDict['refsUnrecognized'] = refsUnrecognized

    apiRefs = crossRefScan()

    callNum = len(apiRefs)
    missesNum = 0

    # FITTING GRAPH WITH API REFS

    for call in apiRefs:

        # get the address of the function, that contains the call to a given symbol
        funcAddress = gimmeRespectiveFunction(call)
        # TODO check if funcAddress is the real function address
        if funcAddress in graphity:

            # node(funcAddress) has attribute calls, which contains a list of API calls
            api = gimmeDatApiName(apiRefs[call])

            graphity.node[funcAddress]['calls'].append([call, api])

        # detected API call reference does not resolve to a function offset, insert handling for this here
        else:
            # print("DANGLING API CALL %s %s" % (call, apiRefs[call]))
            missesNum = missesNum + 1

    # debug: print total API refs and functionless API refs, maybe indicator for obfuscated code
    print('* %s Graph extended with API calls, %d calls in total, %d dangling w/o function reference ' % (
        str(datetime.now()), callNum, missesNum))
    debugDict['apiTotal'] = callNum
    debugDict['apiMisses'] = missesNum

    # FITTING GRAPH WITH STRING REFS

    allTheStrings = stringScan(debugDict)
    stringrefs = 0

    for aString in allTheStrings:

        stringAddr = aString[0]
        stringFunc = aString[1]
        stringData = aString[2]

        # add string to respective function node in graph
        if stringFunc in graphity:
            graphity.node[stringFunc]['strings'].append([stringAddr, stringData])
            stringrefs = stringrefs + 1

        else:
            print("\n*** BIG FAIL *** String's function not in graph %s %s" % (stringFunc, stringData))

    print('* %s Graph extended with string references ' % (str(datetime.now())))
    debugDict['stringsReferencedTotal'] = stringrefs

    return graphity, debugDict


# Tag exports of DLLs
# TODO : check whether exports are coming back after bugfix (?)
def analyzeExports(graphity):
    exportsj = json.loads(R2PY.cmd("iEj"))
    for item in exportsj:

        exportAddress = hex(item['vaddr'])
        exportName = item['name']

        exportFunction = gimmeRespectiveFunction(exportAddress)

        if exportFunction in graphity:
            graphity.node[exportFunction]['functiontype'] = 'Export'
            graphity.node[exportFunction]['alias'] = exportName


# Removing thunks as they make my graphs fat, replace by API calls
def thunkPruning(graphity):
    for aNode in graphity.nodes(data=True):

        # most obvious thunks, other thunks exist too, len seen was 11, 13
        # TODO !!!!!!!! check for 64bit
        # TODO check with radare for thunk detection?
        # funclets that contain nothing but a jump to an import, and do not call other functions
        if len(aNode[1]['calls']) == 1 and aNode[1]['size'] == 6 and not graphity.successors(aNode[0]):

            thunk = aNode[0]
            thunkApi = aNode[1]['calls'][0]

            # need to go on with radare from here, cause graphity doesn't know all the addressed of the xrefs to thunks from within a function
            # getting all xrefs on thunk, then getting function its located in to get to node of graph
            temp = R2PY.cmd("axtj " + thunk)

            thunkRefs = []
            if temp:
                thunkRefs = json.loads(temp)

            for aRef in thunkRefs:

                thunkCallAddr = hex(aRef['from'])
                thunkFuncRef = gimmeRespectiveFunction(thunkCallAddr)

                # if thunk's xrefs include a detected function then add thunk as a regular API call to calls list of respective node
                if thunkFuncRef != '0x0':
                    graphity.node[thunkFuncRef]['calls'].append([thunkCallAddr, thunkApi[1]])

            # after xref to thunk has been added to all calling functions, remove thunk node from graph
            graphity.remove_node(thunk)


# Adding edges to indirectly referenced functions, thread handlers and hook functions for now only
def tagCallbacks(graphity):
    for aNode in graphity.nodes(data=True):
        for call in aNode[1]['calls']:

            xrefTarget = ''
            # TODO consider this bad practise, do something smarter, not sure yet what,  consider _beginthread API etc. etc.
            # also, maybe this is fixed in radare later, so consider this code redundant by then
            if 'CreateThread' in call[1]:
                xrefTarget = getCallback(call[0], 3)

            if 'SetWindowsHookEx' in call[1]:
                xrefTarget = getCallback(call[0], 2)

            if xrefTarget:
                #print (xrefTarget, aNode[0])
                addIndirectEdge(graphity, aNode[0], xrefTarget, "apicallback", "Callback")

    # implicitly filters out callbacks fixed already - gets all nodes with zero in-degre
    # TODO see if feasible for all functions, even with such already having in edges
    for aNode in graphity.nodes(data=True):
        if graphity.in_degree(aNode[0]) == 0:
            jay = R2PY.cmd("axtj @ " + aNode[0])
            jay = jay.rstrip()
            if jay:
                xrefs = json.loads(jay)
                for xref in xrefs:

                    # if xref is code its almost certainly an edge to add
                    if xref['type'] == 'c':

                        # TODO circle back on jumptable-as-a-function bug from r2
                        # really ugly workaround, really really ugly..
                        if not 'dword [' in xref['opcode']:
                            addIndirectEdge(graphity, hex(xref['from']), aNode[0], "coderef", "IndirectCode")

                    # if xref is data
                    if xref['type'] == 'd':

                        opcd = xref['opcode']
                        # TODO run more tests on this list not sure these are all possible cases
                        # TODO make datarefs optional!
                        if opcd.startswith('push') or opcd.startswith('lea') or opcd.startswith('mov'):
                            #print (hex(xref['from']), opcd)
                            addIndirectEdge(graphity, hex(xref['from']), aNode[0], "dataref", "IndirectData")
                        else:
                            # TODO look into add reg, ThreadRoutine -> as xref
                            print ("up for discussion: " + hex(xref['from']), xref['type'], xref['opcode'])


def addIndirectEdge(graphity, fromAddr, toAddr, calltype, functiontype):
    fromNode = gimmeRespectiveFunction(fromAddr)
    toNode = gimmeRespectiveFunction(toAddr)
    if fromNode in graphity and toNode in graphity:
        graphity.node[toNode]['functiontype'] = functiontype
        graphity.add_edge(fromNode, toNode, calltype=calltype)
        # print ("added callback edge", fromNode, toNode, calltype, "\n")
    else:
        print ("Something went wrong with indirect edge ", fromAddr, toAddr, calltype)


# Parsing the handler offset out of the function arguments
def getCallback(call, argcount):
    # simplistic: walk up the code until xref to code is found, works as long as API only receives one code ref, works well with Windows APIs
    disasmMore = "pd -30 @" + call
    upwards = R2PY.cmd(disasmMore)

    for otherLine in reversed(upwards.splitlines()):
        if 'push' in otherLine:
            argcount = argcount - 1

        # TODO better done with a regex, bug prone
        if not argcount:
            address = otherLine.split("push", 1)[1].split()[0]
            if 'fcn.' in address:
                return hex(int(address.split('.')[1], 16))
            if '0x' in address:
                return hex(int(address.split('0x')[1], 16))
            else:
                return ''


# WORKAROUND until function detection - bug? feature? in radare is fixed and export vaddr equal actual offsets again
def gimmeRespectiveFunction(address):
    if address:
        return R2PY.cmd("?v $FB @ " + address).strip("\r\n").strip("\n").strip("\r")
    return ''


def mnemonicism(offset):
    mnems = []
    fsize = 0
    weight = 0

    funcdump = R2PY.cmd("pdfj @ " + offset)
    if funcdump:
        dumpj = json.loads(funcdump)
        for item in dumpj["ops"]:
            # print(item)
            if "type" in item:
                mnems.append(item["type"])
        # print (item["type"], item["opcode"])
        fsize = dumpj["size"]

    # print ("\n" + offset + " " + str(fsize))
    mnemdict = Counter(mnems)
    # for mnem in sorted(mnemdict):
    #	print (mnem, mnemdict[mnem])

    for mnem in mnemdict:
        if mnem in ['shl', 'shr', 'mul', 'div', 'rol', 'ror', 'sar', 'load', 'store']:
            weight += mnemdict[mnem]
    return (weight * 10) / fsize


# TODO count how many above certain threshold, see how close they are together in the graph?


# super graph creation function, radare-analyses the sample, puts together all of the graph and debug info
def graphMagix(filepath, allAtts, deactivatecache):
    global R2PY

    print('* %s R2 started analysis ' % str(datetime.now()))

    BENCH['r2_start'] = time()
    print("filepath:" + filepath)

    R2PY = r2pipe.open(filepath)

    R2PY.cmd("e asm.lines = false")
    R2PY.cmd("e asm.fcnlines = false")
    R2PY.cmd("e anal.autoname= false")
    R2PY.cmd("e anal.jmptbl = true")
    R2PY.cmd("e anal.hasnext = true")
    R2PY.cmd("e anal.bb.maxsize = 1M")
    # R2PY.cmd("e src.null = true")
    R2PY.cmd("aaa")
    # R2PY.cmd("afr")
    # R2PY.cmd("afr @@ sym*")


    BENCH['r2_end'] = time()
    print('* %s R2 finished analysis' % str(datetime.now()))

    # GRAPH CREATION
    graphity, debug = createRawGraph()

    # TODO testing lib code detected
    # flagLibraryCode(graphity)

    # DLL PROCESSING
    if 'DLL' in allAtts['filetype']:
        analyzeExports(graphity)

    # Thunk pruning, thunks are unnecessary information in the graph
    thunkPruning(graphity)

    # handler tagging
    tagCallbacks(graphity)

    # update api and string count attributes
    for aNode in graphity.nodes(data=True):
        aNode[1]['apicallcount'] = len(aNode[1]['calls'])
        aNode[1]['stringcount'] = len(aNode[1]['strings'])

    # calc mnemonic dist
    for aNode in graphity.nodes():
        graphity.node[aNode]['mnemonicism'] = mnemonicism(aNode)

    BENCH['graph_end'] = time()


    return graphity, debug


def get_behaviors(filepath, dst_file, out_dir):
    global BENCH
    BENCH = {}

    behaviours = {}
    if check_pe_header(filepath):
        print('* %s Parsing %s ' % (str(datetime.now()), filepath))
        allAtts = getAllAttributes(filepath)
        graphity, debug = graphMagix(filepath, allAtts, True)  # args.deactivatecache)

        # BEHAVIOR
        print('* %s Scanning for API patterns ' % str(datetime.now()))
        BENCH['behavior_start'] = time()
        allThePatterns = graphityFunc.funcDict

        for patty in allThePatterns:
            # print(patty)
            findings = patternScan(graphity, allThePatterns[patty])
            # print("Findings:")
            # print(findings)
            for hit in findings:
                if not False in hit['patterns'].values():
                    #print("For %s found %s" % (patty, str(hit['patterns'])))
                    if patty in behaviours:
                        list_hit = behaviours[patty]
                        list_hit.append(hit['patterns'])
                        behaviours[patty] = list_hit
                    else:
                        behaviours[patty] = [hit['patterns']]
        BENCH['behavior_end'] = time()

    ret_info = {}
    function_list = {}
    # print("printing behaviors found above")
    if behaviours:
        for behav in behaviours:
            info = behaviours[behav]
            # print(info)
            for entry in info:
                for name in entry:
                    if not str(entry[name]) in function_list:
                        function_list[str(entry[name])] = behav
                        # print(entry)
                        # print function_list

        base_file = dst_file.replace(".behav.json", "")
        for funct in function_list:
            R2PY.cmd("s." + funct)
            pseudo_code = R2PY.cmd("pdc")
            code_file = base_file + "." + function_list[funct] + "_" + funct + ".c"
            with open(code_file, "w") as out:
                for line in pseudo_code.split("\n"):
                    line = line.rstrip()
                    if line:
                        out.write(line + "\n")

        # print(function_list)
        ret_info["Suspicious Behaviors"] = behaviours
        with open(dst_file, "w") as out:
            out.write(json.dumps(ret_info, sort_keys=True, indent=4))

    print('* %s Plotting routine starting ' % str(datetime.now()))
    BENCH['plotting_start'] = time()
    graphvizPlot(graphity, allAtts, function_list, out_dir)
    BENCH['plotting_end'] = time()
    print('* %s Plotting routine finished ' % str(datetime.now()))

    return ret_info
