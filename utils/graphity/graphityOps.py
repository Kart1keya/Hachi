import copy
import os

import networkx as nx


### SCANNING ###

# searching nodes and nearby nodes a pattern defined by graphityFunc.py
def patternScan(graphity, pattern):

    # search is performed by defining "anchor" node, where initial pattern is found
    # search then moved from there 1 level up to search surrounding nodes (number of levels could be increased)
    # pattern lists for now are kept rather small
    # TODO determine distance between found patterns to see which functionalities lie close to each other
    patternNum = len(pattern)
    anchorList = []

    allCalls = nx.get_node_attributes(graphity, 'calls')
    #print("AllCalls")
    #print(allCalls)
    for function in allCalls:
        #print("check:" + function)
        # TODO make this prettier!
        for call in allCalls[function]:
            api = call[1]
            anchorpat = pattern[0]
            # print(anchorpat, call[1])
            if anchorpat in api:
                #print("anchor: " + anchorpat)
                if not list([daAnchor for daAnchor in anchorList if daAnchor['address'] == function]):
                    # maintain a dict of patterns per anchor to keep track of found patterns
                    patternCheck = {}
                    for item in pattern:
                        patternCheck[item] = False
                    patternCheck[anchorpat] = function
                    #print(patternCheck)
                    anchorList.append({'address':function, 'patterns':patternCheck})
    # anchor nodes found and more than one pattern searched for
    if patternNum > 1 and len(anchorList) > 0:
        for anchor in anchorList:

            functionalityScanForApi(graphity, anchor, anchor['address'], patternNum)
            if False in list(anchor['patterns'].values()):

                anchorNeighbors = nx.all_neighbors(graphity, anchor['address'])
                for neighbor in anchorNeighbors:
                    functionalityScanForApi(graphity, anchor, neighbor, patternNum)

    return anchorList


# Search for a specific pattern within a node, orient by anchor pattern
def functionalityScanForApi(graphity, anchor, seNode, patternNum):

    for patt in anchor['patterns']:

        # anchor has a dict that saves which patterns were found already
        for call in graphity.node[seNode]['calls']:
            api = call[1]

            # found a pattern in an api call, that hasnt been found before
            if patt in api and anchor['patterns'][patt] == False:
                anchor['patterns'][patt] = seNode

                if not False in list(anchor['patterns'].values()):
                    # all patterns found - done
                    break

# Graph plotting with pydotplus from within NetworkX, format is dot
def graphvizPlot(graphity, filename, function_list, out_dir):
    graphity_new = copy.deepcopy(graphity)
    for aNode in list(graphity_new.nodes(data=True)):
        if aNode[0] not in function_list:
            graphity_new.remove_node(aNode[0])
    pydotMe = nx.drawing.nx_pydot.to_pydot(graphity_new)

    for node in list(pydotMe.get_nodes()):
        #continue
        # get node address to be able to fetch node directly from graphity to preserve data types of attributes
        nodeaddr = node.to_string().split()[0].replace('\"', '')
        finalString = ''

        if str(nodeaddr) not in function_list:
            print("Still Inside")
            continue
        # print("Entered:"+str(nodeaddr))
        if node.get('calls') != '[]' or node.get('strings') != '[]':

            finalList = []

            # fetching string and call lists directly from graphity
            callList = graphity.node[nodeaddr]['calls']
            stringList = graphity.node[nodeaddr]['strings']

            for item in callList:
                finalList.append(str(item[0]) + ": [C] " + str(item[1]))
            for otem in stringList:
                finalList.append(str(otem[0]) + ": [S] " + str(otem[1]))

            finalList.sort()
            finalString = '\n'.join(finalList)
        name = ""
        if str(nodeaddr) in function_list:
            name = str(function_list[str(nodeaddr)])
        if node.get('functiontype') == 'Export':
            label = "Export " + nodeaddr + node.get('alias')
            label = name+ '\n' + label + "\n" + finalString
            node.set_fillcolor('yellow')
            node.set_style('filled,setlinewidth(3.0)')
            node.set_label(label)

        elif node.get('functiontype') == 'Callback':
            label = name+ '\n'+ "Callback " + nodeaddr + "\n" + finalString
            node.set_fillcolor('skyblue')
            node.set_style('filled,setlinewidth(3.0)')
            node.set_label(label)

        elif node.get('functiontype').startswith('Indirect'):
            label = name + '\n'+ "IndirectRef " + nodeaddr + "\n" + finalString
            node.set_fillcolor('red')
            node.set_style('filled,setlinewidth(3.0)')
            node.set_label(label)

        elif finalString != '':
            finalString = name+ '\n'+ nodeaddr + "\n" + finalString
            node.set_fillcolor('orange')
            node.set_style('filled,setlinewidth(3.0)')
            node.set_label(finalString)


    #print(finalString)
    '''graphinfo = "SAMPLE " + allAtts['filename'] + "\nType: " + allAtts['filetype'] + \
                "\nSize: " + str(allAtts['filesize']) + "\nMD5: " + allAtts['md5'] + "\nImphash:\t\t" +\
                allAtts['imphash'] + "\nCompilation time:\t" + allAtts['compilationts'] + "\nEntrypoint section:\t" + \
                allAtts['sectionep']'''


    graphname = filename + ".png"
    print(graphname)
    try:
        # TODO pydotplus throws an error sometimes (Error: /tmp/tmp6XgKth: syntax error in line 92 near '[') look into pdp code to see why
        out_filename = os.path.join(os.path.abspath(out_dir), graphname)
        print(out_filename)
        pydotMe.write_png(out_filename)
    except Exception as e:
        print("ERROR drawing graph")
        print((str(e)))