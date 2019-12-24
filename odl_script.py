import httplib2
import json
import sys
import logging
from subprocess import Popen, PIPE

########################################################################################################
# GLOBAL VARIABLES
########################################################################################################

baseUrl = 'http://83.212.109.225:8181/restconf'
baseIP = '83.212.109.225'
containerName = 'default/'
h = httplib2.Http(".cache")
h.add_credentials('admin', 'admin')

########################################################################################################
# SUPPORT FUNCTIONS
########################################################################################################

def get_all_wrapper(typestring, attribute):
    url = baseUrl + typestring
    logging.debug('url %s', url)
    _,content = h.request(url, "GET")
    allContent = json.loads(content)
    allrows = allContent[attribute]
    if allrows == {}:#check if we have a topology
        print "Topology not found!"
        exit()
    elif allrows == {u'topology': [{u'topology-id': u'flow:1'}]}:
        print "Topology not found!"
        exit()
    return allrows

def systemCommand(cmd):
    terminalProcess = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)
    terminalOutput, stderr = terminalProcess.communicate()


########################################################################################################
# FLOW FUNCTIONS
########################################################################################################

def get_all_flow_stats():
    '''
    Sends an API Request to Controller, returns a list of two lists, one containing 
    flow IDs and the other containing flow stats. 
    '''

    node_list = get_all_wrapper('/operational/opendaylight-inventory:nodes', 'nodes')

    # Initialze Empty List of lists, we will append flow IDs and stats

    list_2_return = [[],[]]

    # For each node, find its table of flows, and if we find any active, push it to the list
    # along with its stats

    try:

        for node in node_list['node']:

            for table in node["flow-node-inventory:table"]:

                if table['opendaylight-flow-table-statistics:flow-table-statistics']['active-flows'] > 0:

                    for flow in table['flow']:

                        if flow['id'] not in list_2_return[1]: # Double check if we find any duplicates

                            list_2_return[0].append(flow['id']) # Append Flow ID to list

                            list_2_return[1].append(flow['opendaylight-flow-statistics:flow-statistics']) # Append Flow Stats
    except:

        # Error Reporting

        print("Error getting flow stats")

        list_2_return = [[],[]]

    # Lastly, return the list of all flows found

    return list_2_return

def get_all_flows_node(nodeid):
    '''
    Returns a list of it's flows of node with given ID. (nodeid)
    '''

    # Get all nodes and their info

    node_list = get_all_wrapper('/operational/opendaylight-inventory:nodes', 'nodes')

    # Initialize empty list of flows_2_return

    flows_2_return = []

    # Find given node's flows, and append them in the flows_2_return

    try:

        for node in node_list['node']:

            if node['id'] == nodeid: # Have we found the node with the given ID?

                for table in node["flow-node-inventory:table"]: # Search all of the flow table

                    if table['opendaylight-flow-table-statistics:flow-table-statistics']['active-flows'] > 0:

                        for flow in table['flow']:

                            flows_2_return.append(flow['id']) # Add each active flow to the list


                break # No need to look at the rest of the nodes

    except:

        # Error Reporting

        print("Error finding flows of given node.")

        flows_2_return = []


    return flows_2_return

def delete_all_flows_node():
    '''
    Deletes all flows in node with given id. Node id is got by keyboard input.
    '''

    # First get the node id

    node_id = raw_input("Enter nodeid:")

    # Make an API call to get all nodes and their info

    node_list = get_all_wrapper('/operational/opendaylight-inventory:nodes', 'nodes')

    # Initialize an empty list (used to store the flows we will delete)

    flows_2_delete = []

    # Intialize empty list of tableids - we can't delete a flow if we dont know its tableid!

    table_of_flows_2_delete = []

    # Now find given node ...

    try:

        for node in node_list['node']:

            if node['id'] == node_id: # Have we found the node with the given ID?

                for table in node["flow-node-inventory:table"]: # Search all of the flow table

                    if table['opendaylight-flow-table-statistics:flow-table-statistics']['active-flows'] > 0:

                        for flow in table['flow']:

                            flows_2_delete.append(flow['id']) # Add flow for deletion

                            table_of_flows_2_delete.append(table['id'])

                break # No need to look at the rest of the nodes

    except:

        # Error Reporting

        print("Error finding flows of given node.")

        flows_2_delete = []

    # Now lets delete all flows of the node

    for i in range(0,len(flows_2_delete)):

        # Prepare command to execute

        command = "curl --noproxy " + baseIP + " -u admin:admin -H 'Content-Type: application/yang.data+xml' -X DELETE " + baseUrl  + "/config/opendaylight-inventory:nodes/node/" + str(node_id)  + "/table/" + str(table_of_flows_2_delete[i]) + "/flow/" + str(flows_2_delete[i])
 
        # Execute API Call

        systemCommand(command)

def delete_all_flows():
    '''
    Deletes all flows in given topology.
    '''

    # First make an API call to get all nodes and their info

    node_list = get_all_wrapper('/operational/opendaylight-inventory:nodes', 'nodes')

    # Initialize empty lists with info on flows to be deleted

    node_ids_of_flows_2_be_deleted = []

    table_ids_of_flows_2_be_deleted = []

    flows_2_delete = []

    # Search the data to find the flows to delete

    try:

        for node in node_list['node']: # For each node

                for table in node["flow-node-inventory:table"]: # For each table in node

                    if table['opendaylight-flow-table-statistics:flow-table-statistics']['active-flows'] > 0:

                        for flow in table['flow']: # For each active flow

                            # Add flow for deletion

                            flows_2_delete.append(flow['id']) 

                            table_ids_of_flows_2_be_deleted.append(table['id'])

                            node_ids_of_flows_2_be_deleted.append(node['id'])

    except:

        # Error Reporting

        print("Error finding all flows.")

        return

    # Now lets delete all of the flows we collected

    for i in range(0,len(flows_2_delete)):

        # Prepare command to execute

        command = "curl --noproxy " + baseIP + " -u admin:admin -H 'Content-Type: application/yang.data+xml' -X DELETE " + baseUrl + "/config/opendaylight-inventory:nodes/node/" + str(node_ids_of_flows_2_be_deleted[i])  + "/table/" + str(table_ids_of_flows_2_be_deleted[i]) + "/flow/" + str(flows_2_delete[i])
 
        # Execute API Call

        systemCommand(command)

def get_all_flows():
    '''
    Sends an API Request to Controller, returns a list of all flow IDs.
    '''

    node_list = get_all_wrapper('/operational/opendaylight-inventory:nodes', 'nodes')

    # Initialze Empty List, we will push every flow we find there

    flow_list = []

    # For each node, find its table of flows, and if we find any active, push it to the list

    try:

        for node in node_list['node']:

            for table in node["flow-node-inventory:table"]:

                if table['opendaylight-flow-table-statistics:flow-table-statistics']['active-flows'] > 0:

                    for flow in table['flow']:

                        if flow['id'] not in flow_list: # Double check if we find any duplicates

                            flow_list.append(flow['id'])
    except: 
        
        # Error Reporting
        
        print("Error getting flows.")

        flow_list = []

    # Lastly, return the list of all flows found

    return flow_list

def print_all_flows():
    '''
    Prints all flows returned by get_all_flows().
    '''

    flow_list = get_all_flows()

    if len(flow_list) > 0:

        for flow in flow_list:
            print(flow)

    else:

        print("No flows were found.")

def print_all_flow_stats():
    '''
    Prints all flow stats returned by get_all_flow_stats().

    '''

    # Get all flows
    
    flow_stats = get_all_flow_stats()

    # Find number of flows

    no_of_flows = len(flow_stats[0])

    # For each flow in the first list, prints it ID and then its stats
    # from the second lis tin flow_lists.
    
    for flow_no in range(0,no_of_flows):

        print("Flow ID: " +  flow_stats[0][flow_no])

        for stat in ("duration","byte-count","packet-count"):

            if stat == "duration":

                print(stat + " : " + str(flow_stats[1][flow_no][stat]['second']) + " s ") + str(flow_stats[1][flow_no][stat]['nanosecond']) + " ms"

            else:

                print(stat + " : " + str(flow_stats[1][flow_no][stat]))

        print("-----------------------------------------")

def print_all_flows_node():
    '''
    Prints all flows returned by get_all_flows_node(nodeid).
    '''

    nodeid = raw_input('Enter nodeid:')

    flow_list = get_all_flows_node(nodeid)

    for flow in flow_list:

        print(flow)

def delete_spec_flow_node():
    '''
    Deletes a flow of given nodeid.Gets nodeid and flowid from user input.
    '''

    # Get user input, node_id & flow_id

    node_id = raw_input('Enter node id:')

    table_id = raw_input('Enter table id:')

    flow_id = raw_input('Enter flow id:')

    try:

        # Make sure table_id and flow_id are integers

        int(table_id)

        int(flow_id)
    
    except:
        
        # Error Reporting

        print("Table ID and Flow Id must be integers.")

        return

    # table_id an flow_id must be positive ints

    if table_id > 0 and flow_id > 0:

        # Prepare API Call

        command = "curl --noproxy " + baseIP  + " -u admin:admin -H 'Content-Type: application/yang.data+xml' -X DELETE " + baseUrl  + "/config/opendaylight-inventory:nodes/node/" + str(node_id)  + "/table/" + str(table_id) + "/flow/" + str(flow_id)
        
        # Send it

        systemCommand(command)

    else:

        print("Table ID and Flow Id must be larger than 0.")

        return

def add_new_flow():
    node_id = raw_input('Enter node id:')
    table_id = raw_input('Enter table id:')
    flow_id = raw_input('Enter flow id:')
    flow_name = raw_input('Enter flow name:')
    try:
        table_id = int(table_id)
        flow_id = int(flow_id)
    except ValueError:
        print "table-id and flow-id must be integers>0"
        exit()
    if(table_id<0 or flow_id<0):
        print "table-id and flow-id must be integers>0"
        exit()
    flowURL = baseUrl + '/config/opendaylight-inventory:nodes/node/'+node_id+'/table/'+str(table_id)+'/flow/'+str(flow_id)
    flow_header = '-H "Content-Type: application/xml" -H "Access: application/xml"'
    flow_xml = '<flow xmlns="urn:opendaylight:flow:inventory"> <priority>500</priority> <flow-name>' + flow_name + '</flow-name> <idle-timeout>12000</idle-timeout> <match> <ethernet-match> <ethernet-type> <type>2048</type> </ethernet-type> </ethernet-match> <ip-match><ip-dscp>28</ip-dscp> </ip-match></match> <id>' + str(flow_id) + '</id> <table_id>' + str(table_id) + '</table_id> <instructions> <instruction> <order>6555</order> </instruction> <instruction> <order>0</order> <apply-actions> <action> <order>0</order> <output-action> <output-node-connector>1</output-node-connector> </output-action> </action> </apply-actions> </instruction> </instructions> </flow>'

    o = open("flow_xml.xml","wb")
    o.write(flow_xml)
    o.close()
    command = 'curl --noproxy ' + baseIP + ' -u admin:admin ' + flow_header + ' -X PUT -d @flow_xml.xml '+ flowURL

    systemCommand(command)
    systemCommand("rm -f flow_xml.xml")

########################################################################################################
# NODE FUNCTIONS
########################################################################################################

def get_all_nodes():
    node_list = get_all_wrapper('/operational/opendaylight-inventory:nodes', 'nodes')
    return node_list

def print_all_nodes():
    node_list = get_all_nodes()
    o = open("node","wb")
    for node in node_list['node']:
        o.write(str(node['id']))
        o.write("\n")
        print(node['id'])
    o.close()

def get_node_stats(nodeid):
    node_list = get_all_nodes()

    for node in node_list['node']:
        if (node['id'] == nodeid):
            return node

    return []

def print_all_node_stats():
    node_list = get_all_nodes()
    o = open("node_stats","wb")
    o.write('{0:22} {1:20} {2:22} {3:22} {4:22} {5:22}'.format('NODE',
    'PORT', 'TXPKTCNT', 'TXBYTES', 'RXPKTCOUNT', 'RXBYTES'))
    o.write("\n")
    print '{0:22} {1:20} {2:22} {3:22} {4:22} {5:22}'.format('NODE',
    'PORT', 'TXPKTCNT', 'TXBYTES', 'RXPKTCOUNT', 'RXBYTES')
    for node in node_list['node']:
        nodeid = node['id']
        for stats in node['node-connector']:
            flowstatpackets = stats['opendaylight-port-statistics:flow-capable-node-connector-statistics']['packets']
            flowstatbytes = stats['opendaylight-port-statistics:flow-capable-node-connector-statistics']['bytes']
            o.write('{0:22} {1:16} {2:10} {3:22} {4:22} {5:22}'.format(nodeid,
            stats['flow-node-inventory:port-number'], flowstatpackets['transmitted'], flowstatbytes['transmitted'],
            flowstatpackets['received'], flowstatbytes['received']))
            o.write("\n")
            print('{0:22} {1:16} {2:10} {3:22} {4:22} {5:22}'.format(nodeid,
            stats['flow-node-inventory:port-number'], flowstatpackets['transmitted'], flowstatbytes['transmitted'],
            flowstatpackets['received'], flowstatbytes['received']))
    o.close()

def print_node_stats():
    nodeid = raw_input('Enter nodeid:')
    node_stats = get_node_stats(nodeid)

    if node_stats == []:
        print("Wrong nodeid")
        exit()

    print ('{0:22} {1:20} {2:22} {3:22} {4:22} {5:22}'.format('NODE',
    'PORT', 'TXPKTCNT', 'TXBYTES', 'RXPKTCOUNT', 'RXBYTES'))

    for stats in node_stats['node-connector']:
        flowstatpackets = stats['opendaylight-port-statistics:flow-capable-node-connector-statistics']['packets']
        flowstatbytes = stats['opendaylight-port-statistics:flow-capable-node-connector-statistics']['bytes']
        print('{0:22} {1:16} {2:10} {3:22} {4:22} {5:22}'.format(nodeid,
        stats['flow-node-inventory:port-number'], flowstatpackets['transmitted'], flowstatbytes['transmitted'],
        flowstatpackets['received'], flowstatbytes['received']))

########################################################################################################
# HOST FUNCTIONS
########################################################################################################

def get_all_hosts():
    host_list = get_all_wrapper('/operational/network-topology:network-topology', 'network-topology')
    return host_list

def print_all_hosts():
    host_list = get_all_hosts()
    hosts = host_list['topology'][0]
    o = open("host","wb")
    for host in hosts['node']:
        maybe_host = host['node-id']
        if(maybe_host.startswith("host")):
            o.write(str(maybe_host))
            o.write("\n")
            print(maybe_host)
    o.close()

def get_all_hosts_node(node_id):
    all_hosts = get_all_hosts()
    hosts = all_hosts['topology'][0]
    host_list=[]
    for host_prop in hosts['link']:
        host_node_id = host_prop['source']['source-node']
        logging.debug('host_node_id %s node_id %s', host_node_id, node_id)
        if (host_node_id == node_id):
            host = host_prop['destination']['dest-node']
            if(host.startswith("host")):
                host_list.append(host)
    return host_list

def print_all_hosts_node():
    nodeid = raw_input('Enter nodeid:')
    host_list = get_all_hosts_node(nodeid)
    # Dump all hosts
    for fs in host_list:
        print(fs)

########################################################################################################
# EDGE FUNCTIONS
########################################################################################################

def get_all_edges():
    all_edges = get_all_wrapper('/operational/network-topology:network-topology', 'network-topology')
    return all_edges


def print_all_edges():
    all_edges = get_all_edges()
    o = open("edge","wb")
    edges = all_edges['topology'][0]
    for edge in edges['link']:
        o.write('['+edge['source']['source-tp']+']'+ ' to ' +'['+edge['destination']['dest-tp']+']')
        o.write("\n")
        print '['+edge['source']['source-tp']+']'+ ' to ' +'['+edge['destination']['dest-tp']+']'
    o.close()

########################################################################################################
# PORT FUNCTIONS
########################################################################################################

def get_node_port_stats(nodeid, port):
    node_stats = get_node_stats(nodeid)
    if node_stats == []:
        return [],1
    for stats in node_stats['node-connector']:
        if stats['flow-node-inventory:port-number'] == port:
            return stats,0
    return [],2

def print_node_port_stats():
    nodeid = raw_input('Enter nodeid:')
    portid = raw_input('Enter port:')
    stats,err = get_node_port_stats(nodeid, portid)

    if stats == []:
        if err == 1:
            print("Wrong node id!")
        else:
            print("Port not found!")
        exit()
    print('{0:22} {1:20} {2:22} {3:22} {4:22} {5:22}'.format('NODE',
        'PORT', 'TXPKTCNT', 'TXBYTES', 'RXPKTCOUNT', 'RXBYTES'))
    flowstatpackets = stats['opendaylight-port-statistics:flow-capable-node-connector-statistics']['packets']
    flowstatbytes = stats['opendaylight-port-statistics:flow-capable-node-connector-statistics']['bytes']
    print('{0:22} {1:16} {2:10} {3:22} {4:22} {5:22}'.format(nodeid,
    portid, flowstatpackets['transmitted'], flowstatbytes['transmitted'],
    flowstatpackets['received'], flowstatbytes['received']))

########################################################################################################
# MENU INTERFACE
########################################################################################################

while(1):

    print("=========================================")

    print('1. Get all switches')
    print('2. Get all hosts')
    print('3. Get all flows')
    print('4. Get all flow stats')
    print('5. Get all Edges in the topology')
    print('6. Get all node stats')
    print('7. Get node stats')
    print('8. Get port stats')
    print('9. Get hosts attached to a node')
    print('10. Get all flows in a node')
    print('11. Delete all flows in a node')
    print('12. Delete all flows')
    print('13. Delete specific flow in a node')
    print('14. Add new flow in specific node')
    print('0. Exit')

    print("=========================================")

    option = raw_input('Enter option needed:')

    print("=========================================")

    if (option == '0'):
        break
    elif (option == '1'):
        print_all_nodes()
    elif (option == '2'):
        print_all_hosts()
    elif (option == '3'):
        print_all_flows()
    elif (option == '4'):
        print_all_flow_stats()
    elif (option == '5'):
        print_all_edges()
    elif (option == '6'):
        print_all_node_stats()
    elif (option == '7'):
        print_node_stats()
    elif (option == '8'):
        print_node_port_stats()
    elif (option == '9'):
        print_all_hosts_node()
    elif (option == '10'):
        print_all_flows_node()
    elif (option == '11'):
        delete_all_flows_node()
    elif (option == '12'):
        delete_all_flows()
    elif (option == '13'):
        delete_spec_flow_node()
    elif (option == '14'):
        add_new_flow()
    else:
        print('Invalid option')
