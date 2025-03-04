#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name


Table = {}
VLAN = {} # table with contains the vlan name and the type of the interface
state = {} # table with the state of the interface LISTENING, BLOCKING
type = {} # table with the type of the interface ROOT, DESIGNATED
def is_unicast(mac):
    first = int(mac.split(":")[0], 16)
    is_unicast = first & 1 == 0
    return is_unicast

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id


def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def send_bdpu_every_sec():
    global own_bridge_ID
    global root_bridge_ID
    while True:
        # Dacă switch-ul curent este root
        if own_bridge_ID == root_bridge_ID:
            # Parcurge toate interfețele și trimite BPDU pe porturile trunk
            for i in range(0, len(VLAN)):
                if VLAN[get_interface_name(i)] == 'T':
                    bpdu = create_new_bpdu(i)
                    send_to_link(i, len(bpdu), bpdu)

        # Așteaptă o secundă înainte de următoarea iterație
        time.sleep(1)

def read_info_file(switch_id):
    file = f'configs/switch{switch_id}.cfg'
    with open(file, 'r') as f:
        lines = f.readlines()
        
       # first line is the priority of the switch
        priority = int(lines[0].strip())
        global own_bridge_ID 
        own_bridge_ID = priority
        
    
    # Parsing the VLAN and trunk information
    for line in lines[1:]:
        vlan, trunk = line.split()
        VLAN[vlan] = trunk
       


def create_new_bpdu(port_id):
    dest_mac = b'\x01\x80\xc2\x00\x00\x00'
    src_mac = get_switch_mac()
    
 
    global own_bridge_ID
    global root_path_cost

    bpdu_config = struct.pack('!B8sI8sHHHHH',
                                0x00,
                                own_bridge_ID.to_bytes(8, byteorder='big'),
                                root_path_cost,
                                own_bridge_ID.to_bytes(8, byteorder='big'),
                                port_id,
                                0x0000,
                                0x0000,
                                0x0000,
                                0x0000)
    bpdu = dest_mac +src_mac +  struct.pack('!H', 0x0026) + struct.pack('!BBB', 0x42, 0x42, 0x03) +  struct.pack('!HBB', 0X0000, 0X00, 0X00) + bpdu_config
    return bpdu
def multicast_trunk_number(i, interface, data, length, vlan_id):
    # Retrieve VLAN IDs for source and destination interfaces
    vlan_id_received = VLAN[get_interface_name(interface)]
    vlan_id_destination = VLAN[get_interface_name(i)]
    
    # Determine whether to add or remove VLAN tags based on interface types
    if vlan_id_received != 'T' and vlan_id_destination == 'T':
        # Access to Trunk: Add VLAN tag
        header_data = data[0:12] + create_vlan_tag(int(vlan_id_received)) + data[12:]
        length += 4
        send_to_link(i, length, header_data)
    elif (vlan_id_received != 'T' and vlan_id_destination == vlan_id_received) or (vlan_id_received == 'T' and vlan_id_destination == 'T'):
        # Access to Access or Trunk to Trunk: Forward as is
        send_to_link(i, length, data)
    elif vlan_id_received == 'T' and int(vlan_id_destination) == vlan_id:
        # Trunk to Access: Remove VLAN tag
        no_header_data = data[0:12] + data[16:]
        length -= 4
        send_to_link(i, length, no_header_data)

def unicast_trunk_number(interface, dest_mac, data, length, vlan_id):
    # Retrieve VLAN IDs for source and destination interfaces
    vlan_id_received = VLAN[get_interface_name(interface)]
    vlan_id_destination = VLAN[get_interface_name(Table[dest_mac])]
    
    # Determine whether to add or remove VLAN tags based on interface types
    if vlan_id_received != 'T' and vlan_id_destination == 'T':
        # Access to Trunk: Add VLAN tag
        header_data = data[0:12] + create_vlan_tag(int(vlan_id_received)) + data[12:]
        length += 4
        send_to_link(Table[dest_mac], length, header_data)
    elif (vlan_id_received != 'T' and vlan_id_destination == vlan_id_received) or (vlan_id_received == 'T' and vlan_id_destination == 'T'):
        # Access to Access or Trunk to Trunk: Forward as is
        send_to_link(Table[dest_mac], length, data)
    elif vlan_id_received == 'T' and int(vlan_id_destination) == vlan_id:
        # Trunk to Access: Remove VLAN tag
        no_header_data = data[0:12] + data[16:]
        length -= 4
        send_to_link(Table[dest_mac], length, no_header_data)
   

def parse_bpdu(bpdu):
    return {
        'root_ID': int.from_bytes(bpdu[1:9], byteorder='big'),
        'root_path_cost': int.from_bytes(bpdu[9:13], byteorder='big'),
        'bridge_ID': int.from_bytes(bpdu[13:21], byteorder='big')
    }

def update_root_port_state(interface):
    global state
    if state[interface] == "BLOCKING":
        state[interface] = "LISTENING"

def send_bpdu_to_interfaces(interfaces, interface, bpdu):
    for i in interfaces:
        if VLAN[get_interface_name(i)] == 'T' and i != interface:
            send_to_link(i, len(bpdu), bpdu)

def stp_implementation(interface, interfaces, data):
    global own_bridge_ID, root_bridge_ID, root_path_cost, state, type

    bpdu = parse_bpdu(data[21:52])
    
    # Check for a better root bridge
    if bpdu['root_ID'] < root_bridge_ID:
        if root_bridge_ID == own_bridge_ID:
            # Update all interfaces to BLOCKING if we were the root
            for i in interfaces:
                if VLAN[get_interface_name(i)] == 'T' and i != interface:
                    state[i] = "BLOCKING"

        root_bridge_ID = bpdu['root_ID']
        root_path_cost = bpdu['root_path_cost'] + 10
        type[interface] = "ROOT"
        update_root_port_state(interface)
        send_bpdu_to_interfaces(interfaces, interface, create_new_bpdu(interface))

    elif bpdu['root_ID'] == root_bridge_ID:
        if type[interface] == "ROOT" and bpdu['root_path_cost'] + 10 < root_path_cost:
            root_path_cost = bpdu['root_path_cost'] + 10
        elif type[interface] != "ROOT":
            if bpdu['root_path_cost'] > root_path_cost and type[interface] != "DESIGNATED":
                type[interface] = "DESIGNATED"
                state[interface] = "LISTENING"

    # Block the interface if this bridge is the sender
    if bpdu['bridge_ID'] == own_bridge_ID:
        state[interface] = "BLOCKING"

    # Update all trunk ports to DESIGNATED if this is the root bridge
    if own_bridge_ID == root_bridge_ID:
        for i in interfaces:
            if VLAN[get_interface_name(i)] == 'T':
                type[i] = "DESIGNATED"



def main(): 
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]
    
    read_info_file(switch_id)
    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    

    # Create and start a new thread that deals with sending BDPU
   
    for i in interfaces:
        state[i] = "LISTENING"

    for i in interfaces:
        if VLAN[get_interface_name(i)] == 'T':
            state[i] = "BLOCKING"
    global own_bridge_ID 
    global root_bridge_ID 
   
    global root_path_cost 
    root_path_cost = 0
    root_bridge_ID = own_bridge_ID

    
    if own_bridge_ID == root_bridge_ID:
        for i in interfaces:
            if VLAN[get_interface_name(i)] == 'T':
                state[i] = "LISTENING"  
                 # porturi cu costul cel mai mic
                type[i] = "DESIGNATED" 

    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()
    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()
        dest_mac = data[0:6]
      
        if dest_mac == b'\x01\x80\xc2\x00\x00\x00':
            stp_implementation(interface, interfaces, data)


        else:
            dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        
            
            dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
            src_mac = ':'.join(f'{b:02x}' for b in src_mac)

           


            Table[src_mac] = interface
                # we have a UNICAST FRAME and WE KNOW WHERE TO SEND it + ADD LISTENING
            if is_unicast(dest_mac) and dest_mac in Table and state[Table[dest_mac]] == "LISTENING": 
                    unicast_trunk_number(interface, dest_mac, data, length, vlan_id)
    

            else:
                for output_interface in interfaces:
                    if output_interface != interface and state[output_interface] == "LISTENING":
                        multicast_trunk_number(output_interface, interface, data, length, vlan_id)
                
        
     

        # data is of type bytes.
        # send_to_link(i, length, data)

if __name__ == "__main__":
    main()