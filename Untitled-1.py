#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name


Table = {}
VLAN = {} #tabla ce retine numele interfetei si tipul ei: numar/trunk
state = {} #tabla ce retine starea interfetelor BLOCKING/LISTENING
type = {}
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
                if VLAN[i] == 'T':
                    bpdu = create_new_bpdu(i)
                    send_to_link(i, len(bpdu), bpdu)

        # Așteaptă o secundă înainte de următoarea iterație
        time.sleep(1)

def read_info_file(switch_id):
    file = f'configs/switch{switch_id}.cfg'
    with open(file, 'r') as f:
        lines = f.readlines()
        # Prima linie conține prioritatea
        priority = int(lines[0].strip())
        global prio 
        prio = priority
    for line in lines[1:]:
        # Liniile următoare conțin informații despre vlanuri
        vlan, trunk = line.split()
        VLAN[vlan] = trunk
def create_new_bpdu(port_id):
    dest_mac = b'\x01\x80\xc2\x00\x00\x00'
    src_mac = get_switch_mac()
    
    llc_length = struct.pack('!H', 0x0026)
    llc_header = struct.pack('!BBB', 0x42, 0x42, 0x03)

    bpdu_header = struct.pack('!HBB', 0X0000, 0X00, 0X00)
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
    bpdu = dest_mac +src_mac + llc_length + llc_header + bpdu_header + bpdu_config
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
   


def main(): 
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]
    
    read_info_file(switch_id)
    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()
    for i in interfaces:
        state[i] = "LISTENING"
    
    # Printing interface names
    for i in interfaces:
        if VLAN[get_interface_name(i)] == 'T':
            state[i] = "BLOCKING"
    global own_bridge_ID 
    own_bridge_ID = prio
    global root_bridge_ID 
    root_bridge_ID = prio
    global root_path_cost 
    root_path_cost = 0

    if own_bridge_ID == root_bridge_ID:
        for i in interfaces:
            if VLAN[get_interface_name(i)] == 'T':
                state[i] = "LISTENING"  
                 # porturi cu costul cel mai mic
                type[i] = "DESIGNATED" 

    is_bpdu = False
    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()
        dest_mac = data[0:6]
        if dest_mac == '01:80:c2:00:00:00':
            is_bpdu = True
        if is_bpdu:
            dest_mac, src_mac, llc_length, llc_header, bpdu_header, bpdu_config = struct.unpack('!6s6sH3sI31s', data[:52])
            dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
            src_mac = ':'.join(f'{b:02x}' for b in src_mac)

            
            flag, bpdu_root_bridge_ID, bpdu_root_path_cost, bpdu_bridge_id, port_id, message_age, mex_age, hello_time, forward_delay = struct.unpack('!B8sI8sHHHHH', bpdu_config[:38])
            bpdu_root_bridge_ID = int.from_bytes(bpdu_root_bridge_ID, byteorder='big')
            bpdu_bridge_id = int.from_bytes(bpdu_bridge_id, byteorder='big')

            if bpdu_root_bridge_ID < own_bridge_ID:
                if root_bridge_ID == own_bridge_ID:
                    for i in interfaces:
                        if VLAN[get_interface_name(i)] == 'T' and i != interface:
                            state[i] = "BLOCKING"
                root_bridge_ID = bpdu_root_bridge_ID
                root_path_cost = bpdu_root_path_cost + 10
                type[interface] = "ROOT"
                if state[interface] == 'BLOCKING':
                    state[interface] = "LISTENING"
                new_bpdu = create_new_bpdu(interface)
                for i in interfaces:
                    if i != interface and VLAN[get_interface_name(i)] == 'T':
                        send_to_link(i,  len(new_bpdu), new_bpdu)
            elif bpdu_root_bridge_ID == root_bridge_ID:
                if type[interface] == "ROOT" and bpdu_root_path_cost + 10 < root_path_cost:
                    root_path_cost = bpdu_root_path_cost + 10
                else :
                    if type[interface] != "ROOT":
                        if bpdu_root_path_cost > root_path_cost:
                            if type[interface] != "DESIGNATED":
                                type[interface] = "DESIGNATED"
                                state[interface] = "LISTENING"
            else:
                if bpdu_bridge_id == own_bridge_ID:
                    state[interface] = "BLOCKING"
        
            if own_bridge_ID == root_bridge_ID:
                    for i in interfaces:
                        if VLAN[get_interface_name(i)] == 'T':
                            type[i] = "DESIGNATED"
        else:
            dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        
            
            dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
            src_mac = ':'.join(f'{b:02x}' for b in src_mac)

            # Note. Adding a VLAN tag can be as easy as
            # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

            print(f'Destination MAC: {dest_mac}')
            print(f'Source MAC: {src_mac}')
            print(f'EtherType: {ethertype}')

            print("Received frame of size {} on interface {}".format(length, interface), flush=True)

            Table[src_mac] = interface
                # we have a UNICAST FRAME and WE KNOW WHERE TO SEND it + ADD LISTENING
            if is_unicast(dest_mac) and dest_mac in Table and state[Table[dest_mac]] == "LISTENING": 
                    unicast_trunk_number(interface, dest_mac, data, length, vlan_id)
    

            else:
                for output_interface in interfaces:
                    if output_interface != interface and state[output_interface] == "LISTENING":
                        multicast_trunk_number(output_interface, interface, data, length, vlan_id)
                
        
        # TODO: Implement VLAN support
        # TODO: Implement STP support

        # data is of type bytes.
        # send_to_link(i, length, data)

if __name__ == "__main__":
    main()