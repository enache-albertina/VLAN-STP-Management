#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

# ------------------------- GLOBAL VARIABLES -------------------------------------------
own_bridge_ID = -1
root_bridge_ID = -1
root_path_cost = -1
sender_bridge_ID = -1
# --------------------------------------------------------------------------------------


# -------------------------- INFO STRUCTURES -------------------------------------------

MAC_Table = {}  # Initialize an empty MAC table     | entries : {MAC - interface}
interface_vlan = {} # ports of the switch           | entries : {interface_name_trunkport - vlan_id}
ports_trunk = {} # ports of the switch (type trunk) | entries : {interface_name_trunk - mode}
ports = {}

port_vlan = [] # port vlan                          | entries {number_port, NUMBER/TRUNK}
port_state = [] # port state                        | entries {number_port, BLOCKING/LISTENING}
port_type = [] # port type                          | entries {number_port, DESIGNATED/ROOT}

# --------------------------------------------------------------------------------------

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
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

# parse BDPU packet
def parse_bdpu_packet(data):
    # Unpack the header fields from the byte array
    dest_mac, src_mac, llc_length, llc_header, bpdu_header, bpdu_config = struct.unpack('!6s6sH3sI31s', data[:52])
    return dest_mac, src_mac, llc_length, llc_header, bpdu_header, bpdu_config

# parse BDPU config
def parse_bdpu_config(bdpu_config):
    # Unpack the header fields from the byte array
    flag, root_ID, root_path_cost, bridge_ID, port_ID, message_age, max_age, hello_time, forward_delay = struct.unpack('!B8sI8sHHHHH', bdpu_config[:38])
    return root_ID, root_path_cost, bridge_ID, port_ID 

# create vlan tag
def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

# -------------------------- SEND BDPU -------------------------------------------------
def send_bdpu_every_sec():
    global own_bridge_ID
    global root_bridge_ID
    while True:
        # Dacă switch-ul curent este root
        if own_bridge_ID == root_bridge_ID:
            # Parcurge toate interfețele și trimite BPDU pe porturile trunk
            for i in range(0, len(port_vlan)):
                if port_vlan[i] == 'T':
                    bpdu = create_bpdu(i)
                    send_to_link(i, bpdu, len(bpdu))

        # Așteaptă o secundă înainte de următoarea iterație
        time.sleep(1)
# --------------------------------------------------------------------------------------

# ************************** CREATE BDPU ***********************************************

def create_bpdu(port_id):
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

# **************************************************************************************

def parse_config_file(switch_id):

    
    
    # read file location
    file_path = f'configs/switch{switch_id}.cfg'
    ### print(f"[CONFIG FILE] READ : {file_path}")

    # open file location
    with open(file_path) as file:
       file_content = file.read()
    
    # split the content into lines
    lines = file_content.split('\n')

    # extract information from the first line
    PRIO = lines[0]
    ### print(f"[PRIO] SWITCH : {PRIO}")
    global own_bridge_ID
    own_bridge_ID = int(PRIO)

    # extract information from the other lines
    switch_info = [line.split() for line in lines[1:] if line]
    
    for line_info in switch_info:
        ### print(f"[PORT] SWITCH : {line_info}")
        # first is interface name
        interface_name = line_info[0]
        # second is vlan
        vlan = line_info[1]
        # add vlan to port_vlan
        port_vlan.append(vlan)
        port_state.append("LISTENING")
        port_type.append("NONE")

        # add this
        ports[interface_name] = vlan
        
        # optional
        interface_vlan[interface_name] = vlan

    ### print(f"[ALL] PORTS VLAN : {port_vlan}")

def forward_frame(data, length, output_interface):
    send_to_link(output_interface, data, length)

def is_unicast(mac):
    dest_mac_bytes = mac.split(':')
    first_byte = int(dest_mac_bytes[0], 16)
    return (first_byte & 1) == 0

def stp_implementation(interface, interfaces, data):
    global own_bridge_ID, root_bridge_ID, root_path_cost

    # Extract BPDU components
    dest_mac, src_mac, llc_length, llc_header, bpdu_header, bpdu_config = struct.unpack('!6s6sH3sI31s', data[:52])

    # Convert BPDU IDs to readable format
    flag, bpdu_root_ID, bpdu_root_path_cost, bpdu_bridge_ID, port_id, message_age, max_age, hello_time, forward_delay = struct.unpack('!B8sI8sHHHHH', bpdu_config[:38])
    bpdu_root_ID = int.from_bytes(bpdu_root_ID, byteorder='big')
    bpdu_sender_ID = int.from_bytes(bpdu_bridge_ID, byteorder='big')

    # Check if we find a better root bridge
    if bpdu_root_ID < root_bridge_ID:
        if root_bridge_ID == own_bridge_ID:
            # Set all interfaces to BLOCKING if we were previously the root
            for i in interfaces:
                if port_vlan[i] == 'T' and i != interface:
                    port_state[i] = "BLOCKING"

        # Update root bridge ID and path cost
        root_bridge_ID = bpdu_root_ID
        root_path_cost = bpdu_root_path_cost + 10
        port_type[interface] = "ROOT"

        # Set root port to LISTENING
        if port_state[interface] == "BLOCKING":
            port_state[interface] = "LISTENING"

        # Forward updated BPDU to other trunks
        new_bpdu = create_bpdu(interface)
        for i in interfaces:
            if port_vlan[i] == 'T' and i != interface:
                send_to_link(i, new_bpdu, len(new_bpdu))

    elif bpdu_root_ID == root_bridge_ID:
        if port_type[interface] == "ROOT" and bpdu_root_path_cost + 10 < root_path_cost:
            root_path_cost = bpdu_root_path_cost + 10
        elif port_type[interface] != "ROOT":
            if bpdu_root_path_cost > root_path_cost and port_type[interface] != "DESIGNATED":
                port_type[interface] = "DESIGNATED"
                port_state[interface] = "LISTENING"

    # Block the interface if we are the sender
    elif bpdu_sender_ID == own_bridge_ID:
        port_state[interface] = "BLOCKING"

    # If we are the root bridge, mark all trunk ports as DESIGNATED
    if own_bridge_ID == root_bridge_ID:
        for i in interfaces:
            if port_vlan[i] == 'T':
                port_type[i] = "DESIGNATED"
def multicast_trunk_number(i, interface, data, length, vlan_id):
    # Retrieve VLAN IDs for source and destination interfaces
    vlan_id_received = port_vlan[get_interface_name(interface)]
    vlan_id_destination = port_vlan[get_interface_name(i)]
    
    # Determine whether to add or remove VLAN tags based on interface types
    if vlan_id_received != 'T' and vlan_id_destination == 'T':
        # Access to Trunk: Add VLAN tag
        header_data = data[0:12] + create_vlan_tag(int(vlan_id_received)) + data[12:]
        length += 4
        send_to_link(i, header_data, length)
    elif (vlan_id_received != 'T' and vlan_id_destination == vlan_id_received) or (vlan_id_received == 'T' and vlan_id_destination == 'T'):
        # Access to Access or Trunk to Trunk: Forward as is
        send_to_link(i, data, length)
    elif vlan_id_received == 'T' and int(vlan_id_destination) == vlan_id:
        # Trunk to Access: Remove VLAN tag
        no_header_data = data[0:12] + data[16:]
        length -= 4
        send_to_link(i, no_header_data, length)

def unicast_trunk_number(interface, dest_mac, data, length, vlan_id):
    # Retrieve VLAN IDs for source and destination interfaces
    vlan_id_received = port_vlan[get_interface_name(interface)]
    vlan_id_destination = port_vlan[get_interface_name(MAC_Table[dest_mac])]
    
    # Determine whether to add or remove VLAN tags based on interface types
    if vlan_id_received != 'T' and vlan_id_destination == 'T':
        # Access to Trunk: Add VLAN tag
        header_data = data[0:12] + create_vlan_tag(int(vlan_id_received)) + data[12:]
        length += 4
        send_to_link(MAC_Table[dest_mac], header_data, length)
    elif (vlan_id_received != 'T' and vlan_id_destination == vlan_id_received) or (vlan_id_received == 'T' and vlan_id_destination == 'T'):
        # Access to Access or Trunk to Trunk: Forward as is
        send_to_link(MAC_Table[dest_mac], data, length)
    elif vlan_id_received == 'T' and int(vlan_id_destination) == vlan_id:
        # Trunk to Access: Remove VLAN tag
        no_header_data = data[0:12] + data[16:]
        length -= 4
        send_to_link(MAC_Table[dest_mac], no_header_data, length)
def main():
    # START FIRST THREAD
    
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]
    
    # own_bridge_id = switch_prio
    parse_config_file(switch_id)
    # find the number of interfaces
    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()
    # set default port state for all interfaces to LISTENING
    for i in interfaces:
        port_state[i] = "LISTENING"
    
    # Printing interface names
    for i in interfaces:
        if port_vlan[i] == 'T':
            port_state[i] = "BLOCKING"
    global own_bridge_ID 
    global root_bridge_ID 
    
    global root_path_cost 
    root_path_cost = 0
    root_bridge_ID = own_bridge_ID

    if own_bridge_ID == root_bridge_ID:
        for i in interfaces:
            if port_vlan[i] == 'T':
                port_state[i] = "LISTENING"  
                 # porturi cu costul cel mai mic
                port_type[i] = "DESIGNATED" 
    
    # Type of packet
    # 1. ICMP (0)
    # 2. BDPU (1)
    packet_type = 0 # default

    # START SECOND THREAD
    # Create and start a new thread that deals with sending BDPU
    

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].

        interface, data, length = recv_from_any_link()

        dest_mac = data[0:6]
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)

        if dest_mac == "01:80:c2:00:00:00":
        #    print("@@@@@@@@@@@ [BDPU] @@@@@@@@@@@")
            packet_type = 1
        else:
        #    print("@@@@@@@@@@@ [ICMP] @@@@@@@@@@@")
            packet_type = 0

        # on receiving a BDPU
        if dest_mac == "01:80:c2:00:00:00":
            
            stp_implementation(interface, interfaces, data)


        # on receiving a ICMP
        else:
            # print(f"[INFO] Received frame of size {length} on interface {interface} ({get_interface_name})\n", flush=True)
            
            dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

            # Print the MAC src and MAC dst in human readable format
            dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
            src_mac = ':'.join(f'{b:02x}' for b in src_mac)

            # Note. Adding a VLAN tag can be as easy as
            # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

            tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]
            untagged_frame = tagged_frame[0:12] + tagged_frame[16:]

            # print(f'[DESTINATION MAC] Destination MAC: {dest_mac}')
            # print(f'[SOURCE MAC] Source MAC: {src_mac}')
            # print(f'[ETHERTYPE] EtherType: {ethertype}')
            # print(f'[DEFAULT VLAN ID] Vlan ID: {vlan_id}\n')
            
            MAC_Table[src_mac] = interface
            # we have a UNICAST FRAME and WE KNOW WHERE TO SEND it + ADD LISTENING
            if is_unicast(dest_mac) and dest_mac in MAC_Table and port_state[MAC_Table[dest_mac]] == "LISTENING":
                # UNICAST ROUTE (send to a specific target)
                vlan_id_received = ports[get_interface_name(interface)]
                vlan_id_destination = ports[get_interface_name(MAC_Table[dest_mac])] 
                # ACCES
                if vlan_id_received != 'T' :
                    # -> TRUNK
                    if vlan_id_destination == 'T':
                        # ADD HEADER
                        header_data = data[0:12] + create_vlan_tag(int(vlan_id_received)) + data[12:]
                        forward_frame(header_data, length + 4, MAC_Table[dest_mac]) 
                    # -> ACCES
                    else:
                        # HAVE THE SAME VLAN ID
                        if vlan_id_destination == vlan_id_received:
                            forward_frame(data, length, MAC_Table[dest_mac])
                # TRUNK
                if vlan_id_received == 'T':
                    # -> TRUNK
                    if vlan_id_destination == 'T':
                        forward_frame(data, length, MAC_Table[dest_mac])
                    # -> ACCES
                    else:
                        # HAVE THE SAME VLAN ID
                        if int(vlan_id_destination) == vlan_id:
                            # REMOVE HEADER
                            no_header_data = data[0:12] + data[16:]
                            ### print("[SUCCES] Same Vlan ID...\n")
                            forward_frame(no_header_data, length - 4, MAC_Table[dest_mac])

            else:
                for output_interface in interfaces:
                    if output_interface != interface and port_state[output_interface] == "LISTENING":
                        vlan_id_received = ports[get_interface_name(interface)]
                        vlan_id_destination = ports[get_interface_name(output_interface)]
                        # ACCES
                        if vlan_id_received != 'T' :
                            # -> TRUNK
                            if vlan_id_destination == 'T':
                                # ADD HEADER
                                header_data = data[0:12] + create_vlan_tag(int(vlan_id_received)) + data[12:]
                                forward_frame(header_data, length + 4, output_interface) 
                            # -> ACCES
                            else:
                                # HAVE THE SAME VLAN ID
                                if vlan_id_destination == vlan_id_received:
                                    forward_frame(data, length, output_interface)
                        # TRUNK
                        if vlan_id_received == 'T':
                            # -> TRUNK
                            if vlan_id_destination == 'T':
                                forward_frame(data, length, output_interface)
                            # -> ACCES
                            else:
                                # HAVE THE SAME VLAN ID
                                if int(vlan_id_destination) == vlan_id:
                                    # REMOVE HEADER
                                    no_header_data = data[0:12] + data[16:]
                                    forward_frame(no_header_data, length - 4, output_interface)



if __name__ == "__main__":
    main()