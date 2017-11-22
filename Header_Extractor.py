from scapy.all import *
import csv
packets = rdpcap('Good-dns-remoteshell.pcap')
#print(packets)
packetCount = 0
header_written = True

source_port = None
destination_port = None
identification = None
opcode = None
query = None
aa_number = None
return_code = None
number_of_questions = None
number_of_answers = None
query_name_length = None
query_type = None
query_class = None
record_name_length = None
record_type = None
record_class = None
ttl = None

ipversion = None
ip_header_length = None
packet_length = None

Pkt_Result = 0  # 1 This if packet is malicious...

def L3_info(packets):
    global packetCount
    packetCount += 1
    ipversion = packets[:][0].version
    ip_header_length = packets[:][0].ihl
    packet_length = packets[:][0].len
#    print(packets.show())
#    print(packetCount, packet[:][0].id, packet[:][0].an.qname, packet[:][0].an.qclass)
    return (packetCount, ipversion, ip_header_length, packet_length)

def L4_info(packets):
    source_port = packet[:][1].sport
    destination_port = packet[:][1].dport
    identification = packets[:][0].id
    opcode = packets[:][0].opcode
    query = packets[:][0].qr
    aa_number = packets[:][0].aa
    return_code = packets[:][0].rcode
    number_of_questions = packets[:][0].qdcount
    number_of_answers = packets[:][0].ancount

    query_name = packets[:][0].qd.qname
    query_name_length = len(query_name)
    query_type = packets[:][0].qd.qtype
    query_class = packets[:][0].qd.qclass
    if query == 1:
        try:
            record_name = packets[:][0].an.rrname
            record_name_length = len(record_name)
            record_type = packets[:][0].an.type
            record_class = packets[:][0].an.rclass
            ttl = packets[:][0].an.ttl
            return (source_port, destination_port, identification, opcode, query, aa_number, return_code, number_of_questions, number_of_answers, query_name_length, query_type, query_class, record_name_length, record_type, record_class, ttl)
        except:
            print('Response Packet without response')
    else :
        return (source_port, destination_port, identification, opcode, query, aa_number, return_code, number_of_questions, number_of_answers, query_name_length, query_type, query_class)


for packet in packets:
    packetCount, ipversion, ip_header_length, packet_length = L3_info(packet)
    try:
        source_port, destination_port, identification, opcode, query, aa_number, return_code, number_of_questions, number_of_answers, query_name_length, query_type, query_class, record_name_length, record_type, record_class, ttl = L4_info(packet)
    except:
        source_port, destination_port, identification, opcode, query, aa_number, return_code, number_of_questions, number_of_answers, query_name_length, query_type, query_class = L4_info(packets)
    #print(identification, opcode, query)
    #print(packetCount, ipversion, ip_header_length)
#    print(a, b)
    if query == 1:

        csvfile = open('Testing_data.csv', 'a' ,newline='')
        with csvfile:
            mycolumns = ['PacketCount', 'IPversion', 'IP_header_length', 'Packet_length','Source_port', 'Destination_port', 'Identification', 'Opcode', 'Query', 'AA_Number', 'Return_Code','No_ofQ', 'No_ofA','Query_name_length', 'Query_type', 'Query_class','Record_name_length', 'Record_type', 'Record_class', 'TTL', 'Pkt_Result']
            writer = csv.DictWriter(csvfile, fieldnames=mycolumns)

            if header_written == False:
                writer.writeheader()
                header_written = True

            writer.writerow({'PacketCount':packetCount, 'IPversion':ipversion, 'IP_header_length':ip_header_length, 'Packet_length':packet_length,'Source_port':source_port, 'Destination_port':destination_port, 'Identification':identification, 'Opcode':opcode, 'Query':query, 'AA_Number':aa_number, 'Return_Code':return_code,'No_ofQ':number_of_questions, 'No_ofA':number_of_answers,'Query_name_length':query_name_length, 'Query_type':query_type, 'Query_class':query_class, 'Record_name_length':record_name_length, 'Record_type':record_type, 'Record_class':record_class, 'TTL':ttl, 'Pkt_Result':Pkt_Result })

    else:
        record_name_length = record_type = record_class = ttl = '00.0'
        csvfile = open('Testing_data.csv', 'a' ,newline='')
        with csvfile:
            mycolumns = ['PacketCount', 'IPversion', 'IP_header_length', 'Packet_length', 'Source_port', 'Destination_port', 'Identification', 'Opcode', 'Query', 'AA_Number', 'Return_Code','No_ofQ', 'No_ofA','Query_name_length', 'Query_type', 'Query_class','Record_name_length', 'Record_type', 'Record_class', 'TTL', 'Pkt_Result']
            writer = csv.DictWriter(csvfile, fieldnames=mycolumns)

            if header_written == False:
                writer.writeheader()
                header_written = True

            writer.writerow({'PacketCount':packetCount, 'IPversion':ipversion, 'IP_header_length':ip_header_length, 'Packet_length':packet_length, 'Source_port':source_port, 'Destination_port':destination_port, 'Identification':identification, 'Opcode':opcode, 'Query':query, 'AA_Number':aa_number, 'Return_Code':return_code,'No_ofQ':number_of_questions, 'No_ofA':number_of_answers,'Query_name_length':query_name_length, 'Query_type':query_type, 'Query_class':query_class, 'Record_name_length':record_name_length, 'Record_type':record_type, 'Record_class':record_class, 'TTL':ttl, 'Pkt_Result':Pkt_Result })

    identification = None
    opcode = None
    query = None
    aa_number = None
    return_code = None
    number_of_questions = None
    number_of_answers = None
    query_name_length = None
    query_type = None
    query_class = None
    record_name_length = None
    record_type = None
    record_class = None
    ttl = None
