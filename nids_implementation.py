import scapy.all as scp
import codecs
import PySimpleGUI as sg
import os
import threading
import sys
import pyshark
import socket
import scapy.arch.windows as scpwinarch
import json
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import re
import ipaddress
import subprocess
import yara
import pprint
import glob

def readrules():
    rulefile = "rules.txt"
    ruleslist = []
    with open(rulefile, "r") as rf:
        ruleslist = rf.readlines()
    rules_list = []
    for line in ruleslist:
        if line.startswith("alert"):
            rules_list.append(line)
    print(rules_list)
    return rules_list

alertprotocols = []
alertdestips = []
alertsrcips = []
alertsrcports = []
alertdestports = []
alertmsgs = []

# rule format --> "alert [srcip] [srcport] --> [dstip] [dstport] [msg]" [msg] may include spaces and is not within quotes

def process_rules(rulelist):
    global alertprotocols
    global alertdestips
    global alertsrcips
    global alertsrcports
    global alertdestports
    global alertmsgs
    alertprotocols = []
    alertdestips = []
    alertsrcips = []
    alertsrcports = []
    alertdestports = []
    alertmsgs = []
    for rule in rulelist:
        rulewords = rule.split()
        if rulewords[1] != "any":
            protocol = rulewords[1]
            alertprotocols.append(protocol.lower())
        else:
            alertprotocols.append("any")
        if rulewords[2] != "any":
            srcip = rulewords[2]
            alertsrcips.append(srcip.lower())
        else:
            alertsrcips.append("any")
        if rulewords[3] != "any":
            srcport = int(rulewords[3])
            alertsrcports.append(srcport)
        else:
            alertsrcports.append("any")
        if rulewords[5] != "any":
            destip = rulewords[5]
            alertdestips.append(destip.lower())
        else:
            alertdestips.append("any")
        if rulewords[6] != "any":
            destport = rulewords[6]
            alertdestports.append(destport.lower())
        else:
            alertdestports.append("any")
        try:
            alertmsgs.append(" ".join([rulewords[x] for x in range(7, len(rulewords))]))
        except:
            pass    

    print(alertprotocols)
    print(alertdestips)
    print(alertsrcips)
    print(alertsrcports)
    print(alertdestports)
    print(alertmsgs)

process_rules(readrules())

deviceiplist = []
for route in scp.read_routes():
    if str(route[4]) not in deviceiplist:
        deviceiplist.append(str(route[4]))
        print(str(route[4]))

MATRIX_BG = 'black'              # Classic Matrix black
MATRIX_GREEN = '#00FF33'         # Neon matrix green
MATRIX_RED = '#FF3333'           # Alert red for stop button
MATRIX_BUTTON = '#003300'        # Dark green for secondary buttons

pktsummarylist = []
suspiciouspackets = []
suspacketactual = []
lastpacket = ""
sus_readablepayloads = []
all_readablepayloads = []
tcpstreams = []
SSLLOGFILEPATH = "C:\\Users\\mainak\\ssl1.log"
http2streams=[]
logdecodedtls = True
httpobjectindexes = []
httpobjectactuals = []
httpobjecttypes = []
yaraflagged_filenames = []
reqfilepathbase = "./temp/tcpflowdump/"

# GUI COMPONENTS
# ====================
control_col = sg.Column([
    [sg.Text('CONTROL PANEL', font=('Consolas', 14), text_color=MATRIX_GREEN)],
    [sg.Button('▶ START', key='-startcap-', size=(10,1), button_color=('black', MATRIX_GREEN)),
     sg.Button('⏹ STOP', key='-stopcap-', size=(10,1), button_color=('white', MATRIX_RED)),
     sg.Button('🔄 RULES', key='-refreshrules-', button_color=(MATRIX_GREEN, MATRIX_BUTTON))],
    [sg.Button('💾 SAVE', key='-savepcap-', button_color=(MATRIX_GREEN, MATRIX_BUTTON)),
     sg.Button('📊 STATS', key='-statsbtn-', button_color=(MATRIX_GREEN, MATRIX_BUTTON)),
     sg.Button('🚩 YARA', key='-yarafilterstreamsbtn-', button_color=(MATRIX_GREEN, MATRIX_BUTTON))],
    [sg.HSeparator(color=MATRIX_GREEN)],
    [sg.Text('ACTIVE RULES', font=('Consolas', 12), text_color=MATRIX_GREEN)],
    [sg.Multiline("\n".join(readrules()), size=(35,5), key='-rules-',
                 background_color=MATRIX_BG, text_color=MATRIX_GREEN)]
], background_color=MATRIX_BG)

traffic_col = sg.Column([
    [sg.Text('NETWORK TRAFFIC', font=('Consolas', 14), text_color=MATRIX_GREEN)],
    [sg.Listbox(values=pktsummarylist, size=(100,12), key='-pktsall-',
               background_color=MATRIX_BG, text_color=MATRIX_GREEN)],
    [sg.Text('SECURITY ALERTS', font=('Consolas', 14), text_color=MATRIX_RED)],
    [sg.Listbox(values=suspiciouspackets, size=(100,6), key='-pkts-',
               highlight_background_color='#002200', background_color=MATRIX_BG,
               text_color=MATRIX_GREEN)]
], background_color=MATRIX_BG)

analysis_col = sg.Column([
    [sg.Text('PACKET ANALYSIS', font=('Consolas', 14), text_color=MATRIX_GREEN)],
    [sg.Multiline(size=(100,10), key='-payloaddecoded-', font=('Consolas', 10),
                 background_color=MATRIX_BG, text_color=MATRIX_GREEN)],
    [sg.Button('🗜 TCP Streams', key='-showtcpstreamsbtn-'), 
     sg.Button('🌐 HTTP Objects', key='-showhttpstreamsbtn-'),
     sg.Button('🔍 Search', key='-searchbtn-')],
    [sg.Listbox([], size=(45,6), key='-tcpstreams-', enable_events=True,
                background_color=MATRIX_BG, text_color=MATRIX_GREEN),
     sg.Listbox([], size=(45,6), key='-http2streams-', enable_events=True,
                background_color=MATRIX_BG, text_color=MATRIX_GREEN)]
], background_color=MATRIX_BG)

layout = [
    [control_col, traffic_col],
    [analysis_col],
    [sg.StatusBar('Ready', key='-status-', size=(100,1), 
     text_color=MATRIX_GREEN, background_color=MATRIX_BG)]
]

# ====================
# MAIN WINDOW
# ====================
window = sg.Window('NETWORK INTRUSION DETECTION SYSTEM', layout, finalize=True, 
                  resizable=True, margins=(10,10),
                  background_color=MATRIX_BG,
                  element_justification='left')

updatepktlist = False
pkt_list = []


def get_http_headers(http_payload):
    try:
        headers_raw = http_payload[:http_payload.index(b"\r\n\r\n") + 2]
        headers = dict(re.findall(b"(?P<name>.*?): (?P<value>.*?)\\r\\n", headers_raw))

    except ValueError as err:
        logging.error('Could not find \\r\\n\\r\\n - %s' % err)
        return None
    except Exception as err:
        logging.error('Exception found trying to parse raw headers - %s' % err)
        logging.debug(str(http_payload))
        return None

    if b"Content-Type" not in headers:
        logging.debug('Content Type not present in headers')
        logging.debug(headers.keys())
        return None   
    return headers

def extract_object(headers, http_payload):
    object_extracted = None
    object_type = None

    content_type_filters = [b'application/x-msdownload', b'application/octet-stream']

    try:
        if b'Content-Type' in headers.keys():
            #if headers[b'Content-Type'] in content_type_filters:              
            object_extracted = http_payload[http_payload.index(b"\r\n\r\n") +4:]
            object_type = object_extracted[:2]
            logging.info("Object Type: %s" % object_type)
            # else:
            #     logging.debug('Content Type did not matched with filters - %s' % headers[b'Content-Type'])
            #     if len(http_payload) > 10:
            #         logging.debug('Object first 50 bytes - %s' % str(http_payload[:50]))
        else: 
            logging.info('No Content Type in Package')
            logging.debug(headers.keys())

        if b'Content-Length' in headers.keys():
            logging.info( "%s: %s" % (b'Content-Lenght', headers[b'Content-Length']))
    except Exception as err:
        logging.error('Exception found trying to parse headers - %s' % err)
        return None, None
    return object_extracted, object_type

def read_http():
    objectlist = []
    objectsactual = []
    objectsactualtypes = []
    objectcount = 0
    global pkt_list
    try:
        os.remove(f".\\temp\\httpstreamread.pcap")
    except:
        pass
    httppcapfile = f".\\temp\\httpstreamread.pcap"
    scp.wrpcap(httppcapfile, pkt_list)
    pcap_flow = scp.rdpcap(httppcapfile)
    sessions_all = pcap_flow.sessions()

    for session in sessions_all:
        http_payload = bytes()
        for pkt in sessions_all[session]:
            if pkt.haslayer("TCP"):
                if pkt["TCP"].dport == 80 or pkt["TCP"].sport == 80 or pkt["TCP"].dport == 8080 or pkt["TCP"].sport == 8080:
                    if pkt["TCP"].payload:
                        payload = pkt["TCP"].payload
                        http_payload += scp.raw(payload)
        if len(http_payload):
            http_headers = get_http_headers(http_payload)

            if http_headers is None:
                continue

            object_found, object_type = extract_object(http_headers, http_payload)

            if object_found is not None and object_type is not None:
                objectcount += 1
                objectlist.append(objectcount-1)
                objectsactual.append(object_found)
                objectsactualtypes.append(object_type)
    
    return objectlist, objectsactual, objectsactualtypes


def proto_name_by_num(proto_num):
    for name,num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:]
    return "Protocol not found"

def check_rules_warning(pkt):
    global alertprotocols
    global alertdestips
    global alertsrcips
    global alertsrcports
    global alertdestports
    global alertmsgs
    global sus_readablepayloads
    global updatepktlist

    if 'IP' in pkt:
        try:
            src = pkt['IP'].src
            dest = pkt['IP'].dst
            proto = proto_name_by_num(pkt['IP'].proto).lower()
            #print(proto)
            sport = pkt['IP'].sport
            dport = pkt['IP'].dport

            for i in range(len(alertprotocols)):
                flagpacket = False
                if alertprotocols[i] != "any":
                    chkproto = alertprotocols[i]
                else:
                    chkproto = proto
                if alertdestips[i] != "any":
                    chkdestip = alertdestips[i]
                else:
                    chkdestip = dest
                if alertsrcips[i] != "any":
                    chksrcip = alertsrcips[i]
                else:
                    chksrcip = src
                if alertsrcports[i] != "any":
                    chksrcport = alertsrcports[i]
                else:
                    chksrcport = sport
                if alertdestports[i] != "any":
                    chkdestport = alertdestports[i]
                else:
                    chkdestport = dport
                
                # print("chk \n", str(chksrcip) , str(chkdestip) , str(chkproto) , str(chkdestport) , str(chksrcport))
                # print("act \n", str(src) , str(dest) , str(proto) , str(dport) , str(sport))
                
                if "/" not in str(chksrcip).strip() and "/" not in str(chkdestip).strip():
                    if (str(src).strip() == str(chksrcip).strip() and str(dest).strip() == str(chkdestip).strip() and str(proto).strip() == str(chkproto).strip() and str(dport).strip() == str(chkdestport).strip() and str(sport).strip() == str(chksrcport).strip()):
                        flagpacket = True
                if "/" in str(chksrcip).strip() and "/" in str(chkdestip).strip():
                    if (ipaddress.IPv4Address(str(src).strip()) in ipaddress.IPv4Network(str(chksrcip).strip()) and ipaddress.IPv4Address(str(dest).strip()) in ipaddress.IPv4Network(str(chkdestip).strip()) and str(proto).strip() == str(chkproto).strip() and str(dport).strip() == str(chkdestport).strip() and str(sport).strip() == str(chksrcport).strip()):
                        flagpacket = True
                if "/" in str(chksrcip).strip() and "/" not in str(chkdestip).strip():
                    if (ipaddress.IPv4Address(str(src).strip()) in ipaddress.IPv4Network(str(chksrcip).strip()) and str(dest).strip() == str(chkdestip).strip() and str(proto).strip() == str(chkproto).strip() and str(dport).strip() == str(chkdestport).strip() and str(sport).strip() == str(chksrcport).strip()):
                        flagpacket = True
                if "/" not in str(chksrcip).strip() and "/" in str(chkdestip).strip():                        
                    if (str(src).strip() == str(chksrcip).strip() and ipaddress.IPv4Address(str(dest).strip()) in ipaddress.IPv4Network(str(chkdestip).strip()) and str(proto).strip() == str(chkproto).strip() and str(dport).strip() == str(chkdestport).strip() and str(sport).strip() == str(chksrcport).strip()):
                        flagpacket = True

                if flagpacket == True:
                        # print("Match")
                    if proto == "tcp":
                        try:
                            readable_payload = bytes(pkt['TCP'].payload).decode('UTF8','replace')
                            sus_readablepayloads.append(readable_payload)
                        except Exception as ex:
                            sus_readablepayloads.append("Error getting tcp payload!!")
                            print(ex)
                            pass
                    elif proto == "udp":
                        try:
                            readable_payload = bytes(pkt['UDP'].payload).decode('UTF8','replace')
                            sus_readablepayloads.append(readable_payload)
                        except Exception as ex:
                            sus_readablepayloads.append("Error getting udp payload!!")
                            print(ex)
                            pass
                    else:
                        sus_readablepayloads.append("NOT TCP PACKET!!")
                    if updatepktlist:
                        window['-payloaddecoded-'].update(value=sus_readablepayloads[len(suspiciouspackets)])
                    return True, str(alertmsgs[i])
        except:
            pkt.show()
        
    # for protocol in alertprotocols:
    #     if protocol.upper() in pkt:
    #         pass
    return False, ""


def pkt_process(pkt):
    global deviceiplist
    global window
    global updatepktlist
    global suspiciouspackets
    global all_readablepayloads

    pkt_summary = pkt.summary()
        #print("\n", src, " : ", dest, "\n")
        # if dest in deviceiplist:
        #     print(f"\n[*] INCOMING PACKET from \n")
        #     if updatepktlist:
                
        #     lastpacket = pkt_summary
        #     return pkt_summary
    pktsummarylist.append(f"{len(pktsummarylist)} " + pkt_summary)
    pkt_list.append(pkt)
    sus_pkt, sus_msg = check_rules_warning(pkt)
    if sus_pkt == True:
        suspiciouspackets.append(f"{len(suspiciouspackets)} {len(pktsummarylist) - 1}" + pkt_summary + f" MSG: {sus_msg}")
        suspacketactual.append(pkt)

    
    # if 'IP' in pkt:
    #     proto = proto_name_by_num(pkt['IP'].proto).lower()
    #     if proto == "tcp":
    #         try:
    #             readable_payload = bytes(pkt['TCP'].payload).decode('UTF8','replace')
    #             all_readablepayloads.append(readable_payload)
    #         except Exception as ex:
    #             all_readablepayloads.append("Error getting tcp payload!!")
    #             print(ex)
    #             pass
    #     elif proto == "udp":
    #         try:
    #             readable_payload = bytes(pkt['UDP'].payload).decode('UTF8','replace')
    #             all_readablepayloads.append(readable_payload)
    #         except Exception as ex:
    #             all_readablepayloads.append("Error getting udp payload!!")
    #             print(ex)
    #             pass
    #     else:
    #         all_readablepayloads.append("NOT TCP PACKET!!")
    #     if updatepktlist:
    #         window['-payloaddecodedall-'].update(value=all_readablepayloads[-1])
        #print(suspiciouspackets)
    #pkt.show()

    return

ifaces = [str(x["name"]) for x in scpwinarch.get_windows_if_list()]
ifaces1 = [ifaces[6]].append(ifaces[0]) #Ether and VMnet8
sniffthread = threading.Thread(target=scp.sniff, kwargs={"prn":pkt_process, "filter": "", "iface":ifaces[0:6]}, daemon=True)
sniffthread.start()

def show_tcp_stream_openwin(stream_data):
    layout = [
        [sg.Multiline(
            stream_data, 
            size=(120, 50), 
            font=('Consolas', 10),
            text_color=MATRIX_GREEN,
            background_color=MATRIX_BG
        )],
        [sg.Button("Save to File", key='-save-'), sg.Button("Close")]
    ]
    
    stream_window = sg.Window(
        "TCP Stream Analysis", 
        layout, 
        modal=True,
        finalize=True,
        element_justification='c'
    )
    
    while True:
        event, _ = stream_window.read()
        if event in (sg.WIN_CLOSED, "Close"):
            break
        elif event == "-save-":
            save_path = sg.popup_get_file("Save As", save_as=True)
            if save_path:
                with open(save_path, "w", errors="replace") as f:
                    f.write(stream_data)
    
    stream_window.close()

def show_http2_stream_openwin(tcpstreamtext):
    layout = [[sg.Multiline(tcpstreamtext, size=(100,50), key="tcpnewwintext")]]
    window = sg.Window("HTTP2 STREAM", layout, modal=True, size=(1200, 600), resizable=True)
    choice = None
    while True:
        event, values = window.read()
        if event == "Exit" or event == sg.WIN_CLOSED:
            break
    window.close()

def load_tcp_streams(window):
    global http2streams, logdecodedtls, pkt_list

    # Check if pkt_list exists and is initialized
    if 'pkt_list' not in globals():
        pkt_list = []
    
    if not pkt_list:
        sg.popup("No packets captured yet!")
        return

    # Create temp directory if needed
    temp_dir = os.path.join(".", "temp")
    os.makedirs(temp_dir, exist_ok=True)
    temp_path = os.path.join(temp_dir, "tcpstreamread.pcap")

    # Clear existing temp file
    try:
        if os.path.exists(temp_path):
            os.remove(temp_path)
    except Exception as e:
        sg.popup_error(f"Error deleting temporary file: {str(e)}")
        return

    # Write packets to temp file
    scp.wrpcap(temp_path, pkt_list)
    
    # Process TCP streams
    global tcpstreams
    tcpstreams = []
    cap = pyshark.FileCapture(temp_path, display_filter="tcp.stream", keep_packets=True)
    streams = set()
    for pkt in cap:
        if hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'stream'):
            streams.add(int(pkt.tcp.stream))
    cap.close()
    tcpstreams = list(streams)
    window["-tcpstreams-"].update(sorted(tcpstreams))

    # Process HTTP/2 streams
    if logdecodedtls:
        http2streams = []
        cap = pyshark.FileCapture(temp_path, 
                                display_filter="http2", 
                                override_prefs={'ssl.keylog_file': SSLLOGFILEPATH})
        streams = set()
        for pkt in cap:
            if hasattr(pkt, 'http2') and hasattr(pkt.http2, 'streamid'):
                streams.add(int(pkt.http2.streamid))
        cap.close()
        http2streams = list(streams)
        window["-http2streams-"].update(sorted(http2streams))

    sg.popup(f"Loaded {len(tcpstreams)} TCP streams\n{len(http2streams)} HTTP/2 streams")
    pass


def show_http2_stream(window, streamno):
    
    tcpstreamfilename = ".\\temp\\tcpstreamread.pcap"
    cap3 = pyshark.FileCapture(
            tcpstreamfilename,
            # display_filter = f'http2.streamid eq {str(http2streamindex)}',
            display_filter = f'http2.streamid eq {str(streamno)}',
            override_prefs={'ssl.keylog_file': SSLLOGFILEPATH}
        )
    #print(cap3[0].http2.stream)
    dat = ""
    decode_hex = codecs.getdecoder("hex_codec")
    http_payload = bytes()
    for pkt in cap3:
        # for x in pkt[pkt.highest_layer]._get_all_field_lines():
        #     print(x)
        #try:
        try:
            payload = pkt["TCP"].payload
            http_payload += scp.raw(payload)
            #does literally nothing because we do not know the encoding format of the payload so scp.raw returns type error
        except:
            pass

        print(pkt.http2.stream)
        if ("DATA" not in pkt.http2.stream):
            http2headerdat = ''
            rawvallengthpassed = False
            print(pkt.http2._all_fields.items())
            for field, val in pkt.http2._all_fields.items():
                if rawvallengthpassed == False:
                    if field == 'http2.header.name.length':
                        rawvallengthpassed = True
                else:
                    #if field.split(".")[-1] != "headers":
                    http2headerdat += str(field.split(".")[-1]) + " : " + str(val) + " \n"
                    print(http2headerdat)
            dat += "\n" + http2headerdat
            # httpdat = "".join("".join({val for key,val in pkt.http2._all_fields.items() if key == 'http2.data.data'}).split(":"))
            # httpdatdecoded = decode_hex(httpdat)[0]
            # dat += httpdatdecoded
            # dat = pkt.pretty_print
            # payload = pkt.http2.payload
            # if hasattr(pkt,'http2'):
            #     if hasattr(pkt.http2,'json_object'):
            #         if hasattr(pkt.http2,'body_reassembled_data'):
            #             avp=json.loads(codecs.decode(pkt.http2.body_reassembled_data.raw_value,'hex'))
            # # encryptedapplicationdata_hex = "".join(payload.split(":")[0:len(payload.split(":"))])
            # # encryptedapplicationdata_hex_decoded = decode_hex(encryptedapplicationdata_hex)[0]
            # # dat += encryptedapplicationdata_hex_decoded
            #             dat += avp
            #print(encryptedapplicationdata_hex_decoded)
        # except Exception as ex:
        #     print(ex)
    
    if len(http_payload):
        http_headers = get_http_headers(http_payload)

        if http_headers is not None:
            object_found, object_type = extract_object(http_headers, http_payload)

            dat += object_type + "\n" + object_found + "\n"


    print(dat)
    formatteddat = dat
    # formatteddat = str(dat, "ascii", "replace")
    #show_tcp_stream_openwin(formatteddat)
    print(formatteddat)

    show_http2_stream_openwin(formatteddat)
    # os.remove(tcpstreamfilename)
    #print(formatteddat)
    pass

def show_tcpstream(stream_id):  # Remove window parameter
    temp_path = os.path.join(".", "temp", "tcpstreamread.pcap")
    cap = pyshark.FileCapture(temp_path,
                            display_filter=f'tcp.stream eq {stream_id}',
                            override_prefs={'ssl.keylog_file': SSLLOGFILEPATH})
    
    data = {
        'client': b'',
        'server': b''
    }
    
    for pkt in cap:
        if hasattr(pkt, 'tcp'):
            try:
                payload = pkt.tcp.payload.binary_value
                if pkt.tcp.srcport == pkt[pkt.transport_layer].dstport:
                    data['client'] += payload
                else:
                    data['server'] += payload
            except AttributeError:
                continue

    layout = [
        [sg.Text(f"TCP Stream {stream_id}", font=('Consolas', 14))],
        [sg.Multiline(f"CLIENT:\n{data['client'].decode('utf-8', 'replace')}\n\nSERVER:\n{data['server'].decode('utf-8', 'replace')}", 
                     size=(120,30))]
    ]
    sg.Window(f"TCP Stream {stream_id}", layout, modal=True).read(close=True)

def yarascan(scanfile, rules):
    matches = []
    if os.path.getsize(scanfile) > 0:
        for match in rules.match(scanfile):
            matches.append({"name":match.rule, "meta":match.meta})

    return matches

def yarafilterstreams(window):      # window parameter for calling load_tcp_streams if necessary
    
    global yaraflagged_filenames
    global reqfilepathbase

    yaraflagged_filenames = []
    # check if pcap files already exist for captured streams
    # pcap file names are tcpstreamread.pcap and httpstreamread.pcap
    # they are stored in ./temp/

    if not os.path.isfile("./temp/tcpstreamread.pcap"):
        load_tcp_streams(window)
    if not os.path.isfile("./temp/httpstreamread.pcap"):
        read_http()
    
    # tcpflow64 arguments 
    # -a -r <pcapfile> -o <outputdir>
    
    # clear tcpflowdump directory

    dumpfiles = glob.glob(reqfilepathbase + "*")
    for file in dumpfiles:
        os.remove(file)

    # generate files for packet streams using tcpflow
    subprocess.call("tcpflow64.exe -a -r temp/httpstreamread.pcap -o temp/tcpflowdump/", shell=True)
    subprocess.call("tcpflow64.exe -a -r temp/tcpstreamread.pcap -o temp/tcpflowdump/", shell=True)

    yarafile = "./yararules/rules1.yara"
    yararules = yara.compile(yarafile)      # compile yara rules

    
    matchcount = 1
    results = []
    resultstxt = ""
    for req in os.listdir(reqfilepathbase):
        res = yarascan(os.path.join(reqfilepathbase, req), yararules)
        if res:
            for match in res:
                pprint.pprint(match)
                results.append({"ruleMatched":match["name"]})
                resultstxt += str(matchcount) + ". " + str(match["name"]) + "\n"
                matchcount += 1
            if req != "report.xml":
                yaraflagged_filenames.append(str(match["name"]) + ":::" + req)  # ::: serves as separator
    with open("yararesults.txt", "w") as resfile:                       # for filename and yara rule name
        resfile.write(resultstxt)
    for file in yaraflagged_filenames:
        print(file)
    window["-yaraflaggedstreams-"].update(values=yaraflagged_filenames) #update gui with yara flagged stream filenames
    return

def show_yara_flagged(streamdat):
    layout = [[sg.Multiline(streamdat, size=(100,50), key="yaranewwintext")]]
    window = sg.Window("HTTP2 STREAM", layout, modal=True, size=(1200, 600), resizable=True)
    choice = None
    while True:
        event, values = window.read()
        if event == "Exit" or event == sg.WIN_CLOSED:
            break
    window.close()

def event_yaraflagged_selected(stream_idx):
    yarafilename = stream_idx.split(":::")[1]
    filepath = os.path.join(reqfilepathbase, yarafilename)
    with open(filepath, "r", errors="ignore") as yaraflaggedfile:
        yaraflagged_filedat = yaraflaggedfile.read()
    show_yara_flagged(yaraflagged_filedat)

while True:

    print(suspiciouspackets)

    event, values = window.read()
    if event == '-refreshrules-':
        process_rules(readrules())
    if event == "-startcap-":
        updatepktlist = True
        incomingpacketlist = []
        inc_pkt_list = []
        suspiciouspackets = []
        suspacketactual = []
        pktsummarylist = []
        sus_readablepayloads = []
        while True:
            event, values = window.read(timeout=10)
            if event == "-stopcap-":
                updatepktlist = False
                break
            if event == '-refreshrules-':
                process_rules(readrules())
            if event == sg.TIMEOUT_EVENT:
                #window['-pkts-'].update(pktsummarylist, scroll_to_index=len(pktsummarylist))
                window['-pkts-'].update(suspiciouspackets, scroll_to_index=len(suspiciouspackets))
                window['-pktsall-'].update(pktsummarylist, scroll_to_index=len(pktsummarylist))
                #window['-payloaddecoded-'].update(value=sus_readablepayloads[len(suspiciouspackets)])
            if event in (None, 'Exit'):
                sys.exit()
                break
            if event == '-pkts-' and len(values['-pkts-']):     # if a list item is chosen
                sus_selected = values['-pkts-']
                #sus_selected_index = int(sus_selected.split()[0][0:2])
                sus_selected_index = values[event][0]
                try:
                    window["-tcpstreams-"].update(scroll_to_index=int(suspacketactual[sus_selected_index].tcp.stream))
                except:
                    pass
                window['-payloaddecoded-'].update(value=sus_readablepayloads[sus_selected_index])
                # for i in range(100):
                #     print(sus_selected_index)
                #     print("\n")
                # print(sus_readablepayloads)
            if event == '-pktsall-' and len(values['-pktsall-']):     # if a list item is chosen
                #pktselected = values['-pktsall-']
                pkt_selected_index = window["-pktsall-"].get_indexes()
                try:
                    window["-tcpstreams-"].update(scroll_to_index=int(pkt_list[pkt_selected_index].tcp.stream))
                except:
                    pass
            #     #sus_selected_index = int(sus_selected.split()[0][0:2])
            #     pktselectedindex = window['-pktsall-'].get_indexes()[0]
            #     window['-payloaddecodedall-'].update(value=all_readablepayloads[pktselectedindex])
            if event == "-showtcpstreamsbtn-":      # load tcp streams btn
                load_tcp_streams(window)
            if event == "-tcpstreams-":
                streamindex = window["-tcpstreams-"].get_indexes()
                show_tcpstream(window, streamindex)
            if event == "-http2streams-" and values['-http2streams-']:
                selected_http2_stream = values['-http2streams-'][0]
                try:
                    show_http2_stream(int(selected_http2_stream))
                    window['-status-'].update(f"Viewing HTTP/2 Stream {selected_http2_stream}")
                except Exception as e:
                    sg.popup_error(f"HTTP/2 error: {str(e)}")
                show_http2_stream(window, int(http2streamindex))
            if event == "-showhttpstreamsbtn-":         # load http streams btn
                httpobjectindexes = []
                httpobjectactuals = []
                httpobjecttypes = []
                httpobjectindexes, httpobjectactuals, httpobjecttypes = read_http()
                window["-httpobjects-"].update(values=httpobjectindexes)
            if event == "-httpobjects-":
                httpobjectindex = values[event][0]
                show_http2_stream_openwin(httpobjecttypes[httpobjectindex] + b"\n" + httpobjectactuals[httpobjectindex][:900])
            if event == "-yarafilterstreamsbtn-":
                yarafilterstreams(window)
            if event == "-yaraflaggedstreams-":
                yaraflaggedstream_idx = values[event][0]
                event_yaraflagged_selected(yaraflaggedstream_idx)

    if event == "-yaraflaggedstreams-":
        yaraflaggedstream_idx = values[event][0]
        #print(yaraflaggedstream_idx)
        event_yaraflagged_selected(yaraflaggedstream_idx)

    if event == "-yarafilterstreamsbtn-":
        yarafilterstreams(window)

    if event == "-showhttpstreamsbtn-":
        httpobjectindexes = []
        httpobjectactuals = []
        httpobjecttypes = []
        httpobjectindexes, httpobjectactuals, httpobjecttypes = read_http()
        window["-httpobjects-"].update(values=httpobjectindexes)
    
    if event == "-httpobjects-":
        httpobjectindex = values[event][0]
        show_http2_stream_openwin(httpobjecttypes[httpobjectindex] + b"\n" + httpobjectactuals[httpobjectindex][:900])

    if event == "-http2streams-":
        http2streamindex = values[event][0]
        print(http2streamindex)
        show_http2_stream(window, str(int(http2streamindex)))
    if event == '-pktsall-' and len(values['-pktsall-']):     # if a list item is chosen
        #pktselected = values['-pktsall-']
        pkt_selected_index = window["-pktsall-"].get_indexes()[0]
        try:
            window["-tcpstreams-"].update(scroll_to_index=int(pkt_list[pkt_selected_index].tcp.stream))
        except:
            pass
    if event == '-savepcap-':
        pcapname = "nettrafic"
        scp.wrpcap(f'.\\savedpcap\\{pcapname}.pcap', inc_pkt_list)
    if event == '-pkts-' and len(values['-pkts-']):     # if a list item is chosen
        sus_selected = values['-pkts-']
        #sus_selected_index = int(sus_selected.split()[0][0:2])
        sus_selected_index = window['-pkts-'].get_indexes()[0]
        try:
            window["-tcpstreams-"].update(scroll_to_index=int(suspacketactual[sus_selected_index].tcp.stream))
        except:
            pass
        window['-payloaddecoded-'].update(value=sus_readablepayloads[sus_selected_index])
    if event == "-showtcpstreamsbtn-":
        load_tcp_streams(window)    
    if event == "-tcpstreams-":
        streamindex = window["-tcpstreams-"].get_indexes()
        show_tcpstream(window, streamindex)            
    # if event == '-pktsall-' and len(values['-pktsall-']):     # if a list item is chosen
    #             pktselected = values['-pktsall-']
    #             #sus_selected_index = int(sus_selected.split()[0][0:2])
    #             pktselectedindex = window['-pktsall-'].get_indexes()[0]
    #             window['-payloaddecodedall-'].update(value=all_readablepayloads[pktselectedindex])
    if event in (None, 'Exit'):
        break
    


window.close()

# port lookup for rule writing
# >>> from socket import getservbyname, getservbyport
# >>> getservbyname("ssh")
# 22
# >>> getservbyname("domain", "udp")
# 53
# >>> getservbyname("https", "tcp")
# 443
