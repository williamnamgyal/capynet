import statistics
from tkinter import *
from tkinter import filedialog
from tkinter import ttk
from tkinter.tix import MAX
from xml import dom
from scapy.all import *
import threading
import random


rand_num1 = random.randrange(1, 1000000)
rand_num2 = random.randrange(1, 1000000)
packets_to_sniff=300
filter_text_value=""
packets_list_storage=[]


global protocol_number_dictionary
protocol_number_dictionary = {
                1 : "ICMP",
                2 : "IGMP",
                3 : "GGP",
                4 : "IPv4",
                5 : "ST",
                6 : "TCP",
                7 : "CBT",
                8 : "EGP",
                9 : "IGP",
                12 : "PUP",
                13 : "ARGUS",
                14 : "EMCON",
                15 : "XNET",
                16 : "CHAOS",
                17 : "UDP",
                18 : "MUX",
                20 : "MHP",
                21 : "PRM",
                22 : "XNS-IDP",
                27 : "RDP",
                28 : "IRTP",
                30 : "NETBLT",
                33 : "DCCP",
                34 : "3PC",
                35 : "IDPR",
                36 : "XTP",
                37 : "DDP",
                40 : "IL",
                41 : "IPv6",
                42 : "SDRP",
                45 : "IDRP",
                46 : "RSVP",
                47 : "GRE",
                48 : "DSR",
                49 : "BNA",
                50 : "ESP",
                51 : "AH",
                53: "SWIPE",
                54 : "NARP",
                55 : "MOBILE",
                56 : "TLSP",
                57 : "SKIP",
                58 : "IPv6-ICMP",
                62 : "CFTP",
                66 : "RVD",
                67 : "IPPC",
                70 : "VISA",
                71 : "IPCV",
                72 : "CPNX",
                73 : "CPHB",
                84 : "TTP",
                86 : "DGP",
                87 : "TCF",
                91 : "LARP",
                92 : "MTP",
                94 : "IPIP",
                95 : "MICP",
                97 : "ETHERIP",
                98 : "ENCAP",
                100 : "GMTP",
                101: "IFMP",
                102 : "PNNI",
                103 : "PIM",
                104 : "ARIS",
                105 : "SCPS",
                106 : "QNX",
                107 : "A/N",
                108 : "IPComp",
                109 : "SNP",
                112 : "VRRP",
                113 : "PGM",
                115 : "L2TP",
                116 : "DDX",
                117 : "IATP",
                118 : "STP",
                119 : "SRP",
                120 : "UTI",
                121 : "SMP",
                122 : "SM",
                123 : "PTP",
                125 : "FIRE",
                126 : "CRTP",
                127 : "CRUDP",
                128 : "SSCOPMCE",
                129 : "IPLT",
                130 : "SPS",
                131 : "PIPE",
                132 : "SCTP",
                133 : "FC",
                139 : "HIP",
                141 : "WESP",
                142 : "ROHC",
                143 : "Ethernet",
                
            }

class ToggledFrame(Frame):

    def __init__(self, parent, text="", *args, **options):
        Frame.__init__(self, parent, *args, **options)

        self.show = IntVar()
        self.show.set(0)

        self.title_frame = ttk.Frame(self)
        self.title_frame.pack(fill="x", expand=1)

        ttk.Label(self.title_frame, text=text).pack(side="left", fill="x", expand=1)

        self.toggle_button = ttk.Checkbutton(self.title_frame, width=4, text='+', command=self.toggle,
                                            variable=self.show, style='Toolbutton')
        self.toggle_button.pack(side="left")

        self.sub_frame = Frame(self, relief="sunken", borderwidth=1)

    def toggle(self):
        if bool(self.show.get()):
            self.sub_frame.pack(fill="x", expand=1)
            self.toggle_button.configure(text='-')
        else:
            self.sub_frame.forget()
            self.toggle_button.configure(text='+')

def filter_buttons_dropdown():
    global network_protocol_prompt
    network_protocol_prompt = False
    first_level_filter_buttons = Toplevel(root)
    first_level_filter_buttons.title("")
    first_level_filter_buttons.geometry("365x100")

    def prompt_network(filter_text_value1):
        for widget in first_level_filter_buttons.winfo_children():
            widget.destroy()

        filter_text_value = filter_text_value1
        var = StringVar()
        filter_network_entry = Entry(first_level_filter_buttons, bg="black", width=20, font=14, fg="white", textvariable=var)

        filter_network_entry.pack(pady=5)

        def filter_treeview():
            filter_entry_value = filter_network_entry.get().upper()
            for child in my_tree.get_children():
                index_of_treeview_value =0
                if filter_text_value == "Protocol": index_of_treeview_value=3
                elif filter_text_value == "Source": index_of_treeview_value=1
                elif filter_text_value == "Destination": index_of_treeview_value=2

                filtered_value_check = my_tree.item(child)["values"][index_of_treeview_value]

                if filtered_value_check != filter_entry_value:
                    my_tree.detach(child)
        filter_network_btn = Button(first_level_filter_buttons, command=filter_treeview, text="Filter", font=14, bg="red")
        filter_network_btn.pack()
        

    filter_network_protocols = Button(first_level_filter_buttons, text='Network Protocol', height=5, width=15, font=14, command= lambda filter_text_value1="Protocol": prompt_network(filter_text_value1))
    filter_network_protocols.pack(side=LEFT)
    filter_src = Button(first_level_filter_buttons, text='Source', height=5, width=11, font=14, command= lambda filter_text_value1="Source": prompt_network(filter_text_value1))
    filter_src.pack(side=LEFT)
    filter_dst = Button(first_level_filter_buttons, text='Destination', height=5, width=11, font=14, command= lambda filter_text_value1="Destination": prompt_network(filter_text_value1))
    filter_dst.pack(side=LEFT)


class sniffingThread(threading.Thread):

    def __init__(self, threadID, name, if_name, iteration_var_1, my_tree):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.if_name = if_name
        self.iteration_var_1 = iteration_var_1
        self.my_tree = my_tree
    def run(self):
        # print(self.if_name)
        def displaypackets(packet):
            
            packet_src=""
            packet_dst= ""
            packet_protocol=""
            packet_seq=""
            if packet.haslayer(IP):
                packet_seq = str(packet[IP].sport) + " -> " + str(packet[IP].dport)
                packet_src = packet[IP].src
                packet_dst = packet[IP].dst
                protocol_number=""
                protocol_number = packet[IP].proto

                if packet.haslayer(TCP) and (packet.sport==80 or packet.dport==80 or packet.dport==8060 or packet.sport==8060):
                    packet_protocol = "HTTP"
                elif packet.haslayer(UDP) and (packet.dport==53 or packet.sport==53):
                    packet_protocol = "DNS"
                else:
                    packet_protocol = protocol_number_dictionary[protocol_number]
            elif packet.haslayer(IPv6):
                packet_src = packet[IPv6].src
                packet_dst = packet[IPv6].dst
                if packet.haslayer(TCP) and (packet.sport==80 or packet.dport==80 or packet.dport==8060 or packet.sport==8060):
                    packet_protocol = "HTTP"
                elif packet.haslayer(UDP) and (packet.dport==53 or packet.sport==53):
                    packet_protocol = "DNS"

            elif packet.haslayer(ARP):
                packet_dst = "Broadcast"
                packet_src = packet.src
                packet_protocol = "ARP"
        #stop

            packet_length = len(packet)
            self.my_tree.insert("", 'end', iid=self.iteration_var_1, values=(self.iteration_var_1, packet_src, packet_dst, packet_protocol, packet_length, packet_seq))
            packets_list_storage.append(packet)

            self.iteration_var_1 = self.iteration_var_1 + 1
        global packets_to_sniff
        sniff(prn=displaypackets, iface=self.if_name, count=int(packets_to_sniff)+1)
        # default count set to 300
        # sniff(lambda x:x.show(), iface=self.if_name)
        
def save_command():
    savedpcapfilename = "{}packets{}.pcap".format(rand_num1, rand_num2)
    wrpcap(savedpcapfilename, packets_list_storage)
    saved = Toplevel(root)
    saved.geometry("500x100")
    def deletesavedwindow():
        saved.destroy()
    textw = "Your file has been saved to " + os.getcwd()
    t = Label(saved, text=textw + "as " + savedpcapfilename, font=("Georgia 10"))
    t.pack()
    Button(saved, text="Ok", command=deletesavedwindow).pack()

def io_graph_command():
    packets_list_storage_plot = PacketList(packets_list_storage)
    packets_list_storage_plot.plot(lambda packets_list_storage:len(packets_list_storage))

# try:
#                 my_tree.item(child)["values"][1] = socket.gethostbyaddr(source_val)[0]
#             except Exception:
#                 pass

#             try:
#                 my_tree.item(child)["values"][2] = socket.gethostbyaddr(dest_val)[0]
#             except Exception:
#                 pass
domain_dictionary = {}

def dns_resolve():
    for child in my_tree.get_children():
        protocol = my_tree.item(child)["values"][3]
        x = my_tree.item(child)["values"][0]
        if protocol == "DNS":
            try: 
                packets_list_storage[x].qd.qname
                domain_dictionary[packets_list_storage[x].an[1].rdata] = str(packets_list_storage[x].an[1].rrname)
            except Exception:
                pass
    
    for child in my_tree.get_children():
        
        src_value = my_tree.item(child)["values"][1]

        dst_value = my_tree.item(child)["values"][2]

        if src_value in domain_dictionary:  

            dst_value = my_tree.item(child)["values"][2]

            uno = my_tree.item(child)["values"][0]
            protocol2 = my_tree.item(child)["values"][3]
            pktlength = my_tree.item(child)["values"][4]
            
            my_tree.delete(child)
            my_tree.insert("", 'end', iid=uno, values=(uno, domain_dictionary[src_value], dst_value, protocol2, pktlength))

        if dst_value in domain_dictionary:
            src_value = my_tree.item(child)["values"][1]

            uno = my_tree.item(child)["values"][0]
            protocol2 = my_tree.item(child)["values"][3]
            pktlength = my_tree.item(child)["values"][4]
            my_tree.delete(child)
            my_tree.insert("", 'end', iid=uno, values=(uno, src_value, domain_dictionary[dst_value], protocol2, pktlength))


def hide_all_frames():
    for widget in root.winfo_children():
        widget.destroy()
    

def on_click_packet(e):
    for widgets in info_text_frame_area.winfo_children():
        widgets.destroy()
    
    #Get record #
    selected = my_tree.focus()
    # Get record values
    values = my_tree.item(selected, 'values')
    val_No = int(values[0])
    # print(packets_list_storage[val_No].show)

    # print out hexdump
    t3 = ToggledFrame(info_text_frame_area, text='Ethernet', relief="raised", borderwidth=1)
    t3.pack(fill="x", expand=1, pady=2, padx=2, anchor="n")

    t3_sub_frame_text=""
    field_names3 = [field.name for field in Ether.fields_desc]
    for field_name3 in field_names3:
        t3_sub_frame_text+=field_name3 + ": " +str(getattr(packets_list_storage[val_No], field_name3)) + "\n"
    Label(t3.sub_frame, text=t3_sub_frame_text, justify="left").pack(side="left")

    if packets_list_storage[val_No].haslayer(IP): 

        t = ToggledFrame(info_text_frame_area, text='Internet protocol version '+str(packets_list_storage[val_No][IP].version) + ', Src: ' + packets_list_storage[val_No][IP].src + ', Dst: ' + packets_list_storage[val_No][IP].dst, relief="raised", borderwidth=1)
        t.pack(fill="x", expand=1, pady=2, padx=2, anchor="n")

        t_sub_frame_text=""

        field_names = [field.name for field in IP.fields_desc]

        for field_name in field_names:
            t_sub_frame_text+=field_name + ": " +str(getattr(packets_list_storage[val_No][IP], field_name)) + "\n"
        
        # print(t_sub_frame_text)
       
        Label(t.sub_frame, text=t_sub_frame_text, justify="left").pack(side="left")
        if packets_list_storage[val_No].haslayer(UDP):
            t2 = ToggledFrame(info_text_frame_area, text='User Datagram Protocol', relief="raised", borderwidth=1)
            t2.pack(fill="x", expand=1, pady=2, padx=2, anchor="n")
            t2_sub_frame_text=""
            field_names = [field.name for field in UDP.fields_desc]
            for field_name in field_names:
                t2_sub_frame_text+=field_name + ": " +str(getattr(packets_list_storage[val_No][IP], field_name)) + "\n"
            Label(t2.sub_frame, text=t2_sub_frame_text, justify="left").pack(side="left")
            if packets_list_storage[val_No][UDP].dport==53 or packets_list_storage[val_No][UDP].sport==53:
                t4_sub_frame_text=""
                t4 = ToggledFrame(info_text_frame_area, text='Domain Name System', relief="raised", borderwidth=1)
                t4.pack(fill="x", expand=1, pady=2, padx=2, anchor="n")
                field_names = [field.name for field in DNS.fields_desc]
                for field_name in field_names:
                    t4_sub_frame_text+=field_name + ": " +str(getattr(packets_list_storage[val_No][IP], field_name)) + "\n"
                Label(t4.sub_frame, text=t4_sub_frame_text, justify="left").pack(side="left")
            #content for t2 here
    
    #content for t3
        if packets_list_storage[val_No].haslayer(TCP):
            t2 = ToggledFrame(info_text_frame_area, text='Transmission Control Protocol', relief="raised", borderwidth=1)
            t2.pack(fill="x", expand=1, pady=2, padx=2, anchor="n")
            t2_sub_frame_text=""
            field_names = [field.name for field in TCP.fields_desc]
            for field_name in field_names:
                t2_sub_frame_text+=field_name + ": " +str(getattr(packets_list_storage[val_No][IP], field_name)) + "\n"
            Label(t2.sub_frame, text=t2_sub_frame_text, justify="left").pack(side="left")
            if packets_list_storage[val_No][TCP].sport==80 or packets_list_storage[val_No][TCP].dport==80 or packets_list_storage[val_No][TCP].dport==8060 or packets_list_storage[val_No][TCP].sport==8060:
                t4 = ToggledFrame(info_text_frame_area, text='Hypertext Transfer Protocol', relief="raised", borderwidth=1)
                t4.pack(fill="x", expand=1, pady=2, padx=2, anchor="n")
                t4_sub_frame_text=packets_list_storage[val_No].load
                Label(t4.sub_frame, text=t4_sub_frame_text, justify="left").pack(side="left")

        # t4 = ToggledFrame(info_text_frame_area, text='Raw', relief="raised", borderwidth=1)
        # t4.pack(fill="x", expand=1, pady=2, padx=2, anchor="n")
        # t4_sub_frame_text=packets_list_storage[val_No].load
        
        # Label(t4.sub_frame, text=t4_sub_frame_text, justify="left").pack(side="left")
    elif packets_list_storage[val_No].haslayer(IPv6):

        t = ToggledFrame(info_text_frame_area, text='Internet protocol version 6' + ', Src: ' + packets_list_storage[val_No][IPv6].src + ', Dst: ' + packets_list_storage[val_No][IPv6].dst, relief="raised", borderwidth=1)
        t.pack(fill="x", expand=1, pady=2, padx=2, anchor="n")

        t_sub_frame_text=""

        field_names = [field.name for field in IPv6.fields_desc]

        for field_name in field_names:
            t_sub_frame_text+=field_name + ": " +str(getattr(packets_list_storage[val_No][IPv6], field_name)) + "\n"
        
        # print(t_sub_frame_text)
       
        Label(t.sub_frame, text=t_sub_frame_text, justify="left").pack(side="left")
        if packets_list_storage[val_No].haslayer(UDP):
            t2 = ToggledFrame(info_text_frame_area, text='User Datagram Protocol', relief="raised", borderwidth=1)
            t2.pack(fill="x", expand=1, pady=2, padx=2, anchor="n")
            t2_sub_frame_text=""
            field_names = [field.name for field in UDP.fields_desc]
            for field_name in field_names:
                t2_sub_frame_text+=field_name + ": " +str(getattr(packets_list_storage[val_No][IPv6], field_name)) + "\n"
            Label(t2.sub_frame, text=t2_sub_frame_text, justify="left").pack(side="left")
            if packets_list_storage[val_No][UDP].dport==53 or packets_list_storage[val_No][UDP].sport==53:
                t4_sub_frame_text=""
                t4 = ToggledFrame(info_text_frame_area, text='Domain Name System', relief="raised", borderwidth=1)
                t4.pack(fill="x", expand=1, pady=2, padx=2, anchor="n")
                field_names = [field.name for field in DNS.fields_desc]
                for field_name in field_names:
                    t4_sub_frame_text+=field_name + ": " +str(getattr(packets_list_storage[val_No][IPv6], field_name)) + "\n"
                Label(t4.sub_frame, text=t4_sub_frame_text, justify="left").pack(side="left")
            #content for t2 here
    
    #content for t3
        if packets_list_storage[val_No].haslayer(TCP):
            t2 = ToggledFrame(info_text_frame_area, text='Transmission Control Protocol', relief="raised", borderwidth=1)
            t2.pack(fill="x", expand=1, pady=2, padx=2, anchor="n")
            t2_sub_frame_text=""
            field_names = [field.name for field in TCP.fields_desc]
            for field_name in field_names:
                t2_sub_frame_text+=field_name + ": " +str(getattr(packets_list_storage[val_No][IPv6], field_name)) + "\n"
            Label(t2.sub_frame, text=t2_sub_frame_text, justify="left").pack(side="left")
            if packets_list_storage[val_No][TCP].sport==80 or packets_list_storage[val_No][TCP].dport==80 or packets_list_storage[val_No][TCP].dport==8060 or packets_list_storage[val_No][TCP].sport==8060:
                t4 = ToggledFrame(info_text_frame_area, text='Hypertext Transfer Protocol', relief="raised", borderwidth=1)
                t4.pack(fill="x", expand=1, pady=2, padx=2, anchor="n")
                t4_sub_frame_text=packets_list_storage[val_No].load
                Label(t4.sub_frame, text=t4_sub_frame_text, justify="left").pack(side="left")

    if packets_list_storage[val_No].haslayer(ARP):
        t = ToggledFrame(info_text_frame_area, text='Address Resolution Protocol ', relief="raised", borderwidth=1)
        t.pack(fill="x", expand=1, pady=2, padx=2, anchor="n")

        t_sub_frame_text=""

        field_names = [field.name for field in ARP.fields_desc]

        for field_name in field_names:
            t_sub_frame_text+=field_name + ": " +str(getattr(packets_list_storage[val_No][ARP], field_name)) + "\n"

        Label(t.sub_frame, text=t_sub_frame_text, justify="left").pack(side="left")
    # print(hexdump(packets_list_storage[val_No]))
    # print(packets_list_storage[val_No][IP].version)

    # current_row = my_tree.set(e)
    # cur_id_value = current_row["No."]
    # print(packets_list_storage[cur_id_value])


def open_command():
    # text_file = filename

    f = filedialog.askopenfile(title="Open File", filetypes=(("pcap files", "*.pcap"), ("all files", "*.*")))
    filename = f.name
       
    
    hide_all_frames()

    filter_bar = Frame(root, height=100, bg='green')
    filter_bar.pack(fill=BOTH, expand=True)

    filter_button = Button(filter_bar, text='Filter', height=10, width=20, font=18, command=filter_buttons_dropdown)
    filter_button.pack(side=LEFT, padx=100)
    global info_text_frame_area
    info_text_frame_area = Frame(filter_bar, bg='white')
    info_text_frame_area.pack(side=RIGHT, expand=TRUE, fill=BOTH)

    
    #fill=Y, pady=50
    global my_tree
    my_tree = ttk.Treeview(root)
    my_tree['columns'] = ("No.", "Source", "Destination", "Protocol", "Length", "Info")

    style = ttk.Style(root)
    style.configure("Treeview", rowheight=30)
    my_tree.configure(style="Treeview")

    # my_tree.column("#0", width=20)
    my_tree.column("No.", anchor=W, width=50)
    my_tree.column("Source", anchor=W, width=250)
    my_tree.column("Destination", anchor=CENTER, width=250)
    my_tree.column("Protocol", anchor=W, width=100)
    my_tree.column("Length", anchor=W, width=100)

    # my_tree.heading("#0", text="", anchor=W)
    my_tree.heading("No.", text="No.", anchor=W)
    my_tree.heading("Source", text="Source", anchor=W)
    my_tree.heading("Destination", text="Destination", anchor=W)
    my_tree.heading("Protocol", text="Protocol", anchor=W)
    my_tree.heading("Length", text="Length", anchor=W)
    my_tree.heading("Info", text="Info", anchor=W)
    my_tree.pack(fill=BOTH, expand=True)

    my_tree.bind("<Double-1>", on_click_packet)
    # menu
    new_menu = Menu(root)
    root.config(menu=new_menu)
    # file menu

    file_new_menu = Menu(new_menu, tearoff=False)
    new_menu.add_cascade(label="File", menu=file_new_menu)
    file_new_menu.add_command(label="Open", command=open_command)
    file_new_menu.add_command(label="Save As", command=save_command)
    file_new_menu.add_separator()
    file_new_menu.add_command(label="Exit", command=root.quit)

    view_menu = Menu(new_menu, tearoff=False)
    new_menu.add_cascade(label="View", menu=view_menu)
    view_menu.add_command(label="Resolve DNS Host Names", command=dns_resolve)

    statistics_menu = Menu(new_menu, tearoff=False)
    new_menu.add_cascade(label="Statistics", menu=statistics_menu)
    statistics_menu.add_command(label="Generate I/O Graph", command=io_graph_command)



    scapy_cap = rdpcap(filename)

    blahi = 0
    packet_src=""
    packet_dst= ""
    packet_protocol=""
    packet_seq=""
    for packet in scapy_cap:
        if packet.haslayer(IP):
            packet_seq = str(packet[IP].sport) + " -> " + str(packet[IP].dport)
            packet_src = packet[IP].src
            packet_dst = packet[IP].dst
            protocol_number=""
            protocol_number = packet[IP].proto

            if packet.haslayer(TCP) and (packet.sport==80 or packet.dport==80 or packet.dport==8060 or packet.sport==8060):
                packet_protocol = "HTTP"
            elif packet.haslayer(UDP) and (packet.dport==53 or packet.sport==53):
                packet_protocol = "DNS"
            else:
                packet_protocol = protocol_number_dictionary[protocol_number]
        elif packet.haslayer(IPv6):
            packet_src = packet[IPv6].src
            packet_dst = packet[IPv6].dst
            if packet.haslayer(TCP) and (packet.sport==80 or packet.dport==80 or packet.dport==8060 or packet.sport==8060):
                packet_protocol = "HTTP"
            elif packet.haslayer(UDP) and (packet.dport==53 or packet.sport==53):
                packet_protocol = "DNS"

        elif packet.haslayer(ARP):
            packet_dst = "Broadcast"
            packet_src = packet.src
            packet_protocol = "ARP"
        #stop

        packet_length = len(packet)

        my_tree.insert("", 'end', iid=blahi, values=(blahi, packet_src, packet_dst, packet_protocol, packet_length, packet_seq))
        blahi=blahi+1
        packets_list_storage.append(packet)

def open_sniff_page(if_name):
    hide_all_frames()

    filter_bar = Frame(root, height=100, bg='green')
    filter_bar.pack(fill=BOTH, expand=True)

    filter_button = Button(filter_bar, text='Filter', height=10, width=20, font=18, command=filter_buttons_dropdown)
    filter_button.pack(side=LEFT, padx=100)
    global info_text_frame_area
    info_text_frame_area = Frame(filter_bar, bg='white')
    info_text_frame_area.pack(side=RIGHT, expand=TRUE, fill=BOTH)

    
    #fill=Y, pady=50
    global my_tree
    my_tree = ttk.Treeview(root)
    my_tree['columns'] = ("No.", "Source", "Destination", "Protocol", "Length", "Info")

    style = ttk.Style(root)
    style.configure("Treeview", rowheight=30)
    my_tree.configure(style="Treeview")

    # my_tree.column("#0", width=20)
    my_tree.column("No.", anchor=W, width=50)
    my_tree.column("Source", anchor=W, width=250)
    my_tree.column("Destination", anchor=CENTER, width=250)
    my_tree.column("Protocol", anchor=W, width=100)
    my_tree.column("Length", anchor=W, width=100)
    my_tree.column("Info", anchor=W, width=250)

    # my_tree.heading("#0", text="", anchor=W)
    my_tree.heading("No.", text="No.", anchor=W)
    my_tree.heading("Source", text="Source", anchor=W)
    my_tree.heading("Destination", text="Destination", anchor=W)
    my_tree.heading("Protocol", text="Protocol", anchor=W)
    my_tree.heading("Length", text="Length", anchor=W)
    my_tree.heading("Info", text="Info", anchor=W)
    my_tree.pack(fill=BOTH, expand=True)

    my_tree.bind("<Double-1>", on_click_packet)
    # menu
    new_menu = Menu(root)
    root.config(menu=new_menu)
    # file menu
    file_new_menu = Menu(new_menu, tearoff=False)

    new_menu.add_cascade(label="File", menu=file_new_menu)
    file_new_menu.add_command(label="Open", command=open_command)
    file_new_menu.add_command(label="Save As", command=save_command)
    file_new_menu.add_separator()
    file_new_menu.add_command(label="Exit", command=root.quit)

    view_menu = Menu(new_menu, tearoff=False)
    new_menu.add_cascade(label="View", menu=view_menu)
    view_menu.add_command(label="Resolve DNS Host Names", command=dns_resolve)

    statistics_menu = Menu(new_menu, tearoff=False)
    new_menu.add_cascade(label="Statistics", menu=statistics_menu)
    statistics_menu.add_command(label="Generate I/O Graph", command=io_graph_command)


    snifferThread = sniffingThread(1, "Sniffer", if_name, 0, my_tree)
    snifferThread.start()

root = Tk()
root.title("CapyNet Analysis Tool")

width_value=root.winfo_screenwidth()
height_value=root.winfo_screenheight()

root.geometry("%dx%d+0+0" % (width_value, height_value))


menu_bar = Menu(root)
root.config(menu=menu_bar)

# file menu
file_menu = Menu(menu_bar, tearoff=False)
menu_bar.add_cascade(label="File", menu=file_menu)
file_menu.add_command(label="Open", command=open_command)
file_menu.add_command(label="Save As", command=save_command)
file_menu.add_separator()
file_menu.add_command(label="Exit", command=root.quit)

view_menu = Menu(menu_bar, tearoff=False)
menu_bar.add_cascade(label="View", menu=view_menu)
view_menu.add_command(label="Resolve DNS Host Names", command=dns_resolve)

statistics_menu = Menu(menu_bar, tearoff=False)
menu_bar.add_cascade(label="Statistics", menu=statistics_menu)
statistics_menu.add_command(label="Generate I/O Graph", command=io_graph_command)

# Front Page
title = Label(root, text="Select your network interface")
title.config(font=("Alfa Slab One", 24, 'bold'))
title.pack(pady=25, anchor='center')

if_frame = LabelFrame(root)
canvas = Canvas(if_frame, bg='#FFFFFF', width=300, height=300, scrollregion=(0, 0, 500, 500))

text_scroll = Scrollbar(if_frame)
text_scroll.pack(side=RIGHT, fill=Y)

canvas.pack(side=RIGHT, fill=BOTH, expand=1, )
if_frame.pack(fill=BOTH, expand=1, padx=30, pady=10)

adapters = get_working_ifaces()

# input box
spacer0=Label(canvas, text="", bg="white")
spacer0.pack(pady=10)
Label(canvas, text="Enter amount of packets you want to sniff here:", font=14, borderwidth=2).pack()
Label(canvas, text="*If left blank, default amount of packets will be 300", font=10, fg="red").pack()

packet_amount_entry = Entry(canvas, width=10, bd=10, font=("Georgia 20"))
packet_amount_entry.pack(anchor='center', pady=5)

def submit_pkt():
    global packets_to_sniff
    packets_to_sniff = packet_amount_entry.get()
    # print(packets_to_sniff)

packet_amount_submit = Button(canvas, text="Submit", command=submit_pkt, bg="GREEN", font=(14))
packet_amount_submit.pack()

spacer1=Label(canvas, text="", bg="white")
spacer1.pack(pady=20)


for i in range(len(adapters)):
    iface_name = adapters[i].name
    Button(canvas, text=iface_name, command=lambda if_name=iface_name: open_sniff_page(if_name), font=16).pack(pady=2,
                                                                                                      anchor='center')

root.mainloop()
