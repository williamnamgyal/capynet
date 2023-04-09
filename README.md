# CapyNet
Network Packet Analysis Application built using Python only, allows for capturing, analysis, and visualization of packets.

CapyNet - Application for network packet analysis
Coded in Python 3 (3.7.9), using Scapy for capturing packets, and tkinter for GUI/Front-end development

**Install: **

All platforms supported,
Prerequisites: Python <= 3.8 installed, all packages in requirements.txt installed
Install Python: https://www.python.org/downloads/ https://www.youtube.com/watch?v=Kn1HF3oD19c
Install all packages in requirements.txt: pip install -r requirements.txt

Or Manually Install:
Install Scapy, MatPlotLib, and Tkinter:
pip install --pre scapy[basic]
pip install matplotlib
pip install tk
pip install -r requirements.txt

How to Use App:

When opened, it will display a list of your network interfaces on your network.
Click on whichever network interface you want to scan - Note it lists all network interfaces, and some interfaces may be inactive, so make sure you know which interface to sniff on
It will prompt you how many packets you want to sniff after clicking your network interface name
Enter the amount of packets (Notice extremely large amounts of packets like 100,000 might cause application to freeze for a couple seconds, and then load.)

Features:
Filtering network packets display by Network Protocol, Source, and Destination
Viewing more detailed information about packets
IPv6 Support
Generate I/O Graphs from packets
Opening pcap/pcapng files to analyze
Saving sniffed packets into file on computer
DNS Host name resolution for DNS Response packets

Filtering network packets:
Click on Big top left button that says filter, and choose 3 options, either Network Protocol, Source, or Destination. When choosing a single one, a textbox will be prompted, and input either the network protocol (Ex: TCP, HTTP, etc.), or source/destination address (Ex: 24.5.91.64, 2345:0425:2CA1:0000:0000:0567:5673:23b5, etc.). Once finished inputting, click the red filter button, which will implement the filtering.

Viewing more detailed information about packets:
To View more information about packets, just double click on them, and on the top half of the screen it will display the information and field descriptions about the packet.

Generating I/O Graphs:
After having sniffed packets open, click on statistics in the menu header on the top left, and click Generate I/O Graph, which will generate a graph for the packets, and give you options to zoom in, out, move around, and save. (MatPlotLib)

Opening pcap files:
Navigate to the menu header labeled "File" in the top left, and hover/click on it, and then click open as one of the dropdown options. Then, select the pcap or pcapng file.

Saving sniffed packets:
Navigate to the menu header labeled "File" in the top left, and hover/click on it, and click "Save As" from the dropdown menu. It will then open up a menu telling the directory it was saved in (default directory) and the file name.

DNS response packet host name resolution:
Navigate to the menu header labeled "View", and hover/click over it and select "Resolve DNS Hostnames" which will resolve all the DNS hosts to their domain hostnames.

Project is 100% done using only Python3.7.0 along with packages
