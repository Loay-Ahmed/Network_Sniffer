from tkinter import *
from tkinter.ttk import *
import threading
import collections
import scapy.all as scapy

thread = None
should_we_stop = True
subdomain = ''

src_ip_dict = collections.defaultdict(list)

###### functions ######
def start_button():
    global should_we_stop
    global subdomain
    global thread

    subdomain = subdomain_entry.get()

    if (thread is None) or (not thread.is_alive()):
        should_we_stop = False
        thread = threading.Thread(target=sniffing)
        thread.start()

def stop_button():
    global should_we_stop

    should_we_stop = True

def sniffing():
    scapy.sniff(prn=find_ips, stop_filter=stop_sniffing)

def stop_sniffing(packet):
    global should_we_stop
    return should_we_stop

def find_ips(packet):
    global treev
    global src_ip_dict
    global subdomain

    print(packet.show())

    if "IP" in packet:
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst

        if src_ip[0:len(subdomain)] == subdomain:
            if src_ip not in src_ip_dict:
                src_ip_dict[src_ip].append(dst_ip)

                row = treev.insert('', index=END, text=src_ip)
                treev.insert(row, END, text=dst_ip)
                treev.pack(fill=X)

            else:
                if dst_ip not in src_ip_dict[src_ip]:
                    src_ip_dict[src_ip].append(dst_ip)

                    cur_item = treev.focus()

                    if (treev.item(cur_item)["text"] == src_ip):
                        treev.insert(cur_item, END, text=dst_ip)


###### main window and it's customizations ######
root = Tk()
root.geometry("500x500")
root.title("Network Sniffer")

###### labels and buttons ,etc... ######
Label(root, text="Network Sniffer", font="Poppins 24 bold").pack()
Label(root, text="Enter ip subdomain", font="Poppins 15 bold").pack()

subdomain_entry = Entry(root)
subdomain_entry.pack(pady=10, ipadx=50, ipady=5)

treev = Treeview(root, height="400")
treev.column('#0')

button_frame = Frame(root)

Button(button_frame, text="Start sniffing", command=start_button, width=15).pack(side=LEFT)
Button(button_frame, text="Stop sniffing", command=stop_button,width=15).pack(side=LEFT)

button_frame.pack(side=BOTTOM, pady=10)

###### running the window ######
root.mainloop()
