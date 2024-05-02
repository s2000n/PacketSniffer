import tkinter as tk
import webbrowser
from scapy.all import *

sniffing_running = False

def start_sniffing():
    global sniffing_running
    if not sniffing_running:
        monitor_box.insert(tk.END, "Sniffing started...\n")
        sniffing_running = True
        sniff_packets()
        sniffing_button.config(text="Stop Sniffing", command=stop_sniffing)

def sniff_packets():
    if sniffing_running:
        packet = sniff(filter="tcp", count=1)
        process_packet(packet[0])
        root.after(1500, sniff_packets)

def process_packet(packet):
    monitor_box.insert(tk.END, f"Packet: {packet.summary()}\n")
    monitor_box.see(tk.END)

def stop_sniffing():
    global sniffing_running
    if sniffing_running:
        sniffing_running = False
        monitor_box.insert(tk.END, "Sniffing stopped.\n")
        sniffing_button.config(text="Start Sniffing", command=start_sniffing)

def open_about_link():
    webbrowser.open("https://alfan.link/s2000.n")

def exit_program():
    root.quit()

root = tk.Tk()
root.title("Packet Sniffer")
root.geometry("760x420")
root.resizable(False, False)
root.configure(padx=10, pady=10)  

nav_frame = tk.Frame(root)
nav_frame.grid(row=0, column=0, columnspan=5, sticky="ew")
victim_ip_label = tk.Label(nav_frame, text="Target IP:")
victim_ip_label.grid(row=0, column=0, padx=(0, 10), pady=(0, 5), sticky=tk.W)
victim_ip_entry = tk.Entry(nav_frame, width=50)
victim_ip_entry.grid(row=0, column=1, padx=(0, 10), pady=(0, 5), sticky=tk.W)
sniffing_button = tk.Button(nav_frame, text="Start Sniffing", command=start_sniffing)
sniffing_button.grid(row=0, column=2, padx=(0, 10), pady=(0, 5))
about_button = tk.Button(nav_frame, text="About", command=open_about_link)
about_button.grid(row=0, column=3, padx=(0, 10), pady=(0, 5))
exit_button = tk.Button(nav_frame, text="Exit", command=exit_program)
exit_button.grid(row=0, column=4, pady=(0, 5))

monitor_box_label = tk.Label(root, text="Monitor:")
monitor_box_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
monitor_box = tk.Text(root, width=90, height=20)
monitor_box.grid(row=2, column=0, columnspan=5, padx=5, pady=(10, 5))

root.mainloop()
