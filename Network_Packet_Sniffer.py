
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from scapy.all import sniff, IP, TCP, UDP
import threading
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use("TkAgg")

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Full-Fledged Packet Sniffer")
        self.root.geometry("700x500")
        self.root.configure(bg="#2C3E50")
        
       
        style = ttk.Style()
        style.configure("TButton", font=("Arial", 12), padding=5)
        style.configure("TLabel", font=("Arial", 12), background="#2C3E50", foreground="white")
        
        self.packet_count = 0
        self.protocol_count = {'TCP': 0, 'UDP': 0, 'ICMP': 0}
        self.sniffing = False
        
        self.label = ttk.Label(root, text="Packet Sniffer - Network Monitoring Tool", font=("Arial", 14, "bold"))
        self.label.pack(pady=10)
        
        self.text_area = scrolledtext.ScrolledText(root, width=80, height=15, font=("Courier", 10))
        self.text_area.pack(padx=10, pady=10)
        
        button_frame = ttk.Frame(root)
        button_frame.pack(pady=10)
        
        self.start_button = ttk.Button(button_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.grid(row=0, column=0, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop Sniffing", command=self.stop_sniffing)
        self.stop_button.grid(row=0, column=1, padx=5)
        self.stop_button.state(["disabled"])
        
        self.summary_button = ttk.Button(button_frame, text="Show Summary", command=self.show_summary)
        self.summary_button.grid(row=0, column=2, padx=5)
        
    def process_packet(self, packet):
        if IP in packet:
            ip_layer = packet[IP]
            protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if packet.haslayer('ICMP') else "Other"
            
            self.packet_count += 1
            if protocol in self.protocol_count:
                self.protocol_count[protocol] += 1
            
            packet_info = (f"Packet Size: {len(packet)} bytes\n"
                           f"Source IP: {ip_layer.src}\n"
                           f"Destination IP: {ip_layer.dst}\n"
                           f"Protocol: {protocol}\n"
                           f"{"-" * 40}\n")
            
            self.text_area.insert(tk.END, packet_info)
            self.text_area.yview(tk.END)
    
    
    def sniff_packets(self):
        sniff(prn=self.process_packet, store=False, stop_filter=lambda p: not self.sniffing)
    
    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.start_button.state(["disabled"])
            self.stop_button.state(["!disabled"])
            threading.Thread(target=self.sniff_packets, daemon=True).start()
    
    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.state(["!disabled"])
        self.stop_button.state(["disabled"])
    
    def show_summary(self):
        total_packets = sum(self.protocol_count.values())
        
        if total_packets == 0:
            messagebox.showinfo("Summary", "No packets captured yet.")
            return
        
        protocols = list(self.protocol_count.keys())
        counts = list(self.protocol_count.values())

        plt.figure(figsize=(8, 6), facecolor="#34495E")
        
        plt.subplot(1, 2, 1)
        plt.pie(counts, labels=protocols, autopct='%1.1f%%', startangle=140, colors=["#E74C3C", "#3498DB", "#2ECC71"])
        plt.axis('equal')
        plt.title(f"Protocol Distribution - Total Packets: {total_packets}", color='white')

        plt.subplot(1, 2, 2)
        plt.bar(protocols, counts, color=["#E74C3C", "#3498DB", "#2ECC71"])
        plt.title("Packet Count by Protocol", color='white')
        plt.xlabel("Protocols", color='white')
        plt.ylabel("Count", color='white')
        
        plt.tight_layout()
        plt.show()

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
