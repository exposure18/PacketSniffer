import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time
from scapy.all import sniff, IP, TCP, UDP, Raw, Ether, ARP, get_if_list, wrpcap, rdpcap
import json


class PacketSnifferApp:
    def __init__(self, master):
        self.master = master
        master.title("Python Packet Sniffer")
        master.geometry("1000x700")
        master.configure(bg="#000000")

        # Configure the main window's grid
        self.master.grid_rowconfigure(0, weight=0)  # Control Frame
        self.master.grid_rowconfigure(1, weight=0)  # Status Bar
        self.master.grid_rowconfigure(2, weight=0)  # Combined Alerts/Stats Frame (THIS IS NEW)
        self.master.grid_rowconfigure(3, weight=1)  # Captured Packets Frame (THIS WILL EXPAND)
        self.master.grid_columnconfigure(0, weight=1)  # Only one column for main frames

        # --- Styling ---
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TFrame", background="#1a1a1a")
        style.configure("TLabel", background="#1a1a1a", foreground="#ffffff", font=('Arial', 10))
        style.configure("TButton", background="#333333", foreground="#ffffff", font=('Arial', 10, 'bold'))
        style.map("TButton", background=[('active', '#555555')], foreground=[('active', '#ffffff')])
        style.configure("TCombobox", fieldbackground="#222222", background="#222222", foreground="#ffffff")
        style.map("TCombobox",
                  fieldbackground=[('readonly', '#222222')],
                  selectbackground=[('readonly', '#222222')],
                  selectforeground=[('readonly', '#ffffff')],
                  background=[('readonly', '#222222')],
                  foreground=[('readonly', '#ffffff')])
        self.master.option_add('*TEntry.fieldbackground', '#222222')
        self.master.option_add('*TEntry.foreground', '#ffffff')

        # --- Sniffer State ---
        self.sniffer_thread = None
        self.stop_sniffer_event = threading.Event()
        self.raw_scapy_packets = []  # Stores raw Scapy packets for export
        self.alert_keyword = tk.StringVar(value="sensitive")

        # --- Filter States ---
        self.src_ip_filter = tk.StringVar(value="")
        self.dst_ip_filter = tk.StringVar(value="")
        self.protocol_filter = tk.StringVar(value="")

        # --- Live Monitoring Buffers and Schedule ---
        self.packet_display_buffer = []  # Stores tuples: (formatted_line_text, list_of_tags)
        self.alert_display_buffer = []
        self.display_update_interval_ms = 2000
        self.after_id = None
        self.is_live_sniffing = False

        # --- Protocol Statistics Counters ---
        self.stats_total_packets = 0
        self.stats_total_bytes = 0
        self.stats_protocol_counts = {
            'Ethernet': 0, 'IP': 0, 'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0, 'Other': 0
        }
        self.stats_protocol_bytes = {
            'Ethernet': 0, 'IP': 0, 'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0, 'Other': 0
        }

        # --- UI Elements ---
        self.create_widgets()
        self.update_interface_list()

    def create_widgets(self):
        # --- Controls Frame (Row 0) ---
        control_frame = ttk.Frame(self.master, padding="15", relief="groove", borderwidth=2, style="TFrame")
        control_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)

        # Row 0: Network Interface and Start Button
        ttk.Label(control_frame, text="Network Interface:", style="TLabel").grid(row=0, column=0, padx=5, pady=5,
                                                                                 sticky="w")
        self.interface_var = tk.StringVar()
        self.interface_combobox = ttk.Combobox(control_frame, textvariable=self.interface_var, state="readonly")
        self.interface_combobox.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        control_frame.grid_columnconfigure(1, weight=1)
        self.start_button = ttk.Button(control_frame, text="Start Sniffing", command=self.start_sniffing,
                                       style="TButton")
        self.start_button.grid(row=0, column=2, padx=10, pady=5, sticky="e")

        # Row 1: Alert Keyword and Stop Button
        ttk.Label(control_frame, text="Alert Keyword:", style="TLabel").grid(row=1, column=0, padx=5, pady=5,
                                                                             sticky="w")
        self.alert_keyword_entry = ttk.Entry(control_frame, textvariable=self.alert_keyword, width=30)
        self.alert_keyword_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.stop_button = ttk.Button(control_frame, text="Stop Sniffing", command=self.stop_sniffing,
                                      state=tk.DISABLED, style="TButton")
        self.stop_button.grid(row=1, column=2, padx=10, pady=5, sticky="e")

        # Row 2: Export/Import Buttons
        self.export_button = ttk.Button(control_frame, text="Export Packets", command=self.export_packets,
                                        state=tk.DISABLED, style="TButton")
        self.export_button.grid(row=2, column=1, padx=10, pady=5, sticky="ew")
        self.import_button = ttk.Button(control_frame, text="Import PCAP", command=self.import_pcap_packets,
                                        style="TButton")
        self.import_button.grid(row=2, column=2, padx=10, pady=5, sticky="e")

        # --- Filter Inputs ---
        filter_frame = ttk.LabelFrame(control_frame, text="Packet Filters", padding="10", style="TFrame")
        filter_frame.grid(row=3, column=0, columnspan=3, padx=5, pady=10, sticky="ew")

        ttk.Label(filter_frame, text="Source IP:", style="TLabel").grid(row=0, column=0, padx=5, pady=2, sticky="w")
        self.src_ip_entry = ttk.Entry(filter_frame, textvariable=self.src_ip_filter)
        self.src_ip_entry.grid(row=0, column=1, padx=5, pady=2, sticky="ew")
        filter_frame.grid_columnconfigure(1, weight=1)

        ttk.Label(filter_frame, text="Destination IP:", style="TLabel").grid(row=0, column=2, padx=5, pady=2,
                                                                             sticky="w")
        self.dst_ip_entry = ttk.Entry(filter_frame, textvariable=self.dst_ip_filter)
        self.dst_ip_entry.grid(row=0, column=3, padx=5, pady=2, sticky="ew")
        filter_frame.grid_columnconfigure(3, weight=1)

        ttk.Label(filter_frame, text="Protocol:", style="TLabel").grid(row=1, column=0, padx=5, pady=2, sticky="w")
        self.protocol_combobox = ttk.Combobox(filter_frame, textvariable=self.protocol_filter, state="readonly",
                                              values=["", "IP", "TCP", "UDP", "ICMP", "ARP", "Ether"])
        self.protocol_combobox.grid(row=1, column=1, padx=5, pady=2, sticky="ew")
        self.protocol_combobox.set("")

        # --- Status Bar (Row 1) ---
        self.status_label = ttk.Label(self.master, text="Status: Ready", style="TLabel", anchor="w")
        self.status_label.grid(row=1, column=0, sticky="ew", padx=10, pady=5)

        # --- NEW: Combined Alerts & Statistics Frame (Row 2) ---
        combined_bottom_frame = ttk.Frame(self.master, style="TFrame")
        combined_bottom_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=5)
        combined_bottom_frame.grid_columnconfigure(0, weight=1)  # Alerts column
        combined_bottom_frame.grid_columnconfigure(1, weight=1)  # Stats column

        # --- Alerts Display (Left side of combined_bottom_frame) ---
        alert_frame = ttk.Frame(combined_bottom_frame, padding="10", relief="groove", borderwidth=2, style="TFrame")
        alert_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5), pady=0)  # Added padding to the right
        ttk.Label(alert_frame, text="Active Alerts:", font=('Arial', 12, 'bold'), foreground="#f59e0b",
                  background="#1a1a1a").pack(side=tk.TOP, fill=tk.X, pady=5)
        self.alerts_text = scrolledtext.ScrolledText(alert_frame, wrap=tk.WORD, height=3, bg="#000000", fg="#fbd38d",
                                                     font=('Consolas', 9), relief="flat")
        self.alerts_text.pack(fill=tk.BOTH, expand=True)  # Allow alerts to expand within its sub-frame if needed
        self.alerts_text.config(state=tk.DISABLED)
        ttk.Label(alert_frame,
                  text="(Alerts typically trigger on plaintext data; won't work on encrypted traffic like HTTPS)",
                  font=('Arial', 8, 'italic'), foreground="#aaaaaa", background="#1a1a1a").pack(side=tk.TOP, fill=tk.X,
                                                                                                pady=(2, 0))

        # --- Protocol Statistics Display (Right side of combined_bottom_frame) ---
        stats_frame = ttk.LabelFrame(combined_bottom_frame, text="Protocol Statistics", padding="10", relief="groove",
                                     borderwidth=2, style="TFrame")
        stats_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 0), pady=0)  # Added padding to the left

        # Labels for counts (inside grid for stats_frame)
        self.stats_labels = {}
        row_idx = 0
        for protocol in ['Total', 'Ethernet', 'IP', 'TCP', 'UDP', 'ICMP', 'ARP', 'Other']:
            ttk.Label(stats_frame, text=f"{protocol} Packets:", style="TLabel").grid(row=row_idx, column=0, padx=5,
                                                                                     pady=2, sticky="w")
            self.stats_labels[f'{protocol}_packets'] = ttk.Label(stats_frame, text="0", style="TLabel",
                                                                 font=('Arial', 10, 'bold'), foreground="#e0e0e0")
            self.stats_labels[f'{protocol}_packets'].grid(row=row_idx, column=1, padx=5, pady=2, sticky="w")

            ttk.Label(stats_frame, text=f"{protocol} Bytes:", style="TLabel").grid(row=row_idx, column=2, padx=20,
                                                                                   pady=2, sticky="w")
            self.stats_labels[f'{protocol}_bytes'] = ttk.Label(stats_frame, text="0 Bytes", style="TLabel",
                                                               font=('Arial', 10, 'bold'), foreground="#e0e0e0")
            self.stats_labels[f'{protocol}_bytes'].grid(row=row_idx, column=3, padx=5, pady=2, sticky="w")
            row_idx += 1
        stats_frame.grid_columnconfigure(1, weight=1)  # Allow numbers to expand
        stats_frame.grid_columnconfigure(3, weight=1)

        # --- Captured Packets Display Area (Row 3 - This will get all remaining vertical space) ---
        packet_frame = ttk.Frame(self.master, padding="10", relief="groove", borderwidth=2, style="TFrame")
        packet_frame.grid(row=3, column=0, sticky="nsew", padx=10, pady=10)  # sticky="nsew" for filling all directions

        ttk.Label(packet_frame, text="Captured Packets:", font=('Arial', 12, 'bold'), foreground="#63b3ed",
                  background="#1a1a1a").pack(side=tk.TOP, fill=tk.X, pady=5)

        # Ensure the scrolledtext itself expands within its frame
        self.packet_text = scrolledtext.ScrolledText(packet_frame, wrap=tk.WORD, bg="#000000", fg="#e2e8f0",
                                                     font=('Consolas', 9), relief="flat")
        self.packet_text.pack(fill=tk.BOTH,
                              expand=True)  # This is essential for the text widget to fill its parent frame
        self.packet_text.config(state=tk.DISABLED)

        # --- Color Tag Configuration ---
        self.packet_text.tag_config('tcp', foreground="#FFD700")  # Gold
        self.packet_text.tag_config('udp', foreground="#87CEEB")  # SkyBlue
        self.packet_text.tag_config('icmp', foreground="#FF6347")  # Tomato
        self.packet_text.tag_config('arp', foreground="#DA70D6")  # Orchid
        self.packet_text.tag_config('ether', foreground="#C0C0C0")  # Silver (for pure Ethernet)
        self.packet_text.tag_config('ip', foreground="#98FB98")  # PaleGreen (for general IP)
        self.packet_text.tag_config('alert', foreground="#FF0000",
                                    background="#330000")  # Red for alerts, dark red background

    def update_interface_list(self):
        """Populates the network interface dropdown."""
        try:
            interfaces = get_if_list()
            self.interface_combobox['values'] = interfaces
            if interfaces:
                self.interface_var.set(interfaces[0])
        except Exception as e:
            messagebox.showerror("Error",
                                 f"Could not list interfaces: {e}\nEnsure Npcap/WinPcap is installed on Windows, or run with sudo on Linux.")
            self.interface_combobox['values'] = ["Error loading interfaces"]
            self.interface_var.set("Error loading interfaces")

    def start_sniffing(self):
        interface = self.interface_var.get()
        if not interface or interface == "Error loading interfaces":
            messagebox.showwarning("Warning", "Please select a valid network interface.")
            return

        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.status_label.config(text="Status: Sniffer already running.")
            return

        self.stop_sniffer_event.clear()
        self.raw_scapy_packets = []
        self._clear_display_and_buffers()  # Clears main display and alerts, and resets stats
        self.is_live_sniffing = True

        self._set_ui_sniffing_state(True)

        self.status_label.config(text=f"Status: Starting sniffer on {interface}...")

        current_filters = {
            'src_ip': self.src_ip_filter.get().strip(),
            'dst_ip': self.dst_ip_filter.get().strip(),
            'protocol': self.protocol_filter.get().strip()
        }

        self.sniffer_thread = threading.Thread(target=self._run_sniffer, args=(interface, current_filters))
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()

        self._schedule_display_update()

    def _run_sniffer(self, interface, filters):
        """Internal method to run Scapy sniff in a thread."""
        try:
            bpf_parts = []
            protocol_filter_val = filters['protocol'].lower()

            if protocol_filter_val:
                proto_map = {'tcp': 'tcp', 'udp': 'udp', 'icmp': 'icmp', 'arp': 'arp', 'ip': 'ip', 'ether': 'ether'}
                if protocol_filter_val in proto_map:
                    bpf_parts.append(proto_map[protocol_filter_val])
                else:
                    self.master.after(0, lambda: messagebox.showwarning("Filter Warning",
                                                                        f"Unsupported protocol filter: '{filters['protocol']}'. Ignoring protocol filter."))

            if filters['src_ip']:
                if 'ip' not in bpf_parts and 'ether' not in bpf_parts:
                    bpf_parts.append('ip')
                bpf_parts.append(f"src host {filters['src_ip']}")

            if filters['dst_ip']:
                if 'ip' not in bpf_parts and 'ether' not in bpf_parts:
                    bpf_parts.append('ip')
                bpf_parts.append(f"dst host {filters['dst_ip']}")

            bpf_filter_string = " and ".join(bpf_parts) if bpf_parts else None

            self.master.after(0, lambda: self.status_label.config(
                text=f"Status: Sniffing on {interface} with filter: '{bpf_filter_string if bpf_filter_string else 'None'}'"))

            sniff(prn=self._process_packet, store=False, iface=interface,
                  stop_filter=lambda p: self.stop_sniffer_event.is_set(),
                  filter=bpf_filter_string, timeout=None)

        except Exception as e:
            error_msg = (f"An error occurred during sniffing: {e}\n\n"
                         "Possible causes:\n"
                         "1. Incorrect interface name.\n"
                         "2. Insufficient permissions (try running script with Administrator/sudo).\n"
                         "3. Npcap/WinPcap not installed (on Windows).\n"
                         f"4. Invalid BPF filter used: '{bpf_filter_string if bpf_filter_string else 'None'}'")
            self.master.after(0, lambda: messagebox.showerror("Sniffing Error", error_msg))
            self.master.after(0, lambda: self.status_label.config(text=f"Status: Error: {e}"))
        finally:
            self.master.after(0, self._reset_ui_after_stop)

    def _reset_ui_after_stop(self):
        """Resets UI elements to the stopped state."""
        if self.after_id:
            self.master.after_cancel(self.after_id)
            self.after_id = None

        self._update_display_periodically()  # Ensure any buffered items and stats are shown

        self.is_live_sniffing = False
        self._set_ui_sniffing_state(False)

        if not self.status_label.cget("text").startswith("Error:"):
            self.status_label.config(text="Status: Sniffer stopped.")

    def _set_ui_sniffing_state(self, is_sniffing):
        """Helper to enable/disable UI elements based on sniffing state."""
        self.start_button.config(state=tk.DISABLED if is_sniffing else tk.NORMAL)
        self.stop_button.config(state=tk.NORMAL if is_sniffing else tk.DISABLED)
        self.export_button.config(state=tk.NORMAL if self.raw_scapy_packets else tk.DISABLED)
        self.import_button.config(state=tk.DISABLED if is_sniffing else tk.NORMAL)
        self.interface_combobox.config(state=tk.DISABLED if is_sniffing else "readonly")
        self.alert_keyword_entry.config(state=tk.DISABLED if is_sniffing else tk.NORMAL)
        self.src_ip_entry.config(state=tk.DISABLED if is_sniffing else tk.NORMAL)
        self.dst_ip_entry.config(state=tk.DISABLED if is_sniffing else tk.NORMAL)
        self.protocol_combobox.config(state=tk.DISABLED if is_sniffing else "readonly")

    def _clear_display_and_buffers(self):
        """Clears all text areas and internal packet buffers, and resets stats."""
        self.packet_text.config(state=tk.NORMAL)
        self.packet_text.delete(1.0, tk.END)
        self.packet_text.config(state=tk.DISABLED)

        self.alerts_text.config(state=tk.NORMAL)
        self.alerts_text.delete(1.0, tk.END)
        self.alerts_text.config(state=tk.DISABLED)

        self.packet_display_buffer = []
        self.alert_display_buffer = []
        self.raw_scapy_packets = []

        # Reset statistics counters
        self.stats_total_packets = 0
        self.stats_total_bytes = 0
        for proto in self.stats_protocol_counts:
            self.stats_protocol_counts[proto] = 0
            self.stats_protocol_bytes[proto] = 0
        self._update_protocol_stats_display()  # Update display immediately after reset

    def _schedule_display_update(self):
        """Schedules the periodic display update."""
        self.after_id = self.master.after(self.display_update_interval_ms, self._update_display_periodically)

    def _update_display_periodically(self):
        """Processes buffered packets and alerts and updates the GUI."""
        if self.packet_display_buffer:
            self.packet_text.config(state=tk.NORMAL)
            for line_text, line_tags in self.packet_display_buffer:
                self.packet_text.insert(tk.END, line_text, tuple(line_tags))
            self.packet_text.see(tk.END)
            self.packet_text.config(state=tk.DISABLED)
            self.packet_display_buffer = []

        if self.alert_display_buffer:
            self.alerts_text.config(state=tk.NORMAL)
            for message in self.alert_display_buffer:
                self.alerts_text.insert(tk.END, message + "\n")
            self.alerts_text.see(tk.END)
            self.alerts_text.config(state=tk.DISABLED)
            self.alert_display_buffer = []

        # Update protocol statistics display
        self._update_protocol_stats_display()

        if self.is_live_sniffing and not self.stop_sniffer_event.is_set():
            self._schedule_display_update()

    def _bytes_to_human_readable(self, num_bytes):
        """Converts bytes to KB, MB, GB for display."""
        for unit in ['Bytes', 'KB', 'MB', 'GB']:
            if num_bytes < 1024.0:
                return f"{num_bytes:.2f} {unit}"
            num_bytes /= 1024.0
        return f"{num_bytes:.2f} TB"  # Fallback for very large numbers

    def _update_protocol_stats_display(self):
        """Updates the labels in the Protocol Statistics section."""
        self.stats_labels['Total_packets'].config(text=str(self.stats_total_packets))
        self.stats_labels['Total_bytes'].config(text=self._bytes_to_human_readable(self.stats_total_bytes))

        for proto in self.stats_protocol_counts:
            self.stats_labels[f'{proto}_packets'].config(text=str(self.stats_protocol_counts[proto]))
            self.stats_labels[f'{proto}_bytes'].config(
                text=self._bytes_to_human_readable(self.stats_protocol_bytes[proto]))

    def _process_packet(self, packet):
        """Processes each sniffed packet, extracts relevant info, checks for alerts,
           and updates statistics counters.
        """
        # Store raw Scapy packet for potential export
        self.raw_scapy_packets.append(packet)

        # Update total packet and byte counts
        self.stats_total_packets += 1
        packet_len = len(packet)
        self.stats_total_bytes += packet_len

        packet_info = {
            'timestamp': time.strftime('%H:%M:%S', time.localtime(packet.time)),
            'srcIp': 'N/A', 'dstIp': 'N/A', 'protocol': 'N/A',
            'srcPort': 'N/A', 'dstPort': 'N/A', 'summary': packet.summary(),
            'rawData': ''
        }

        # Determine protocol for display, color-coding, and statistics
        protocol_tag = 'ether'  # Default to ether if no higher layer
        main_protocol_name = 'Ethernet'  # For stats counting

        # Always count Ethernet for layer 2
        self.stats_protocol_counts['Ethernet'] += 1
        self.stats_protocol_bytes['Ethernet'] += packet_len

        if packet.haslayer(IP):
            ip_layer = packet[IP]
            packet_info['srcIp'] = ip_layer.src
            packet_info['dstIp'] = ip_layer.dst
            packet_info['protocol'] = ip_layer.proto
            protocol_tag = 'ip'
            main_protocol_name = 'IP'
            self.stats_protocol_counts['IP'] += 1
            self.stats_protocol_bytes['IP'] += packet_len

            if ip_layer.proto == 6:  # TCP
                packet_info['protocol'] = 'TCP'
                if packet.haslayer(TCP):
                    packet_info['srcPort'] = packet[TCP].sport
                    packet_info['dstPort'] = packet[TCP].dport
                protocol_tag = 'tcp'
                main_protocol_name = 'TCP'
                self.stats_protocol_counts['TCP'] += 1
                self.stats_protocol_bytes['TCP'] += packet_len
            elif ip_layer.proto == 17:  # UDP
                packet_info['protocol'] = 'UDP'
                if packet.haslayer(UDP):
                    packet_info['srcPort'] = packet[UDP].sport
                    packet_info['dstPort'] = packet[UDP].dport
                protocol_tag = 'udp'
                main_protocol_name = 'UDP'
                self.stats_protocol_counts['UDP'] += 1
                self.stats_protocol_bytes['UDP'] += packet_len
            elif ip_layer.proto == 1:  # ICMP
                packet_info['protocol'] = 'ICMP'
                protocol_tag = 'icmp'
                main_protocol_name = 'ICMP'
                self.stats_protocol_counts['ICMP'] += 1
                self.stats_protocol_bytes['ICMP'] += packet_len
            else:  # Other IP protocols
                self.stats_protocol_counts['Other'] += 1
                self.stats_protocol_bytes['Other'] += packet_len
        elif packet.haslayer(ARP):
            packet_info['protocol'] = 'ARP'
            packet_info['srcIp'] = packet[ARP].psrc if packet[ARP].psrc else 'N/A'
            packet_info['dstIp'] = packet[ARP].pdst if packet[ARP].pdst else 'N/A'
            protocol_tag = 'arp'
            main_protocol_name = 'ARP'
            self.stats_protocol_counts['ARP'] += 1
            self.stats_protocol_bytes['ARP'] += packet_len
        # If it's an Ethernet frame but not IP or ARP, it's already counted under 'Ethernet' and 'Other' isn't needed here.

        # Extract Raw data if present for alert keyword searching
        if packet.haslayer(Raw):
            try:
                packet_info['rawData'] = packet[Raw].load.decode('utf-8', errors='ignore')
            except Exception:
                packet_info['rawData'] = str(packet[Raw].load)[:80] + " (binary data)"

        # --- Alerting System ---
        current_alert_keyword = self.alert_keyword.get().strip().lower()
        tags_for_line = [protocol_tag]  # Start with protocol tag
        if current_alert_keyword and current_alert_keyword in packet_info['rawData'].lower():
            alert_message = (f"[{packet_info['timestamp']}] ALERT: Keyword '{current_alert_keyword}' "
                             f"found in packet from {packet_info['srcIp']}:{packet_info['srcPort']} to {packet_info['dstIp']}:{packet_info['dstPort']} "
                             f"[{packet_info['protocol']}]")
            self.alert_display_buffer.append(alert_message)
            tags_for_line.append('alert')  # Add alert tag if triggered

        # --- Add Packet Info to Buffer for display ---
        display_line = (
            f"[{packet_info['timestamp']}] "
            f"{packet_info['srcIp']}:{packet_info['srcPort']} -> "
            f"{packet_info['dstIp']}:{packet_info['dstPort']} "
            f"[{packet_info['protocol']}] "
            f"Summary: {packet_info['summary']}\n"
        )
        # Store the line text and its tags
        self.packet_display_buffer.append((display_line, tags_for_line))

    def stop_sniffing(self):
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.status_label.config(text="Status: Stopping sniffer...")
            self.stop_sniffer_event.set()
            self.master.after(100, self._check_thread_stopped_and_reset_ui)
        else:
            self._reset_ui_after_stop()

    def _check_thread_stopped_and_reset_ui(self):
        """Checks if the sniffer thread has stopped; if not, retry or force UI reset."""
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.master.after(500, self._check_thread_stopped_and_reset_ui)
        else:
            self._reset_ui_after_stop()

    def export_packets(self):
        if not self.raw_scapy_packets:
            messagebox.showinfo("Export", "No packets to export.")
            return

        # Offer choice between JSON and PCAP
        file_type_choice = messagebox.askyesno("Export Type", "Export as PCAP file? (No for JSON)")

        if file_type_choice:  # User chose PCAP
            defaultext = ".pcap"
            filetypes = [("PCAP files", "*.pcap"), ("PCAP Next Generation files", "*.pcapng"), ("All files", "*.*")]
            exporter = self._export_to_pcap
        else:  # User chose JSON
            defaultext = ".json"
            filetypes = [("JSON files", "*.json"), ("All files", "*.*")]
            exporter = self._export_to_json

        timestamp_str = time.strftime("%Y%m%d_%H%M%S")
        initial_file_name = f"captured_packets_{timestamp_str}{defaultext}"

        file_path = filedialog.asksaveasfilename(
            defaultextension=defaultext,
            filetypes=filetypes,
            initialfile=initial_file_name,
            title="Save Captured Packets"
        )

        if file_path:
            exporter(file_path)
        else:
            self.status_label.config(text="Status: Export cancelled.")

    def _export_to_json(self, file_path):
        """Internal method to export packets to JSON."""
        try:
            export_data = []
            for pkt in self.raw_scapy_packets:
                pkt_info = {
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(pkt.time)),
                    'summary': pkt.summary(),
                    'raw_hex': pkt.build().hex()
                }
                if pkt.haslayer(Ether): pkt_info['eth_src'] = pkt[Ether].src; pkt_info['eth_dst'] = pkt[Ether].dst
                if pkt.haslayer(IP): pkt_info['src_ip'] = pkt[IP].src; pkt_info['dst_ip'] = pkt[IP].dst; pkt_info[
                    'ip_protocol'] = pkt[IP].proto
                if pkt.haslayer(TCP): pkt_info['src_port'] = pkt[TCP].sport; pkt_info['dst_port'] = pkt[TCP].dport
                if pkt.haslayer(UDP): pkt_info['src_port'] = pkt[UDP].sport; pkt_info['dst_port'] = pkt[UDP].dport
                if pkt.haslayer(Raw):
                    try:
                        pkt_info['payload_text'] = pkt[Raw].load.decode(errors='ignore')
                    except Exception:
                        pkt_info['payload_text'] = "(binary/undecodable data)"
                export_data.append(pkt_info)

            with open(file_path, 'w') as f:
                json.dump(export_data, f, indent=4)
            messagebox.showinfo("Export Successful", f"Exported {len(self.raw_scapy_packets)} packets to:\n{file_path}")
            self.status_label.config(text=f"Status: Exported {len(self.raw_scapy_packets)} packets to JSON.")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export packets to JSON: {e}")
            self.status_label.config(text="Status: JSON Export failed.")

    def _export_to_pcap(self, file_path):
        """Internal method to export packets to PCAP."""
        try:
            wrpcap(file_path, self.raw_scapy_packets)
            messagebox.showinfo("Export Successful", f"Exported {len(self.raw_scapy_packets)} packets to:\n{file_path}")
            self.status_label.config(text=f"Status: Exported {len(self.raw_scapy_packets)} packets to PCAP.")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export packets to PCAP: {e}")
            self.status_label.config(text="Status: PCAP Export failed.")

    def import_pcap_packets(self):
        if self.is_live_sniffing and self.sniffer_thread and self.sniffer_thread.is_alive():
            messagebox.showwarning("Warning", "Please stop live sniffing before importing a PCAP file.")
            return

        file_path = filedialog.askopenfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")],
            title="Open PCAP File"
        )

        if file_path:
            self.status_label.config(text=f"Status: Loading packets from {file_path}...")
            self._clear_display_and_buffers()

            try:
                import_thread = threading.Thread(target=self._load_and_process_pcap_thread, args=(file_path,))
                import_thread.daemon = True
                import_thread.start()

            except Exception as e:
                messagebox.showerror("Import Error", f"Failed to read PCAP file: {e}")
                self.status_label.config(text="Status: PCAP Import failed.")
        else:
            self.status_label.config(text="Status: PCAP import cancelled.")

    def _load_and_process_pcap_thread(self, file_path):
        """Loads a PCAP file and processes packets in a separate thread."""
        try:
            packets = rdpcap(file_path)
            num_packets = len(packets)
            self.master.after(0, lambda: self.status_label.config(
                text=f"Status: Processing {num_packets} packets from PCAP..."))

            for i, pkt in enumerate(packets):
                self._process_packet(pkt)
                if i % 100 == 0:
                    self.master.after(0, lambda p=i + 1: self.status_label.config(
                        text=f"Status: Processed {p}/{num_packets} packets..."))

            self.master.after(0, self._update_display_periodically)
            self.master.after(0,
                              lambda: self.status_label.config(text=f"Status: Loaded {num_packets} packets from PCAP."))
            self.master.after(0, lambda: self.export_button.config(state=tk.NORMAL))
        except Exception as e:
            self.master.after(0, lambda: messagebox.showerror("Import Error", f"Error processing PCAP packets: {e}"))
            self.master.after(0, lambda: self.status_label.config(text="Status: PCAP Import failed during processing."))


# --- Main Application Entry Point ---
if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()