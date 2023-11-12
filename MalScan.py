


import os
import threading
from tkinter import Tk, Button, Label, Text, filedialog, Entry
from scapy.all import sniff, IP, TCP

def scan_file(file_path, signature_database):
    with open(file_path, 'rb') as file:
        file_data = file.read()

    for signature in signature_database:
        if signature in file_data:
            return True

    return False

def scan_directory(directory_paths, signature_database):
    malware_files = []
    current_file = os.path.basename(__file__)
    for directory_path in directory_paths:
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                if file != current_file and scan_file(file_path, signature_database):
                    malware_files.append(file_path)

    return malware_files

def browse_directory():
    directory_path = filedialog.askdirectory()
    directory_entry.delete(0, 'end')
    directory_entry.insert('end', directory_path)

def scan_directory_gui():
    directory_paths = directory_entry.get()
    if directory_paths:
        malware_files = scan_directory([directory_paths], signature_database)
        result_text.delete(1.0, 'end')
        if malware_files:
            result_text.insert('end', "Malware files found:\n")
            for file in malware_files:
                result_text.insert('end', file + '\n')
        else:
            result_text.insert('end', "No malware files found.")

def packet_callback(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        payload = packet[TCP].payload

        if len(payload) > 50:
            print(f"Suspicious payload detected from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
        # Detect traffic on non-standard ports
        non_standard_ports = [80, 443, 22, 21]
        if dst_port not in non_standard_ports:
            print(f"Suspicious traffic on non-standard port {dst_port}")        
def start_sniffing():
    sniff(prn=packet_callback, filter="tcp")

# Example usage
signature_database = [
    b'X5O!P%@AP[4\PZX54(P^)7CC)7',
    b'68 65 6c 6c 6f 20 57 6f 72 6c 64',
    b'4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF FF FF',
    b'E8 85 85 2B 50 68 2A 67 6E 80 00 00 00',
    b'4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF FF FF',
    b'WNRY 9956 5700 E400 CC00 3E00 0000 C000 0000 0000',
    b'4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF FF FF',
    b'4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF FF FF' 
]

# Create the main window
window = Tk()
window.title("Malware Scanner")

# Create GUI elements
directory_label = Label(window, text="Directory:")
directory_label.pack()

directory_entry = Entry(window)
directory_entry.pack()

browse_button = Button(window, text="Browse", command=browse_directory)
browse_button.pack()

scan_button = Button(window, text="Scan", command=lambda: threading.Thread(target=scan_directory_gui).start())
scan_button.pack()

result_label = Label(window, text="Scan Result:")
result_label.pack()

result_text = Text(window, font='Consolas', height=100, width=100, fg='white', bg='#050533')
result_text.pack()

# Start packet sniffing in a separate thread
sniff_thread = threading.Thread(target=start_sniffing)
sniff_thread.start()

# Run the main event loop
window.mainloop()
