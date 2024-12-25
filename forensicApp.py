import tkinter as tk
from tkinter import ttk, filedialog
import subprocess

# Function to run shell commands
def run_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        log_output.insert(tk.END, f"> {command}\n{result.stdout}\n{result.stderr}\n")
        log_output.see(tk.END)  # Auto-scroll to the end
    except Exception as e:
        log_output.insert(tk.END, f"Error: {str(e)}\n")
        log_output.see(tk.END)

# File selection wrapper for commands requiring input files
def choose_file_and_run(command_template):
    file_path = filedialog.askopenfilename(title="Select File")
    if file_path:
        command = command_template.replace("<file>", f"\"{file_path}\"")
        run_command(command)

# Directory selection wrapper for commands requiring directories
def choose_directory_and_run(command_template):
    directory_path = filedialog.askdirectory(title="Select Directory")
    if directory_path:
        command = command_template.replace("<directory>", f"\"{directory_path}\"")
        run_command(command)

def choose_file_and_run(command_template):
    file_path = filedialog.askopenfilename(title="Select File")
    if file_path:
        command = command_template.replace("<file>", f"\"{file_path}\"")
        run_command(command)

# GUI Setup
root = tk.Tk()
root.title("Digital Forensic Toolkit")
root.geometry("1000x750")
root.configure(bg="#2C3E50")  # Dark background color

# Create notebook (tabs)
notebook = ttk.Notebook(root)
notebook.pack(fill='both', expand=True, padx=10, pady=10)

# Style configuration
style = ttk.Style()
style.configure("TFrame", background="#34495E")  # Tab background
style.configure("TButton", background="#2980B9", foreground="white", font=("Arial", 10), padding=5)
style.map("TButton", background=[("active", "#1ABC9C")], foreground=[("active", "white")])
style.configure("TLabel", background="#34495E", foreground="white", font=("Arial", 12))

# Log output window
log_frame = ttk.Frame(root)
log_frame.pack(fill='both', expand=True, padx=10, pady=10)
log_label = ttk.Label(log_frame, text="Log Output", font=("Arial", 14))
log_label.pack(anchor='w', padx=5)
log_output = tk.Text(log_frame, wrap='word', height=10, state='normal', bg="#ECF0F1", fg="#2C3E50", font=("Courier", 10))
log_output.pack(fill='both', expand=True, padx=5, pady=5)

# Clear log button
clear_log_button = ttk.Button(log_frame, text="Clear Log", command=lambda: log_output.delete(1.0, tk.END))
clear_log_button.pack(side='right', padx=5, pady=5)


# Forensic Categories and Commands
    
categories = {
    "Network Forensics": {
        "Scan Open Ports": "nmap -sV localhost",
        "Analyze Traffic (Wireshark)": "wireshark capture.pcap"
    },
    "File Forensics": {
        "Generate File Hash (SHA-256)": "sha256sum <file>",
        "Extract Hidden Data": "bulk_extractor -o output <file>"
    },
    "Disk Forensics": {
        "Create Disk Image": "sudo dd if=/dev/sdX of=<file> bs=4M",
        "Analyze Disk Image (Autopsy)": "autopsy"
    },
   
    "Malware Forensics": {
        "Scan for Malware": "clamscan -r <directory>",
        "Run YARA Rules": "yara -r rules.yar <directory>"
    },
    "Browser Forensics": {
        "Extract Browser History": "sqlite3 <file> 'SELECT * FROM urls;'"
    },
   
    "USB Device Analysis": {
        "List USB Devices": "lsusb",
        "Analyze USB Metadata": "sudo dmesg | grep usb"
    },
   
    "Persistence Mechanisms": {
        "List Cron Jobs": "crontab -l"
    },
   
    
    "Remote Connections (RDP, VPN)": {
        "Analyze RDP Logs": "grep 'RDP' <file>",
        "Analyze VPN Logs": "grep 'VPN' <file>"
    },
    "Process Analysis": {
        "List Running Processes": "ps aux",
        "Analyze Terminated Processes": "forensic_process_analyzer.py <file>"
    }
}

# Create tabs and buttons for each category
for category, actions in categories.items():
    frame = ttk.Frame(notebook)
    notebook.add(frame, text=category)
    
    label = ttk.Label(frame, text=f"{category} Tools", font=("Arial", 14))
    label.pack(pady=10)

    for action_name, command in actions.items():
        if "<file>" in command:
            button = ttk.Button(frame, text=action_name, command=lambda c=command: choose_file_and_run(c))
        elif "<directory>" in command:
            button = ttk.Button(frame, text=action_name, command=lambda c=command: choose_directory_and_run(c))
        else:
            button = ttk.Button(frame, text=action_name, command=lambda c=command: run_command(c))
        button.pack(pady=5, fill='x', padx=10)

# Run the application
root.mainloop()