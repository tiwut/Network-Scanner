import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import threading
import subprocess
import platform
import csv
import webbrowser
from scapy.all import srp, Ether, ARP, conf

class AdvancedNetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner")
        self.root.geometry("800x600")

        self.style = ttk.Style()
        self.style.theme_use("clam")

        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.control_frame = ttk.LabelFrame(self.main_frame, text="Controls", padding="10")
        self.control_frame.pack(fill=tk.X, pady=5)

        self.ip_range_label = ttk.Label(self.control_frame, text="IP Range (e.g., 192.168.1.1/24):")
        self.ip_range_label.pack(side=tk.LEFT, padx=5)

        self.ip_range_entry = ttk.Entry(self.control_frame, width=20)
        self.ip_range_entry.pack(side=tk.LEFT, padx=5)
        self.ip_range_entry.insert(0, self.get_default_ip_range())

        self.scan_button = ttk.Button(self.control_frame, text="Scan Network", command=self.start_scan_thread)
        self.scan_button.pack(side=tk.LEFT, padx=10)

        self.export_button = ttk.Button(self.control_frame, text="Export", command=self.export_to_csv, state="disabled")
        self.export_button.pack(side=tk.LEFT, padx=5)

        self.progress_frame = ttk.Frame(self.main_frame)
        self.progress_frame.pack(fill=tk.X, pady=5)
        self.progress_label = ttk.Label(self.progress_frame, text="Ready.")
        self.progress_label.pack(side=tk.LEFT)
        self.progress = ttk.Progressbar(self.progress_frame, orient="horizontal", length=400, mode="determinate")
        self.progress.pack(side=tk.RIGHT, fill=tk.X, expand=True)

        self.tree_frame = ttk.Frame(self.main_frame)
        self.tree_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.tree = ttk.Treeview(self.tree_frame, columns=("ip", "name", "mac", "status"), show="headings")
        self.tree.heading("ip", text="IP Address", command=lambda: self.sort_treeview("ip", False))
        self.tree.heading("name", text="Name", command=lambda: self.sort_treeview("name", False))
        self.tree.heading("mac", text="MAC Address", command=lambda: self.sort_treeview("mac", False))
        self.tree.heading("status", text="Status", command=lambda: self.sort_treeview("status", False))

        self.tree.column("ip", width=120, anchor=tk.W)
        self.tree.column("name", width=200, anchor=tk.W)
        self.tree.column("mac", width=150, anchor=tk.W)
        self.tree.column("status", width=80, anchor=tk.CENTER)

        self.scrollbar = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=self.scrollbar.set)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True)

        self.tree.bind("<Button-3>", self.on_treeview_right_click)
        self.tree.bind("<Motion>", self.on_treeview_motion)

        self.status_bar = ttk.Label(self.main_frame, text="Ready to scan.", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(fill=tk.X)


    def on_treeview_right_click(self, event):
        """Creates and displays a context menu on right-clicking an IP address."""
        item_id = self.tree.identify_row(event.y)
        column_id = self.tree.identify_column(event.x)
        
        if item_id and column_id == "#1":
            self.tree.selection_set(item_id)
            ip_address = self.tree.item(item_id, "values")[0]
            
            context_menu = tk.Menu(self.root, tearoff=0)
            context_menu.add_command(label=f"Copy IP Address ({ip_address})", 
                                      command=lambda: self.copy_to_clipboard(ip_address))
            context_menu.add_command(label=f"Open in Browser (http://{ip_address})", 
                                      command=lambda: self.open_in_browser(ip_address))
            
            context_menu.tk_popup(event.x_root, event.y_root)

    def on_treeview_motion(self, event):
        """Changes the mouse cursor to a hand when hovering over the IP column."""
        item_id = self.tree.identify_row(event.y)
        column_id = self.tree.identify_column(event.x)
        
        if item_id and column_id == "#1":
            self.tree.config(cursor="hand2")
        else:
            self.tree.config(cursor="")

    def copy_to_clipboard(self, text):
        """Copies the given text to the clipboard."""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status_bar.config(text=f"IP address {text} copied to clipboard.")

    def open_in_browser(self, ip_address):
        """Opens the IP address in the default web browser."""
        try:
            url = f"http://{ip_address}"
            webbrowser.open(url, new=2)
            self.status_bar.config(text=f"Attempting to open {url} in browser...")
        except Exception as e:
            messagebox.showerror("Error", f"Could not open browser: {e}")


    def get_default_ip_range(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            return ".".join(local_ip.split('.')[:-1]) + ".1/24"
        except Exception:
            return "192.168.1.1/24"

    def start_scan_thread(self):
        self.scan_button.config(state="disabled")
        self.export_button.config(state="disabled")
        self.progress.config(value=0, maximum=100)
        self.progress_label.config(text="Scanning...")
        self.status_bar.config(text="Scan in progress...")
        self.tree.delete(*self.tree.get_children())
        
        scan_thread = threading.Thread(target=self.scan_network)
        scan_thread.daemon = True
        scan_thread.start()

    def scan_network(self):
        try:
            ip_range = self.ip_range_entry.get()
            if not ip_range:
                self.root.after(0, messagebox.showerror, "Error", "Please enter an IP range.")
                return

            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range), timeout=3, verbose=False)

            devices = []
            total = len(ans) if ans else 1
            for i, (sent, received) in enumerate(ans):
                ip = received.psrc
                mac = received.hwsrc
                
                try:
                    name = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    name = "Unknown"
                
                status = self.ping_host(ip)
                
                devices.append((ip, name, mac, status))
                progress_percentage = int((i + 1) / total * 100)
                self.root.after(0, self.update_progress, progress_percentage)

            self.root.after(0, self.update_ui, devices)

        except Exception as e:
            self.root.after(0, messagebox.showerror, "Error", f"An error occurred: {e}")
        finally:
            self.root.after(0, self.stop_scan)

    def ping_host(self, ip):
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', ip]
        try:
            response = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1)
            return "Online" if response.returncode == 0 else "Offline"
        except subprocess.TimeoutExpired:
            return "Offline"

    def update_progress(self, value):
        self.progress['value'] = value
        self.progress_label.config(text=f"{value}% complete")

    def update_ui(self, devices):
        for device in devices:
            self.tree.insert("", "end", values=device)
        self.status_bar.config(text=f"{len(devices)} devices found.")
        if devices:
            self.export_button.config(state="normal")

    def stop_scan(self):
        self.progress.config(value=100)
        self.progress_label.config(text="Completed.")
        self.scan_button.config(state="normal")

    def sort_treeview(self, col, reverse):
        l = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        l.sort(reverse=reverse)

        for index, (val, k) in enumerate(l):
            self.tree.move(k, '', index)

        self.tree.heading(col, command=lambda: self.sort_treeview(col, not reverse))

    def export_to_csv(self):
        if not self.tree.get_children():
            messagebox.showinfo("Information", "No data to export.")
            return
        
        file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                                   filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if file_path:
            try:
                with open(file_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow([self.tree.heading(c)["text"] for c in self.tree["columns"]])
                    for row_id in self.tree.get_children():
                        writer.writerow(self.tree.item(row_id)["values"])
                messagebox.showinfo("Success", f"Data successfully exported to {file_path}.")
            except Exception as e:
                messagebox.showerror("Error", f"Error exporting data: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedNetworkScannerApp(root)
    root.mainloop()