import tkinter as tk
from tkinter import ttk, messagebox
import threading
from typing import Optional
import logging
import os
import sys
from Usbkey import USBSecuritySystem

logger = logging.getLogger(__name__)

class PasswordDialog:
    def __init__(self, parent, title="Set Password"):
        self.result = None
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center the dialog
        self.dialog.geometry("300x150")
        self.dialog.resizable(False, False)
        
        # Create main frame with padding
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Password entry
        ttk.Label(main_frame, text="Enter password:").pack(pady=(0, 5))
        self.password = ttk.Entry(main_frame, show="*")
        self.password.pack(fill=tk.X, pady=(0, 10))
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        # OK and Cancel buttons
        ttk.Button(button_frame, text="OK", command=self.on_ok).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.on_cancel).pack(side=tk.RIGHT)
        
        # Bind Enter key to OK
        self.password.bind('<Return>', lambda e: self.on_ok())
        
        # Focus password entry
        self.password.focus_set()
        
        # Wait for dialog to close
        self.dialog.wait_window()
        
    def on_ok(self):
        self.result = self.password.get()
        self.dialog.destroy()
        
    def on_cancel(self):
        self.result = None
        self.dialog.destroy()

class SecuritySystemGUI:
    def __init__(self, security_system: USBSecuritySystem):
        self.security_system = security_system
        self.root = tk.Tk()
        self.root.title("USB Security System")
        self.root.geometry("400x500")
        self.root.resizable(False, False)
        
        # Configure style
        self.style = ttk.Style()
        self.style.configure('Status.TLabel', font=('Helvetica', 10))
        self.style.configure('Title.TLabel', font=('Helvetica', 12, 'bold'))
        
        self.setup_gui()
        self.update_device_info()
        
    def setup_gui(self):
        # Main container with padding
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title = ttk.Label(
            main_frame,
            text="USB Security System",
            style='Title.TLabel'
        )
        title.pack(pady=(0, 20))
        
        # Status frame
        status_frame = ttk.LabelFrame(main_frame, text="System Status", padding="10")
        status_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.status_label = ttk.Label(
            status_frame,
            text="Status: Active",
            style='Status.TLabel'
        )
        self.status_label.pack()
        
        # Device info frame
        device_frame = ttk.LabelFrame(main_frame, text="Authorized Device", padding="10")
        device_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.device_info = ttk.Label(device_frame, text="No device authorized")
        self.device_info.pack()
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Setup button
        self.setup_button = ttk.Button(
            button_frame,
            text="Setup New Device",
            command=self.setup_device
        )
        self.setup_button.pack(fill=tk.X, pady=5)
        
        # Password button
        self.password_button = ttk.Button(
            button_frame,
            text="Change Override Password",
            command=self.set_password
        )
        self.password_button.pack(fill=tk.X, pady=5)
        
        # Unlock button
        self.unlock_button = ttk.Button(
            button_frame,
            text="Unlock System",
            command=self.unlock
        )
        self.unlock_button.pack(fill=tk.X, pady=5)
        
        # Log frame
        log_frame = ttk.LabelFrame(main_frame, text="Activity Log", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        # Log text area with scrollbar
        self.log_text = tk.Text(log_frame, height=10, wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Configure log text to be read-only
        self.log_text.configure(state='disabled')
        
        # Update buttons based on system state
        self.update_buttons()
        
    def update_device_info(self):
        try:
            if os.path.exists(self.security_system.serial_file):
                with open(self.security_system.serial_file, 'r') as f:
                    serial = f.read().strip()
                self.device_info.config(text=f"Serial Number: {serial}")
            else:
                self.device_info.config(text="No device authorized")
        except Exception as e:
            logger.error(f"Error updating device info: {e}")
            self.device_info.config(text="Error reading device info")
            
    def update_buttons(self):
        try:
            has_device = os.path.exists(self.security_system.serial_file)
            self.setup_button.config(state='normal' if not has_device else 'disabled')
            self.password_button.config(state='normal' if has_device else 'disabled')
            self.unlock_button.config(state='normal' if has_device else 'disabled')
        except Exception as e:
            logger.error(f"Error updating buttons: {e}")
            messagebox.showerror("Error", "Failed to update interface state")
        
    def setup_device(self):
        try:
            self.security_system.setup_new_device()
            self.update_device_info()
            self.update_buttons()
            self.log_message("New device setup completed successfully")
            messagebox.showinfo("Success", "Device setup completed successfully")
        except Exception as e:
            self.log_message(f"Error during device setup: {str(e)}")
            messagebox.showerror("Error", f"Failed to setup device: {str(e)}")
            
    def set_password(self):
        dialog = PasswordDialog(self.root, "Set Override Password")
        if dialog.result:
            try:
                self.security_system.set_override_password(dialog.result)
                self.log_message("Override password updated successfully")
                messagebox.showinfo("Success", "Password updated successfully")
            except Exception as e:
                self.log_message(f"Error updating password: {str(e)}")
                messagebox.showerror("Error", f"Failed to update password: {str(e)}")
                
    def unlock(self):
        dialog = PasswordDialog(self.root, "Unlock System")
        if dialog.result:
            try:
                if self.security_system.verify_password(dialog.result):
                    self.security_system.unlock_system()
                    self.log_message("System unlocked successfully")
                    messagebox.showinfo("Success", "System unlocked successfully")
                else:
                    self.log_message("Failed unlock attempt - incorrect password")
                    messagebox.showerror("Error", "Incorrect password")
            except Exception as e:
                self.log_message(f"Error during unlock: {str(e)}")
                messagebox.showerror("Error", f"Failed to unlock system: {str(e)}")
                
    def log_message(self, message: str):
        self.log_text.configure(state='normal')
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state='disabled')
        
    def run(self):
        # Start USB monitoring in a separate thread
        monitor_thread = threading.Thread(
            target=self.security_system.monitor_usb,
            daemon=True
        )
        monitor_thread.start()
        
        # Start the GUI main loop
        self.root.mainloop()

def main():
    try:
        security_system = USBSecuritySystem()
        gui = SecuritySystemGUI(security_system)
        gui.run()
    except Exception as e:
        logger.error(f"GUI Error: {e}")
        messagebox.showerror("Error", f"Failed to start GUI: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 