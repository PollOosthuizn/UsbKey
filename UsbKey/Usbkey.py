import usb.core
import usb.util
from cryptography.fernet import Fernet
import os
import sys
import time
import ctypes
from threading import Thread
import argparse
import getpass
import logging
import json
from base64 import b64encode, b64decode
import hashlib
import platform
import functools
import win32file
import win32con
import pyudev
from typing import Optional, Callable, Any
import hmac

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('usb_security.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def handle_errors(func: Callable) -> Callable:
    """Decorator for consistent error handling and logging"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> Any:
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in {func.__name__}: {str(e)}")
            raise
    return wrapper

class USBSecuritySystem:
    def __init__(self):
        self.key_file = "auth.key"
        self.serial_file = "device.id"
        self.config_file = "config.json"
        self.encryption_key = self._load_or_generate_key()
        self.fernet = Fernet(self.encryption_key)
        self.authorized_device = None
        self.override_password_hash = None
        self.load_config()
        self._setup_usb_monitoring()
        
    def _load_or_generate_key(self) -> bytes:
        """Load existing encryption key or generate a new one"""
        try:
            if os.path.exists(self.key_file):
                with open(self.key_file, 'rb') as f:
                    return f.read()
            else:
                key = Fernet.generate_key()
                with open(self.key_file, 'wb') as f:
                    f.write(key)
                return key
        except Exception as e:
            logger.error(f"Error handling encryption key: {e}")
            raise

    @handle_errors
    def load_config(self):
        """Load configuration including encrypted override password"""
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                self.override_password_hash = config.get('override_password_hash')
        else:
            self.override_password_hash = None

    @handle_errors
    def save_config(self):
        """Save configuration including encrypted override password"""
        config = {
            'override_password_hash': self.override_password_hash
        }
        with open(self.config_file, 'w') as f:
            json.dump(config, f)
        
    @handle_errors
    def setup_new_device(self):
        """Initial setup to register a USB device"""
        logger.info("Scanning for USB devices...")
        devices = list(usb.core.find(find_all=True))
        
        if not devices:
            raise RuntimeError("No USB devices found")
            
        logger.info("\nAvailable USB devices:")
        for i, device in enumerate(devices):
            try:
                product = usb.util.get_string(device, device.iProduct)
                serial = getattr(device, 'serial_number', 'No Serial')
                logger.info(f"{i}: {product} (Serial: {serial})")
            except Exception as e:
                logger.warning(f"{i}: Unknown Device (Error: {e})")
                
        selection = int(input("\nSelect device number to use as security key: "))
        if not 0 <= selection < len(devices):
            raise ValueError("Invalid device selection")
            
        self.authorized_device = devices[selection]
        
        # Generate and save authentication key
        auth_key = os.urandom(32)
        encrypted_key = self.fernet.encrypt(auth_key)
        
        # Save encrypted key and device serial
        with open(self.key_file, 'wb') as f:
            f.write(encrypted_key)
        with open(self.serial_file, 'w') as f:
            f.write(str(getattr(self.authorized_device, 'serial_number', 'No Serial')))
            
        # Set override password
        self.set_override_password(input("Set emergency override password: "))
        
    @handle_errors
    def lock_system(self):
        """Lock the computer screen"""
        if sys.platform == 'win32':
            ctypes.windll.user32.LockWorkStation()
            logger.info("Windows system locked")
        elif sys.platform == 'darwin':  # macOS
            os.system('pmset displaysleepnow')
            logger.info("macOS system locked")
        else:  # Linux
            os.system('xdg-screensaver lock')
            logger.info("Linux system locked")
            
    @handle_errors
    def unlock_system(self):
        """Unlock the computer screen using OS-native APIs"""
        if sys.platform == 'win32':
            # Use Windows Credential Provider API
            try:
                import win32security
                import win32api
                import win32con
                
                # Get the current user's SID
                user_sid = win32security.GetTokenInformation(
                    win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY),
                    win32security.TokenUser
                )[0]
                
                # Create a new desktop for the unlock session
                desktop_name = f"Unlock_{int(time.time())}"
                desktop = win32security.CreateDesktop(desktop_name, 0, win32con.MAXIMUM_ALLOWED, None)
                
                # Switch to the new desktop
                win32security.SwitchDesktop(desktop)
                
                # Simulate Ctrl+Alt+Delete to show the login screen
                win32api.keybd_event(win32con.VK_CONTROL, 0, 0, 0)
                win32api.keybd_event(win32con.VK_MENU, 0, 0, 0)
                win32api.keybd_event(win32con.VK_DELETE, 0, 0, 0)
                time.sleep(0.1)
                win32api.keybd_event(win32con.VK_DELETE, 0, win32con.KEYEVENTF_KEYUP, 0)
                win32api.keybd_event(win32con.VK_MENU, 0, win32con.KEYEVENTF_KEYUP, 0)
                win32api.keybd_event(win32con.VK_CONTROL, 0, win32con.KEYEVENTF_KEYUP, 0)
                
                logger.info("Windows system unlocked")
            except Exception as e:
                logger.error(f"Error using Windows Credential Provider: {e}")
                # Fallback to basic key simulation
                ctypes.windll.user32.keybd_event(0x2E, 0, 0, 0)
                ctypes.windll.user32.keybd_event(0x2E, 0, 0x0002, 0)
        elif sys.platform == 'darwin':  # macOS
            os.system('pmset displaysleepnow 0')
            logger.info("macOS system unlocked")
        else:  # Linux
            os.system('xdg-screensaver deactivate')
            logger.info("Linux system unlocked")

    def _setup_usb_monitoring(self):
        """Setup platform-specific USB monitoring with automatic fallback"""
        try:
            if sys.platform == 'win32':
                self._setup_windows_monitoring()
            elif sys.platform == 'linux':
                self._setup_linux_monitoring()
            else:
                self._setup_polling_monitoring()
        except Exception as e:
            logger.error(f"Failed to setup native USB monitoring: {e}")
            logger.info("Falling back to polling-based monitoring")
            self._setup_polling_monitoring()

    def _setup_windows_monitoring(self):
        """Setup Windows-specific USB monitoring using win32file"""
        try:
            # Test if we have proper permissions
            test_device = usb.core.find(find_all=True)
            if test_device is None:
                raise RuntimeError("No USB devices accessible - check permissions")
            
            self.monitor_thread = Thread(target=self._windows_monitor_loop, daemon=True)
            logger.info("Windows USB monitoring initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Windows USB monitoring: {e}")
            raise

    def _windows_monitor_loop(self):
        """Windows-specific USB monitoring loop"""
        def monitor_callback(change_type, action, file_name):
            if change_type == win32con.FILE_NOTIFY_CHANGE_DEVICE:
                try:
                    current_devices = set(usb.core.find(find_all=True))
                    if hasattr(self, '_prev_devices'):
                        self._handle_usb_change(current_devices, self._prev_devices)
                    self._prev_devices = current_devices
                except Exception as e:
                    logger.error(f"Error in Windows USB callback: {e}")
            return True

        try:
            self._prev_devices = set(usb.core.find(find_all=True))
            while True:
                try:
                    win32file.ReadDirectoryChangesW(
                        win32file.GetLogicalDriveStrings().split('\000')[0],
                        monitor_callback,
                        win32con.FILE_NOTIFY_CHANGE_DEVICE
                    )
                except Exception as e:
                    logger.error(f"Windows USB monitoring error: {e}")
                    time.sleep(1)
        except Exception as e:
            logger.error(f"Failed to start Windows USB monitoring: {e}")
            self._setup_polling_monitoring()

    def _handle_usb_change(self, current_devices, prev_devices):
        """Handle USB device changes"""
        try:
            if len(current_devices) < len(prev_devices):
                logger.info("USB device removed")
                self.lock_system()
            elif len(current_devices) > len(prev_devices):
                new_device = (current_devices - prev_devices).pop()
                if self.verify_device(new_device):
                    logger.info("Authorized USB device detected")
                    self.unlock_system()
                else:
                    logger.warning("Unauthorized USB device detected")
        except Exception as e:
            logger.error(f"Error handling USB change: {e}")

    def _setup_linux_monitoring(self):
        """Setup Linux-specific USB monitoring using pyudev"""
        try:
            self.context = pyudev.Context()
            self.monitor = pyudev.Monitor.from_netlink(self.context)
            self.monitor.filter_by(subsystem='usb')
            self.monitor_thread = Thread(target=self._linux_monitor_loop, daemon=True)
            logger.info("Linux USB monitoring initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Linux USB monitoring: {e}")
            raise

    def _linux_monitor_loop(self):
        """Linux-specific USB monitoring loop"""
        observer = pyudev.MonitorObserver(self.monitor, self._handle_linux_usb_event)
        observer.start()

    def _setup_polling_monitoring(self):
        """Setup fallback polling-based USB monitoring"""
        try:
            self.monitor_thread = Thread(target=self._polling_monitor_loop, daemon=True)
            logger.info("Polling-based USB monitoring initialized")
        except Exception as e:
            logger.error(f"Failed to initialize polling monitoring: {e}")
            raise

    def _polling_monitor_loop(self):
        """Fallback polling-based USB monitoring loop with error recovery"""
        prev_devices = set()
        consecutive_errors = 0
        max_errors = 5
        
        while True:
            try:
                current_devices = set(usb.core.find(find_all=True))
                if current_devices is None:
                    raise RuntimeError("Failed to enumerate USB devices")
                    
                if current_devices != prev_devices:
                    self._handle_usb_change(current_devices, prev_devices)
                prev_devices = current_devices
                consecutive_errors = 0  # Reset error counter on success
                time.sleep(0.1)  # Reduced polling interval
            except Exception as e:
                consecutive_errors += 1
                logger.error(f"Polling USB monitoring error ({consecutive_errors}/{max_errors}): {e}")
                
                if consecutive_errors >= max_errors:
                    logger.critical("Too many consecutive errors in polling monitoring")
                    # Try to recover by reinitializing USB monitoring
                    try:
                        self._setup_usb_monitoring()
                    except Exception as recovery_error:
                        logger.error(f"Failed to recover USB monitoring: {recovery_error}")
                
                time.sleep(1)  # Longer delay on error

    def _handle_linux_usb_event(self, device):
        """Handle Linux USB events"""
        if device.action == 'remove':
            logger.info("USB device removed")
            self.lock_system()
        elif device.action == 'add':
            if self.verify_device(device):
                logger.info("Authorized USB device detected")
                self.unlock_system()
            else:
                logger.warning("Unauthorized USB device detected")

    @handle_errors
    def verify_device(self, device):
        """Verify if the inserted USB is authorized"""
        with open(self.serial_file, 'r') as f:
            authorized_serial = f.read().strip()
        device_serial = getattr(device, 'serial_number', 'No Serial')
        return str(device_serial) == authorized_serial

    @handle_errors
    def set_override_password(self, password):
        """Set a new override password with enhanced security"""
        try:
            # Generate a unique salt for each password
            salt = os.urandom(32)
            
            # Use PBKDF2 with SHA-256 for key derivation
            password_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode(),
                salt,
                100000  # Number of iterations
            )
            
            # Store salt and hash together
            self.override_password_hash = b64encode(salt + password_hash).decode()
            self.save_config()
            logger.info("Override password updated successfully")
        except Exception as e:
            logger.error(f"Failed to set override password: {e}")
            raise

    @handle_errors
    def verify_password(self, password):
        """Verify the override password with timing attack protection"""
        if not self.override_password_hash:
            return False
            
        try:
            stored_data = b64decode(self.override_password_hash)
            salt = stored_data[:32]
            stored_hash = stored_data[32:]
            
            # Use constant-time comparison to prevent timing attacks
            password_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode(),
                salt,
                100000
            )
            
            # Use hmac.compare_digest for constant-time comparison
            return hmac.compare_digest(password_hash, stored_hash)
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False  # Fail securely on error

    @handle_errors
    def unlock_with_password(self):
        """Unlock the system using the override password"""
        password = getpass.getpass("Enter override password: ")
        if self.verify_password(password):
            self.unlock_system()
            return True
        logger.warning("Incorrect override password attempt")
        return False
            
    def run(self):
        """Main method to run the security system"""
        if not os.path.exists(self.key_file):
            self.setup_new_device()
            
        logger.info("USB Security System Active")
        self.monitor_thread.start()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down USB Security System...")

    def monitor_usb(self):
        """Main USB monitoring method that can be called from GUI"""
        if sys.platform == 'win32':
            self._windows_monitor_loop()
        elif sys.platform == 'linux':
            self._linux_monitor_loop()
        else:
            self._polling_monitor_loop()

def main():
    parser = argparse.ArgumentParser(description='USB Security System with Password Override')
    parser.add_argument('--set-password', help='Set the override password', action='store_true')
    parser.add_argument('--unlock', help='Unlock using override password', action='store_true')
    parser.add_argument('--gui', help='Run in GUI mode', action='store_true')
    args = parser.parse_args()

    security_system = USBSecuritySystem()

    try:
        if args.gui:
            # Import GUI only when needed
            from gui import SecuritySystemGUI
            gui = SecuritySystemGUI(security_system)
            gui.run()
        elif args.set_password:
            password = getpass.getpass("Enter new override password: ")
            confirm = getpass.getpass("Confirm override password: ")
            if password == confirm:
                security_system.set_override_password(password)
                logger.info("Override password set successfully")
            else:
                logger.error("Passwords do not match")
                sys.exit(1)
        elif args.unlock:
            if security_system.unlock_with_password():
                logger.info("System unlocked successfully")
            else:
                sys.exit(1)
        else:
            security_system.run()
    except Exception as e:
        logger.error(f"Unexpected error occurred: {e}")
        sys.exit(1)
    finally:
        security_system.lock_system()
        logger.info("System locked and resources cleaned up.")

if __name__ == "__main__":
    main()

