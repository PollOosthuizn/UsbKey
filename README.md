# UsbKey
This is a security system that uses a USB device as a physical key to lock/unlock your computer.

I'll explain how to use the USB Security System step by step:

1. **Installation and Setup**:
   ```bash
   # Install required packages
   pip install pyusb cryptography pywin32 pyudev
   ```

2. **Running the Program**:
   You can run the program in two modes:
   ```bash
   # GUI Mode (Recommended)
   python Usbkey.py --gui
   
   # Command Line Mode
   python Usbkey.py
   ```

3. **Initial Setup (First Time)**:
   - When you run the program for the first time, you'll need to:
     1. Select a USB device to use as your security key
     2. Set an emergency override password
     3. The program will save the device's serial number and encrypt the configuration

4. **Using the GUI Interface**:
   The GUI provides several options:
   - **Setup New Device**: Use this to register a new USB device as your security key
   - **Change Override Password**: Update your emergency override password
   - **Unlock System**: Manually unlock the system using your override password
   - **Activity Log**: Shows all system events and status changes

5. **How it Works**:
   - The system continuously monitors for USB device changes
   - When your authorized USB device is removed:
     - The system automatically locks your computer
     - You can't use the computer until you either:
       a) Reinsert the authorized USB device
       b) Enter the override password
   - When you reinsert the authorized USB device:
     - The system automatically unlocks your computer

6. **Emergency Override**:
   - If you lose your USB device, you can use the override password to unlock the system
   - To use the override password:
     - Click the "Unlock System" button in the GUI
     - Enter your override password
     - The system will unlock if the password is correct

7. **Security Features**:
   - Device authentication using unique serial numbers
   - Encrypted password storage
   - Automatic system locking/unlocking
   - Activity logging for security monitoring
   - Protection against timing attacks

8. **Troubleshooting**:
   - If the system isn't detecting your USB device:
     - Make sure the device is properly connected
     - Try unplugging and replugging the device
     - Check the activity log for error messages
   - If you can't unlock the system:
     - Verify you're using the correct override password
     - Check if the USB device is properly recognized
     - Look at the activity log for any error messages

9. **Important Notes**:
   - Keep your USB device safe - losing it means you'll need to use the override password
   - Remember your override password - it's your backup access method
   - The system requires administrator/sudo privileges to function properly
   - The activity log helps track any security-related events

10. **Platform-Specific Requirements**:
    - Windows: Run as administrator for proper USB monitoring
    - Linux: May need to add udev rules for USB access
    - macOS: Grant security permissions when prompted

Would you like me to explain any specific aspect in more detail?

