import threading
from Protocol import Protocol, DATA, SYN
import time
import os

# Example ports 
# SRC_PORT = 60000
# DEST_PORT = 50000

class PC1:
    def __init__(self, SRC_IP, SRC_PORT, DEST_IP, DEST_PORT):
        self.protocol = Protocol(SRC_IP, SRC_PORT, DEST_IP, DEST_PORT)

    def run_pc1(self):
        threading.Thread(target=self.protocol.receive).start()
        threading.Thread(target=self.protocol._send_message_loop).start()
        threading.Thread(target=self.protocol.check_keep_alive).start()

        while self.protocol.running:
            message = input("Input message (or 'start' to connect, 'quit' to exit): ")
            
            if message.lower() == "start":
                if not self.protocol.connection_started:
                    print("Trying to connect...")
                    print("Sending SYN...")
                    self.protocol.send(flag=SYN, seq_num=0)
                    
                    while not self.protocol.is_connected:
                        time.sleep(1)

                    self.protocol.connection_started = True
                    print("Connection established. You can now send messages.")
                else:
                    print("Connection already established.")

            elif message.lower() == "quit":
                self.protocol.quit()

            elif self.protocol.connection_started:
                if message.lower().startswith("-f "):
                    try:
                        parts = message[3:].strip().split(" ", 1)
                        if len(parts) < 2:
                            print("Invalid format. Use: -f fragment_size path_to_file")
                            continue
                        
                        fragment_size = int(parts[0])
                        file_path = parts[1].strip()

                        if fragment_size <= 0:
                            print("Invalid fragment size. Please provide a positive integer.")
                            continue

                        if fragment_size > 1440:
                            print("Fragment size is too large")
                            continue

                        print(f"File path: {file_path}")
                        print(f"Fragment size: {fragment_size}")

                        try:
                            with open(file_path, 'rb') as file:
                                file_data = file.read()
                                file_size = len(file_data)
                        except FileNotFoundError:
                            print("File not found.")
                            continue

                        self.protocol.send_file_in_fragments(file_path, fragment_size)
                    except ValueError:
                        print("Invalid size of fragments. Please provide a valid integer.")
                    except Exception as e:
                        print(f"Error while processing file: {e}")

                elif message.lower().startswith("-m "):
                    try:
                        parts = message[3:].strip().split(" ", 1)
                        if len(parts) < 2:
                            print("Invalid format. Use: -m fragment_size message")
                            continue
                        
                        fragment_size = int(parts[0])
                        message_content = parts[1]

                        if fragment_size <= 0:
                            print("Invalid fragment size. Please provide a positive integer.")
                            continue

                        elif fragment_size > 1440:
                            print("Fragment size is too large")
                            continue

                        self.protocol.send_message_in_fragments(message_content, fragment_size, message_type="TEXT")
                    except ValueError:
                        print("Invalid size of fragments. Please provide a valid integer.")
                elif message.lower().startswith("-d"):
                    try:
                        save_path = input("Enter the directory where the file should be saved (or press Enter for the current directory): ").strip()

                        if not save_path:
                            save_path = "./"
                            break

                        if not os.path.exists(save_path) and not os.path.isdir(save_path):
                            print(f"Invalid path: {save_path}. Please enter a valid directory.")
                            break

                        self.protocol.default_save_path = save_path
                        print(f"Default save path updated to: {self.protocol.default_save_path}")

                    except Exception as e:
                        print(f"Error while processing download request: {e}")
                elif message.lower() == "help":
                    self.display_help()
                else:
                    payload = message.encode("utf-8")
                    self.protocol.send(
                        seq_num=self.protocol.seq_num,
                        flag=DATA,
                        message=payload,
                    )
                    print(f"Message sent with seq_num {self.protocol.seq_num - 1}")
            else:
                print("Connection not established. Use 'start' to initiate the connection.")

    def display_help(self):
            print("""
    Available commands:
        start - Initiates a connection with the destination.
            Usage: start

        quit - Terminates the connection and exits the program.
            Usage: quit

        -f <fragment_size> <file_path> - Sends a file in specified fragment sizes.
            Usage: -f 1024 /path/to/file

        -m <fragment_size> <message> - Sends a text message split into fragments of the given size.
            Usage: -m 100 Hello, this is a fragmented message!

        -d - Sets the default directory for saving received files.
            Usage: -d
            You will be prompted to enter the save directory.

        help - Displays this help message.
            Usage: help
            """)


def main():
    SRC_IP = input("Enter the source IP address: ")
    SRC_PORT = int(input("Enter the source port: "))
    DEST_IP = input("Enter the destination IP address: ")
    DEST_PORT = int(input("Enter the destination port: "))
    print("Write start to start the connection")
    main = PC1(SRC_IP, SRC_PORT, DEST_IP, DEST_PORT)
    main.run_pc1()

main()
