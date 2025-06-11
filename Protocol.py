import random
import time
import zlib
import socket
from Protocol_header import Protocol_header
import os
import queue

KEEP_ALIVE_INTERVAL = 5
KEEP_ALIVE_TIMEOUT = 20

SYN = 0x1
ACK = 0x2
SYN_ACK = 0x3
FIN = 0x4
NACK = 0x5
DATA = 0x6
KEEPALIVE = 0x7

HEADER_SIZE = 13

class Protocol:
    def __init__(self, src_ip, src_port, dest_ip, dest_port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((src_ip, src_port))
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.running = True
        self.is_connected = False
        self.connection_started = False
        self.last_keep_alive = time.time()
        self.state = "INITIAL"
        self.mode = "TEXT"
        self.received_fragments = {}
        self.keep_alive_started = False
        self.seq_num = 0
        self.ack_num = 0
        self.sent_packets = {}
        self.window_size = 50
        self.received_acks = set()
        self.timeout = 5
        self.window_base = 0
        self.sent_fragments = {}
        self.default_save_path = "D:/DU/PKS/Project/directory_to_save/"
        # self.default_save_path = "./"
        self.send_queue = queue.Queue()
        self.last_ack_check = time.time()
        self.error_seq_num = None
        self.post_nack_fragments = []
        self.saved_acks = []
        self.keep_alive_heartbeat = 0
        self.number_of_nacks = 0

    def _send_message_loop(self):
        while self.running:
            if self.is_connected and (time.time() - self.last_keep_alive >= KEEP_ALIVE_INTERVAL):
                self.send(seq_num=self.seq_num, flag=KEEPALIVE, ack_num=self.window_base, window=self.window_size)
                self.last_keep_alive = time.time()

            if not self.send_queue.empty():
                message = self.send_queue.get()
                
                if isinstance(message, bytes):
                    header = Protocol_header.bytes_to_header(message[:HEADER_SIZE])
                    if header.seq_num == self.error_seq_num:
                        corrupted_message = self.simulate_error(message)
                        print(f"Simulating corruption for seq_num {header.seq_num}")
                        self.sock.sendto(corrupted_message, (self.dest_ip, self.dest_port))
                        self.error_seq_num = None
                    else:
                        self.sock.sendto(message, (self.dest_ip, self.dest_port))
                else:
                    self.sock.sendto(message, (self.dest_ip, self.dest_port))

            time.sleep(0.02)

    def simulate_error(self, packet):
        header_size = HEADER_SIZE
        corrupted_packet = bytearray(packet)

        if len(packet) > header_size:
            data_start = header_size
            error_index = random.randint(data_start, len(packet) - 1)
            corrupted_packet[error_index] = random.randint(0, 255)
            print(f"Simulated corruption at index {error_index}")

        return bytes(corrupted_packet)


    def send(self, flag, seq_num=0, ack_num=0, window=0, fragment_size=0, message=""):
        if isinstance(message, str):
            payload = message.encode('utf-8')
        elif isinstance(message, bytes):
            payload = message
        else:
            payload = b''
        
        checksum = self.calculate_checksum(payload)
        header = Protocol_header(
            flag=flag,
            seq_num=seq_num,
            ack_num=ack_num,
            window=self.window_size,
            fragment_size=fragment_size,
            check_sum=checksum
        )
        packet = header.header_to_bytes() + payload
        if flag != KEEPALIVE and flag != NACK and flag != ACK and flag != FIN and flag != SYN_ACK and flag != SYN:
            self.seq_num += 1

        self.sent_packets[seq_num - 1] = packet
        
        self.send_queue.put(packet)

    def process_ack_window(self):
        if len(self.post_nack_fragments) > 0:
            #print("Waiting for missing fragments to arrive...")

            missing_seq = min(self.post_nack_fragments)
            #print(f"Missing fragment seq_num={missing_seq}")
            if missing_seq in self.received_acks:
                print(f"Missing fragment seq_num={missing_seq} received. Updating window...")
                self.post_nack_fragments.remove(missing_seq)

                for seq in sorted(self.saved_acks):
                    self.received_acks.add(seq)
                self.post_nack_fragments.clear()
            else:
                #print(f"Still waiting for fragment seq_num={missing_seq}.")
                return

        while self.window_base in self.received_acks:
            #print(f"Window base moving forward from {self.window_base}")
            self.received_acks.remove(self.window_base)
            self.window_base += 1
            print(f"New window base: {self.window_base}")

            if self.window_base in self.sent_packets:
                del self.sent_packets[self.window_base]
                print(f"Packet with seq_num={self.window_base} removed from sent_packets")

            if self.window_base in [frag["seq_num"] for frag in self.sent_fragments.values()] and len(self.post_nack_fragments) == 0:
                index = [i for i, frag in self.sent_fragments.items() if frag["seq_num"] == self.window_base][0]
                del self.sent_fragments[index]
                print(f"Fragment with seq_num={self.window_base} removed from sent_fragments")

        for seq_num in sorted(self.received_acks):
            if seq_num < self.window_base:
                continue

            if seq_num not in self.received_acks:
                print(f"Detected missing fragment seq_num={seq_num}, halting window progression.")
                self.post_nack_fragments[seq_num] = True
                break

        self.last_ack_check = time.time()



    def receive(self):
        self.sock.settimeout(KEEP_ALIVE_INTERVAL)
        complete_message = b""
        total_fragments = None

        while self.running:
            try:
                data, addr = self.sock.recvfrom(2048)
                if not self.running:
                    break

                if len(data) < HEADER_SIZE:
                    print("Error: Received data is smaller than header size.")
                    continue

                header_data = data[:HEADER_SIZE]
                payload = data[HEADER_SIZE:]
                try:
                    header = Protocol_header.bytes_to_header(header_data)
                except Exception as e:
                    print(f"Error parsing header: {e}")
                    continue

                flag = header.flag
                seq_num = header.seq_num
                ack_num = header.ack_num
                window = header.window
                fragment_size = header.fragment_size
                checksum = header.check_sum

                if flag == KEEPALIVE:
                    self.keep_alive_heartbeat = 0
                    self.last_keep_alive = time.time()
                    self.is_connected = True
                    self.state = "ESTABLISHED"
                    self.connection_started = True
                    #print(f"Received keep-alive packet {seq_num}")
                    continue

                calculated_checksum = self.calculate_checksum(payload)
                if calculated_checksum != checksum:
                    print(f"Checksum mismatch for seq_num={seq_num}: expected {checksum}, got {calculated_checksum}")
                    print("Sending NACK")
                    self.number_of_nacks += 1
                    self.send(NACK, seq_num=seq_num, ack_num=ack_num)
                    continue

                if time.time() - self.last_ack_check >= 0.01 and flag == ACK:
                    self.process_ack_window()

                #print(f"Received packet with control={flag}, seq_num={seq_num}, ack_num={ack_num}, checksum={checksum}")

                if flag == SYN:
                    print("Received SYN")
                    if not self.is_connected:
                        self.send(SYN_ACK, seq_num=0, ack_num=0)
                        self.state = "SYN_SENT"
                        self.error_seq_num = None

                elif flag == ACK and self.state == "SYN_SENT":
                    print("Connection established")
                    self.is_connected = True
                    self.state = "ESTABLISHED"
                    self.connection_started = True
                    self.window_base = seq_num + 1
                    if not self.keep_alive_started:
                        self.keep_alive_started = True

                elif flag == NACK:
                    print(f"Received NACK for seq_num={seq_num}, retransmitting packet...")
                    fragment_info = self.sent_fragments.get(seq_num - 2)
                    if fragment_info:
                        self.send_queue.put(fragment_info["packet"])
                        self.post_nack_fragments.append(seq_num)
                        print(f"Retransmitted packet with seq_num={seq_num}")
                    else:
                        print(f"Warning: seq_num={seq_num} not found in sent_fragments.")

                        
                elif header.flag == ACK and self.state == "ESTABLISHED":
                    print(f"Received ACK for seq_num={seq_num}")
                    if seq_num >= self.window_base and seq_num < self.window_base + self.window_size:
                        if len(self.post_nack_fragments) > 0:
                            mis_seq = min(self.post_nack_fragments)
                            #print(f"Detected missing fragment seq_num={mis_seq}, halting window progression.")
                            if seq_num > mis_seq:
                                self.saved_acks.append(seq_num)
                                print(f"Saved ACK for seq_num={seq_num}")
                            elif seq_num == mis_seq:
                                print(f"Retransmitting missing fragment seq_num={mis_seq}")
                                self.received_acks.add(seq_num)
                                self.process_ack_window()
                        else:
                            self.received_acks.add(seq_num)
                        #self.received_acks.add(seq_num)

                        #print(f"Current window: [{self.window_base}, {self.window_base + self.window_size - 1}]")

                elif flag == SYN_ACK:
                    print("Received SYN-ACK")
                    self.send(ACK, seq_num=0, ack_num=0)
                    self.is_connected = True
                    #self.connection_started = True
                    self.state = "ESTABLISHED"
                    self.seq_num = 1
                    self.window_base = seq_num + 1

                elif flag == FIN:
                    print("Received FIN, sending ACK and closing connection...")
                    self.send(ACK, seq_num=seq_num, ack_num=seq_num + 1)
                    self.is_connected = False
                    self.state = "INITIAL"
                    self.connection_started = False
                    self.running = False
                    self.sock.close()

                elif flag == DATA:
                    if payload.startswith(b"FILE "):
                        try:
                            file_info = payload.decode("utf-8")
                            _, file_name, file_size, total_fragments = file_info.split(" ", 3)
                            self.current_file_name = file_name
                            self.current_file_size = int(file_size)
                            self.expected_fragments = int(total_fragments)
                            #self.received_fragments = 0
                            self.received_file_data = b""
                            print(f"Receiving file: {self.current_file_name} ({self.current_file_size} bytes, {self.expected_fragments} fragments)")
                        except Exception as e:
                            print(f"Error processing file header: {e}")
                        finally:
                            self.switch_to_file_mode()
                            self.send(ACK, seq_num=seq_num, ack_num=seq_num + 1, window=self.window_size)
                    else:
                        if self.mode == "FILE":
                            # print(f"Received file fragment of size {len(payload)} bytes, processing...")
                            # self.receive_file_fragment(payload)
                            # self.send(ACK, seq_num=seq_num, ack_num=seq_num + 1, window=self.window_size)
                            if seq_num not in self.received_fragments:
                                self.received_fragments[seq_num] = payload
                                print(f"Received fragment with seq_number={seq_num} for total_fragment: {total_fragments}")
                                self.send(ACK, seq_num=seq_num, ack_num=seq_num + 1, window=self.window_size)
                                print(f"Sent ACK for fragment for seq_number={seq_num}")
                            else:
                                print(f"Duplicate fragment {seq_num} received, ignoring...")

                            #self.received_fragments += 1
                            if len(self.received_fragments) == self.expected_fragments:
                                print(f"\nNumber of received fragments: {len(self.received_fragments)}")
                                print(f"Number of corupted fragments(NACK): {self.number_of_nacks}\n")
                                self.number_of_nacks = 0
                                self.received_fragments.clear()
                                try:
                                    self.save_file()
                                    total_fragments = None
                                    continue
                                except Exception as e:
                                    print(f"Error saving received file: {e}")
                        elif payload.startswith(b"START_FRAGMENTATION"):
                            print("Received initial message with fragmentation info")
                            meta_data = {}
                            meta_data_str = payload.decode('utf-8', errors='ignore')
                            for key_value in meta_data_str.split("|"):
                                if ":" in key_value:
                                    key, value = key_value.split(":", 1)
                                    meta_data[key] = value
                            total_fragments = int(meta_data["Fragments"])
                            fragment_size = int(meta_data["FragmentSize"])
                            print(f"Total fragments: {total_fragments}, Fragment size: {fragment_size}")
                            self.send(ACK, seq_num=seq_num, ack_num=seq_num + 1, window=self.window_size)
                            continue

                        if total_fragments and self.mode == "TEXT":
                            if seq_num not in self.received_fragments:
                                self.received_fragments[seq_num] = payload
                                print(f"Received fragment with seq_number={seq_num} for total_fragment: {total_fragments}")
                                self.send(ACK, seq_num=seq_num, ack_num=seq_num + 1, window=self.window_size)
                                print(f"Sent ACK for fragment for seq_number={seq_num} for total_fragment: {total_fragments}")
                            else:
                                print(f"Duplicate fragment {seq_num} received, ignoring...")

                            if len(self.received_fragments) == total_fragments:
                                print(f"\nNumber of received fragments: {len(self.received_fragments)}")
                                print(f"Number of corupted fragments(NACK): {self.number_of_nacks}\n")
                                self.number_of_nacks = 0
                                complete_message = b''.join(self.received_fragments[i] for i in sorted(self.received_fragments))
                                print("All fragments received, message reassembled:")
                                print(complete_message.decode('utf-8', errors='replace'))
                                self.received_fragments.clear()
                                total_fragments = None
                        else:
                            if self.mode == "TEXT" and not total_fragments:
                                print(f"Received DATA: {payload.decode('utf-8', errors='replace')}")
                                print(f"Sending ACK for seq_num={seq_num}")
                                self.send(ACK, seq_num=seq_num, ack_num=seq_num + 1)

            except socket.timeout:
                if time.time() - self.last_keep_alive > KEEP_ALIVE_TIMEOUT:
                    print("KEEP_ALIVE_TIMEOUT reached in receive. Shutting down.")
                    self.running = False
                    break
            except ConnectionResetError:
                print("Connection reset error occurred.")
                self.is_connected = False
                self.running = False
                break

    def receive_file_fragment(self, fragment):
        self.received_file_data += fragment
        #print(f"Accumulated file size: {len(self.received_file_data)} bytes")

    def save_file(self):
        file_path = os.path.join(self.default_save_path, self.current_file_name)
        try:
            with open(file_path, 'wb') as file:
                file.write(self.received_file_data)
            print(f"File transfer complete. File saved as: {file_path}")
        except Exception as e:
            print(f"Error saving received file: {e}")
        finally:
            self.switch_to_text_mode()

    def switch_to_file_mode(self):
        print("Switching to file mode...")
        self.mode = "FILE"

    def switch_to_text_mode(self):
        print("Switching to text mode...")
        self.mode = "TEXT"

    def calculate_checksum(self, data):
        return zlib.crc32(data) & 0xffffffff
    
    def verify_checksum(self, header, data):
        calculated_checksum = self.calculate_checksum(data)
        return calculated_checksum == header.check_sum 

    def send_keep_alive(self):
        while self.running:
            if self.is_connected:
                self.keep_alive_heartbeat += 1
                self.send(seq_num=self.seq_num, flag=KEEPALIVE, ack_num=self.window_base, window=self.window_size)
                #print(f"Sent KEEPALIVE with seq_num {self.seq_num}")
            time.sleep(KEEP_ALIVE_INTERVAL)

    def check_keep_alive(self):
        while self.running:
            if self.is_connected and (time.time() - self.last_keep_alive > KEEP_ALIVE_TIMEOUT):
                print("KEEP_ALIVE_TIMEOUT reached. Connection lost. Shutting down.")
                
                self.is_connected = False
                self.state = "INITIAL"
                self.connection_started = False
                self.running = False
                
                self.sock.close()
                break
            
            time.sleep(1)


    # def check_keep_alive(self):
    #     while self.running:
    #         try:
    #             if self.is_connected and (time.time() - self.last_keep_alive > KEEP_ALIVE_TIMEOUT):
    #                 print("KEEP_ALIVE_TIMEOUT reached. Attempting to re-establish connection.")
    #                 retries = 3
    #                 for attempt in range(1, retries + 1):
    #                     print(f"Retry attempt {attempt} to send keep-alive.")
    #                     self.send(seq_num=self.seq_num, flag=KEEPALIVE, ack_num=self.window_base, window=self.window_size)
    #                     time.sleep(KEEP_ALIVE_INTERVAL)
    #                     if time.time() - self.last_keep_alive < KEEP_ALIVE_TIMEOUT:
    #                         print("Keep-alive response received. Connection restored.")
    #                         break
    #                 else:
    #                     print("Failed to re-establish connection after 3 attempts. Closing connection.")
    #                     self.is_connected = False
    #                     self.state = "INITIAL"
    #                     self.connection_started = False
    #                     self.running = False
    #                     self.sock.close()
    #                     break
    #         except ConnectionResetError:
    #             print("Connection reset error occurred. Stopping keep-alive checks.")
    #             self.is_connected = False
    #             self.running = False
    #             self.sock.close()
    #             break
    #         time.sleep(1)


    def quit(self):
        print("Initiating connection termination...")

        time.sleep(2)

        # Надіслати FIN
        self.send(flag=FIN,seq_num=self.seq_num)
        print(f"Sent FIN with seq_num {self.seq_num}")
        self.seq_num += 1
        self.state = "FIN_WAIT"

        start_time = time.time()
        while time.time() - start_time < 3:
            try:
                self.sock.settimeout(1)
                data, addr = self.sock.recvfrom(1024)

                header = Protocol_header.bytes_to_header(data[:HEADER_SIZE])
                payload = data[HEADER_SIZE:]
                if not self.verify_checksum(header, payload):
                    print("Checksum verification failed. Ignoring packet.")
                    continue

                if header.flag == ACK and self.state == "FIN_WAIT":
                    print(f"Received ACK for FIN with ack_num {header['ack_num']}. Connection terminated gracefully.")
                    break

            except socket.timeout:
                continue

        self.is_connected = False
        self.state = "INITIAL"
        self.connection_started = False
        self.running = False
        self.sock.close()
        print("connection terminated")

    def send_message_in_fragments(self, message, fragment_size, message_type="TEXT", file_name="", file_size=0):
        fragments, checksums = self.fragmentation(message, fragment_size)
        total_fragments = len(fragments)

        if message_type == "TEXT":
            initial_message = (
                f"START_FRAGMENTATION|Fragments: {total_fragments}|"
                f"FragmentSize: {fragment_size}|Type: {message_type}"
            ).encode('utf-8')
            
            self.send(
                seq_num=self.seq_num,
                flag=DATA,
                message=initial_message
            )

            # self.seq_num += 1
            print(f"Sent initial message with fragmentation info: {initial_message.decode('utf-8')}")
        elif message_type == "FILE":
            file_info = f"FILE {file_name} {file_size} {total_fragments}"
            self.send(
                seq_num=self.seq_num,
                flag=DATA,
                message=file_info.encode("utf-8"),
            )
            print(f"Sent initial message with seq_num: {self.seq_num}")
            # self.seq_num += 1
            print(f"Sent file info: {file_info}")

        for i, fragment_data in enumerate(fragments):
            seq_num = self.seq_num + i
            checksum = checksums[i]

            header = Protocol_header(
                flag=DATA,
                seq_num=seq_num,
                ack_num=0,
                window=self.window_size,
                fragment_size=fragment_size,
                check_sum=checksum
            )
            packet = header.header_to_bytes() + fragment_data
            self.sent_fragments[i] = {"packet": packet, "status": "sent", "seq_num": seq_num}
            print(f"Created packet {i + 1}/{len(fragments)} with seq_num {seq_num}")

        # # Відправлення фрагментів
        # for fragment in self.sent_fragments.values():
        #     self.send_queue.put(fragment["packet"])
        # self.seq_num += total_fragments

        time.sleep(1)

        #self.sent_fragments = {i: {"packet": fragment, "status": "sent", "seq_num": self.seq_num - 1 + i} for i, fragment in enumerate(fragments)}
        
        while self.sent_fragments:
            sent_packets = 0
            current_batch = []
            for seq_num, fragment_info in list(self.sent_fragments.items()):
                if fragment_info["status"] == "sent" and self.window_base <= fragment_info["seq_num"] < self.window_base + self.window_size:
                    self.send_queue.put(fragment_info["packet"])
                    fragment_info["send_time"] = time.time()
                    current_batch.append(seq_num)
                    sent_packets += 1
                    self.seq_num += 1
                    print(f"Sent fragment {seq_num}")
                    # Simulate an error
                    if fragment_info["seq_num"] == 70:
                        self.error_seq_num = 70

                if sent_packets >= self.window_size:
                    break

            start_time = time.time()
            attempts = 0
            while True:
                if all(seq_num not in self.sent_fragments for seq_num in current_batch):
                    #print(f"All packets from current batch confirmed: {current_batch}")
                    break

                if attempts == 3:
                    print("Fragments failed to send after 3 attempts")
                    break

                if time.time() - start_time > 10:
                    print(f"Timeout: Re-sending unacknowledged packets from batch: {current_batch}")
                    for seq_num in current_batch:
                        if seq_num in self.sent_fragments:
                            self.send_queue.put(self.sent_fragments[seq_num]["packet"])
                            self.sent_fragments[seq_num]["send_time"] = time.time()
                    attempts += 1
                    break
                time.sleep(0.25)

            if not self.sent_fragments:
                print("All fragments have been acknowledged. Message sent successfully.")
                break

    def send_file_in_fragments(self, file_path, fragment_size):
        try:
            with open(file_path, 'rb') as file:
                file_data = file.read()
            
            file_name = os.path.basename(file_path)
            #file_size = len(file_data)
            file_size = os.path.getsize(file_path)

            total_fragments = (file_size + fragment_size - 1) // fragment_size

            print(f"Starting file transfer in {total_fragments} fragments...")
            self.send_message_in_fragments(file_data, fragment_size, message_type="FILE", file_name=file_name, file_size=file_size)
            print(f"File transfer completed for {file_name}.")
        except FileNotFoundError:
            print(f"File not found: {file_path}")
        except Exception as e:
            print(f"Error during file transfer: {e}")

    def fragmentation(self, data, fragment_size):
        data = data.encode('utf-8') if isinstance(data, str) else data
        
        number_of_fragments = (len(data) + fragment_size - 1) // fragment_size
        fragments = []
        checksums = []

        for i in range(number_of_fragments):
            start = i * fragment_size
            end = start + fragment_size
            fragment_data = data[start:end]
            checksum = self.calculate_checksum(fragment_data)

            fragments.append(fragment_data)
            checksums.append(checksum)

            print(f"Prepared fragment {i + 1}/{number_of_fragments} with checksum {checksum}")

        return fragments, checksums

