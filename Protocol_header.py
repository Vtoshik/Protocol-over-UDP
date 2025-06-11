class Protocol_header:
    def __init__(self, flag, seq_num, ack_num, window, fragment_size, check_sum):
        self.flag = flag
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.window = window
        self.fragment_size = fragment_size
        self.check_sum = check_sum

    def header_to_bytes(self):
        return (
            self.flag.to_bytes(1, byteorder='big') +  # Flag - 1 byte (2 bits)
            self.seq_num.to_bytes(2, byteorder='big') +  # Sequence Number - 2 bytes
            self.ack_num.to_bytes(2, byteorder='big') +  # Acknowledgment Number - 2 bytes
            self.window.to_bytes(2, byteorder='big') +  # Window Size - 2 byte
            self.fragment_size.to_bytes(2, byteorder='big') +  # Fragment Size - 2 byte
            self.check_sum.to_bytes(4, byteorder='big')  # Checksum - 4 bytes (CRC32)
        )
    
    @staticmethod
    def bytes_to_header(data):
        flag = int.from_bytes(data[0:1], byteorder='big')
        seq_num = int.from_bytes(data[1:3], byteorder='big')
        ack_num = int.from_bytes(data[3:5], byteorder='big')
        window = int.from_bytes(data[5:7], byteorder='big')
        fragment_size = int.from_bytes(data[7:9], byteorder='big')
        check_sum = int.from_bytes(data[9:13], byteorder='big')
        return Protocol_header(flag, seq_num, ack_num, window, fragment_size, check_sum)
    
