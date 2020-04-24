#!/usr/bin/python3
#
# DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
#         Version 2, December 2004
# 
#      Copyright (C) 2020 michal0803
#
# Everyone is permitted to copy and distribute verbatim or modified
# copies of this license document, and changing it is allowed as long
# as the name is changed.
#
# DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
# TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
# 0. You just DO WHAT THE FUCK YOU WANT TO.
#
import socket
import zlib
import sys
import struct


class ReciverICMP:
    def __init__(self, port):
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.socket.bind(('', port))
        self.data = None

    def listen(self):
        """
            Listen for ONE SEQUENCE of packets. It means that
            it could be more than one packet but they have to be in one sequence. 
            Listener know about the end of the sequence because of timeout.
            Then data is extracted from recived packets.
        """
        packets_list = []

        while True:
            try:
                packet = self.socket.recv(65535)
            except socket.timeout:
                break
            finally:
                # After first recived packet set timeout for incoming
                self.socket.settimeout(0.5)

            # Extract icmp from ip
            icmp = self._remove_ip_headers(packet)

            # Recognize request (not replay), collect data and sequence number
            if icmp[0] == 0x08:
                packets_list.append({
                    'seq': struct.unpack('!H', icmp[6:8])[0],
                    'data': self._get_icmp_data(icmp)
                })
            
        # Reset timeout
        self.socket.settimeout(None)
        self.data = self._prepare_data(packets_list)

    def _prepare_data(self, packets_list):
        """
            :packets_list - list of dicts e.g. {data: b'example', seq: 54}
                1. Sort list by sequence number in dicts.
                2. Join bytes-like data of all dicts.
                3. Decompress data
                4. Decode data
        """
        sorted_packets_list = sorted(packets_list, key=lambda k: k['seq'])
        compressed_data = b''.join([packet['data'] for packet in sorted_packets_list])
        clean_data = zlib.decompress(compressed_data).decode()

        return clean_data

    def _remove_ip_headers(self, bytes_packet):
        return bytes_packet[20:]

    def _get_icmp_data(self, bytes_packet):
        return bytes_packet[8:]


if __name__ == "__main__":
    # Example usage
    reciver = ReciverICMP(port=50)

    while True:
        # Recive data
        reciver.listen()
        # Print data
        print(f'>>> {reciver.data}')
