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
import zlib
import sys
import random
import socket
import struct


class DataOverICMP:
    def __init__(self, ip, port):
        # Socket properties
        self.ip = ip
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

        # ICMP fields
        self._set_initial_fields()

    def send(self, data, chunk_size=4096):
        """
            :data - string to send
            :chunk_size - if passed data is bigger than this bytes size, 
                data will be split into several packets.
        """
        data_list = self._prepare_data_list(data, chunk_size)

        # Generate raw packet for each piece of data and send it
        for data in data_list:
            self.fields['data'] = data
            raw_icmp = self._generate_raw_packet()
            self._send(raw_icmp)
            self._next_seq()

        self._set_initial_fields()

    def _send(self, raw_icmp):
        self.socket.sendto(raw_icmp, (self.ip, self.port))

    def _next_seq(self):
        self.fields['seq'] += 1

    def _set_initial_fields(self):
        self.fields = {
            'type': 8,
            'code': 0,
            'checksum': 0,
            'id': random.randint(1673, 23863),
            'seq': 1,
            'data': None
        }

    def _generate_raw_packet(self):
        """
            Calc checksum and generate raw bytes-like packet from fields.
        """
        # Make data length even number
        if len(self.fields['data']) % 2:
            self.fields['data'] += b'\x00'

        def packed_fields(initial_checksum=False):
            return struct.pack(
                '!bbHHh',
                self.fields['type'],
                self.fields['code'],
                # Initial checksum has to be 0
                0 if initial_checksum else self.fields['checksum'],
                self.fields['id'],
                self.fields['seq']
            ) + self.fields['data']

        self.fields['checksum'] = socket.htons(self._calc_checksum(packed_fields(True)))
        return packed_fields()

    def _prepare_data_list(self, data, chunk_size):
        """ 
            :chunk_size – number of bytes to split data
            Return list of (compressed, split into chunks) bytes data ready to
            be joined with the rest of the packet.
        """
        compressed = zlib.compress(data.encode(), 9)

        # If compressed data is bigger than one chunk
        # it has to be split into several chunks
        if sys.getsizeof(compressed) > chunk_size:
            chunks_list = []
            chunk = bytearray(b'')

            # Split data into chunks
            for byte in compressed:
                chunk.append(byte)

                if sys.getsizeof(chunk) >= chunk_size:
                    chunks_list.append(chunk)
                    chunk = bytearray(b'')

            # Append last chunk
            if chunk != b'':
                chunks_list.append(chunk)

            return chunks_list
        else:
            return [compressed]

    def _calc_checksum(self, data):
        """
            Calculate checksum for bytes-like object of ICMP packet.
        """
        def carry_around_add(a, b):
            c = a + b
            return (c & 0xffff) + (c >> 16)

        s = 0
        for i in range(0, len(data), 2):
            w = (data[i]) + (data[i+1] << 8)
            s = carry_around_add(s, w)

        return ~s & 0xffff


if __name__ == "__main__":
    # Example usage
    icmp = DataOverICMP(ip='192.168.1.21', port=50)
    icmp.send(
        data='testetststetststetstetstetststettsstet', 
        chunk_size=100
    )
