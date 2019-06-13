import binascii
import socket
import ssl
import struct
import sys

NRPE_REQUEST = 1
NRPE_RESPONSE = 2

NRPE_OK = 0

NRPE_VERSION = 2

_NRPE_STRUCT = ">hhIh"
_BUFFER_LENGHT = 1024 + 2

PACKET_SIZE = _BUFFER_LENGHT + 10


def calculate_checksum(_type, checksum, return_code, command):

    packet_without_checksum = _create_packet(_type, checksum, return_code, command)

    return binascii.crc32(packet_without_checksum) & 0xffffffff


def _create_packet(_type, checksum, return_code, command):

    if isinstance(command, str):
        command = str.encode(command) + str.encode('\0'*(_BUFFER_LENGHT-len(command)))

    return struct.pack(_NRPE_STRUCT, NRPE_VERSION, _type, checksum, return_code) + command


def create_request(command):

    request_checksum = calculate_checksum(NRPE_REQUEST, 0, NRPE_OK, command)

    return _create_packet(NRPE_REQUEST, request_checksum, NRPE_OK, command)


def parse_response(response):

    assert len(response) == PACKET_SIZE

    version, _type, checksum, return_code = struct.unpack(_NRPE_STRUCT, response[:10])
    buffer = response[10:]

    response_checksum = calculate_checksum(_type, 0, return_code, buffer)

    assert checksum == response_checksum

    return return_code, buffer


def check_nrpe(host, command, port=5666, timeout=10, use_ssl=False):

    if use_ssl:
        connection = ssl.wrap_socket(socket.create_connection((host, port), timeout=timeout), ciphers="ADH")
    else:
        connection = socket.create_connection((host, port), timeout=timeout)

    request = create_request(command)

    connection.sendall(request)

    response = connection.recv(PACKET_SIZE)

    return_code, response_buffer = parse_response(response)

    answer_string = response_buffer.decode('utf-8').split('\0', 1)[0]

    return return_code, answer_string


if __name__ == "__main__":

    import argparse

    parser = argparse.ArgumentParser('Python implementation of NRPE protocol')
    parser.add_argument('host', metavar='HOST', help='Server IP or hostname')
    parser.add_argument('command', metavar='COMMAND', help='NRPE command')
    args = parser.parse_args()

    exit_code, output = check_nrpe(args.host, args.command)

    print(output)
    sys.exit(exit_code)
