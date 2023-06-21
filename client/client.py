import socket
import hashlib
import time
import hmac
import random
import struct
import pyotp
import base64 

# Packet field sizes
MACHINE_ID_SIZE = 36
NONCE_SIZE = 2
TIMESTAMP_SIZE = 8
HMAC_SIZE = 32

def generate_packet(machine_id, source_ip, shared_secret):
    # Set packet field values
    timestamp = int(time.time())

    # Generate nonce value (between 0 and 65535)
    nonce = random.randint(0, 65535)

    # Generate HMAC for machine_id
    hmac_algorithm = hashlib.sha256()
    hmac_algorithm.update(shared_secret.encode())
    hmac_algorithm.update(machine_id.encode())
    hmac_value = hmac_algorithm.digest()

    shared_secret_base32 = base64.b32encode(hmac_value).decode()

    # Generate TOTP based on the current time
    totp = pyotp.TOTP(shared_secret_base32)
    totp_value = totp.at(timestamp)

    print(" - OTP  [", totp_value, "]")

    # Generate HMAC
    hmac_value = generate_hmac(shared_secret, machine_id, nonce, timestamp, source_ip, totp_value)

    # Create packet
    packet_data = (
        machine_id.encode().ljust(MACHINE_ID_SIZE, b'\x00') +
        nonce.to_bytes(NONCE_SIZE, byteorder='big') +
        timestamp.to_bytes(TIMESTAMP_SIZE, byteorder='big') +
        socket.inet_aton(source_ip) +
        totp_value.encode().ljust(HMAC_SIZE, b'\x00') +
        hmac_value.ljust(HMAC_SIZE, b'\x00') 
    )

    return packet_data


def generate_hmac(shared_secret, machine_id, nonce, timestamp, source_ip, totp_value):
    # Prepare data for HMAC generation
    data = (
        machine_id.encode().ljust(MACHINE_ID_SIZE, b'\x00') +
        nonce.to_bytes(NONCE_SIZE, byteorder='big') +
        timestamp.to_bytes(TIMESTAMP_SIZE, byteorder='big') +
        socket.inet_aton(source_ip) + 
        totp_value.encode().ljust(HMAC_SIZE, b'\x00')
    )

    key = shared_secret.encode()

    # Calculate HMAC
    hmac_algorithm = hashlib.sha256()
    hmac_algorithm.update(key)
    hmac_algorithm.update(data)
    hmac_value = hmac_algorithm.digest()

    print (" - HMAC [", hmac_value.hex(), "]")

    return hmac_value


# Create UDP socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('localhost', 12345)

with open('shared_secret', 'r') as file:
    shared_secret = file.read().strip()

# Generate packet
machine_id = "d9afb880-9a1a-103d-8002-1a506ad6292a"
source_ip = "192.168.1.100"
packet = generate_packet(machine_id, source_ip, shared_secret)

# Send packet
client_socket.sendto(packet, server_address)

print("Packet sent successfully")
