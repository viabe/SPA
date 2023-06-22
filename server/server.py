import socket
import hashlib
import hmac
import time
import struct
import pyotp
import base64 

# Packet field sizes
MACHINE_ID_SIZE = 36
NONCE_SIZE = 2
TIMESTAMP_SIZE = 8
SOURCE_IP_SIZE = 4
HMAC_SIZE = 32
OTP_SIZE = 6

def generate_hmac(shared_secret, machine_id, nonce, timestamp, source_ip, totp_value):
    # Prepare data for HMAC generation
    data = (
        machine_id.encode().ljust(MACHINE_ID_SIZE, b'\x00') +
        nonce.to_bytes(NONCE_SIZE, byteorder='big') +
        timestamp.to_bytes(TIMESTAMP_SIZE, byteorder='big') +
        socket.inet_aton(source_ip) +
        totp_value.encode().ljust(OTP_SIZE, b'\x00')
    )

    # Calculate HMAC
    hmac_algorithm = hashlib.sha256()
    hmac_algorithm.update(shared_secret.encode())
    hmac_algorithm.update(data)
    hmac_value = hmac_algorithm.digest()

    return hmac_value

def verify_otp(shared_secret, device_id, timestamp, totp_value):
    hmac_algorithm = hashlib.sha256()
    hmac_algorithm.update(shared_secret.encode())

    hmac_algorithm.update(device_id.encode())
    hmac_value = hmac_algorithm.digest()

    shared_secret_base32 = base64.b32encode(hmac_value).decode()

    totp = pyotp.TOTP(shared_secret_base32)

    timestamp = int(time.time())
    print(" - OTP  [", totp.at(timestamp), "]")

    return totp.verify(totp_value, timestamp)

def verify_packet(packet, shared_secret, device_id):
    # Extract packet fields
    machine_id = packet[:MACHINE_ID_SIZE].rstrip(b'\x00').decode()
    nonce = int.from_bytes(packet[MACHINE_ID_SIZE:MACHINE_ID_SIZE + NONCE_SIZE], byteorder='big')
    timestamp = int.from_bytes(packet[MACHINE_ID_SIZE + NONCE_SIZE:MACHINE_ID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE], byteorder='big')
    source_ip = socket.inet_ntoa(packet[MACHINE_ID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE:MACHINE_ID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE + SOURCE_IP_SIZE])
    totp_value = packet[MACHINE_ID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE + SOURCE_IP_SIZE:MACHINE_ID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE + SOURCE_IP_SIZE + OTP_SIZE].rstrip(b'\x00').decode()

    hmac_value = packet[-HMAC_SIZE:]

    # Generate HMAC
    hmac_calculated = generate_hmac(shared_secret, machine_id, nonce, timestamp, source_ip, totp_value)
    
    print("\nCalculated Data:")
    print(" - HMAC [", hmac_calculated.hex(), "]")

    # Compare HMAC values
    if hmac.compare_digest(hmac_value, hmac_calculated):
        # Verify OTP
        if verify_otp(shared_secret, device_id, timestamp, totp_value):
            return True
    else:
        return False


# Create UDP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('0.0.0.0', 12345)
server_socket.bind(server_address)

device_id = "d9afb880-9a1a-103d-8002-1a506ad6292a"

with open('shared_secret', 'r') as file:
    shared_secret = file.read().strip()

# Receive and verify packets
while True:
    data, client_address = server_socket.recvfrom(1024)
    received_packet = data

    if verify_packet(received_packet, shared_secret, device_id):
        print("Packet verification succeeded\n")
    else:
        print("Packet verification failed\n")

    # Pretty print the received data
    print("Received Data:")
    print(" - MachineID:", received_packet[:MACHINE_ID_SIZE].rstrip(b'\x00').decode())
    print(" - Nonce:", int.from_bytes(received_packet[MACHINE_ID_SIZE:MACHINE_ID_SIZE + NONCE_SIZE], byteorder='big'))
    print(" - Timestamp:", int.from_bytes(received_packet[MACHINE_ID_SIZE + NONCE_SIZE:MACHINE_ID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE], byteorder='big'))
    print(" - Source IP:", socket.inet_ntoa(received_packet[MACHINE_ID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE:MACHINE_ID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE + SOURCE_IP_SIZE]))
    print(" - OTP:", received_packet[MACHINE_ID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE + SOURCE_IP_SIZE:MACHINE_ID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE + SOURCE_IP_SIZE + OTP_SIZE].rstrip(b'\x00').decode())
    print(" - HMAC:", received_packet[-HMAC_SIZE:].hex())
    print("\n")
