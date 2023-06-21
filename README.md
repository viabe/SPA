# Packet Verification System

This repository provides a packet verification system that uses Time-Based One-Time Passwords (TOTP) and Hash-based Message Authentication Codes (HMAC) to ensure the integrity and authenticity of packets.

## Features

- Generates packets with TOTP and HMAC values
- Verifies received packets using TOTP and HMAC values

## Getting Started

To use the packet verification system, follow the steps below:

1. Clone the repository: `git clone https://github.com/sfreet/spa.git`
2. Install the required dependencies: `pip install pyotp`
3. Open the terminal and navigate to the repository directory: `cd spa`
4. Generate a shared secret and save it in a file named `shared_secret`. This secret will be used for HMAC calculation.
5. Update the `machine_id`, `source_ip`, and `server_address` variables in the provided code files to match your configuration.
6. Run the client-side script to generate and send a packet: `python client.py`
7. Run the server-side script to receive and verify the packets: `python server.py`
8. Observe the verification results in the terminal.

## Code Files

The repository contains the following code files:

- `client.py`: Generates and sends packets to the server.
- `server.py`: Receives and verifies packets from clients.
- `gnspa.c`: An example implementation in C for generating and sending packets.
- `gnspa.h`: Header file for the C implementation.

Usage:
1. Build and run the server:
   - Open a terminal and navigate to the 'spa' directory:
   - Run the server using Python 3:
```
  $ cd server
  $ python3 server.py
```
```
   Result:
   Calculated Data:
    - HMAC [ 6d343c4378f887634eb9b3d3a618d4a4fec07c11e0292562b9e95271ee440ac3 ]
    - OTP  [ 104207 ]
   Packet verification succeeded

   Received Data:
    - MachineID: d9afb880-9a1a-103d-8002-1a506ad6292a
    - Nonce: 56659
    - Timestamp: 1687339209
    - Source IP: 192.168.1.100
    - OTP: 104207
    - HMAC: 6d343c4378f887634eb9b3d3a618d4a4fec07c11e0292562b9e95271ee440ac3
```
2. Run the client:
   - Open another terminal and navigate to the 'spa' directory (if not already there):
   - Run the client using Python 3:
```
  $ cd client
  $ python3 client.py
```
```
   Result:
    - OTP  [ 104207 ]
    - HMAC [ cc2de10d0f60c100bdbdb047ffa5ff1bd162f486722944925dc2e777042c3a4b ]
```
## License

This project is licensed under the MIT License - see the `LICENSE` file for details.

## Acknowledgments

- The TOTP implementation uses the `pyotp` library.
- The C & golang implementation is Work in progress.