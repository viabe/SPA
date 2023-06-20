package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

const (
	MACHINE_ID_SIZE = 36
	NONCE_SIZE      = 2
	TIMESTAMP_SIZE  = 8
	SOURCE_IP_SIZE  = 4
	HMAC_SIZE       = 32
)

func generateHMAC(sharedSecret, machineID string, nonce uint16, timestamp uint64, sourceIP net.IP) []byte {
	// Prepare data for HMAC generation
	data := make([]byte, 0)
	data = append(data, []byte(machineID)...)
	data = append(data, make([]byte, MACHINE_ID_SIZE-len(machineID))...)
	data = append(data, make([]byte, NONCE_SIZE)...)
	binary.BigEndian.PutUint16(data[MACHINE_ID_SIZE:MACHINE_ID_SIZE+NONCE_SIZE], nonce)
	binary.BigEndian.PutUint64(data[MACHINE_ID_SIZE+NONCE_SIZE:MACHINE_ID_SIZE+NONCE_SIZE+TIMESTAMP_SIZE], timestamp)
	data = append(data, sourceIP.To4()...)

	key := []byte(sharedSecret)

	// Calculate HMAC
	hmacAlgorithm := hmac.New(sha256.New, key)
	hmacAlgorithm.Write(data)
	hmacValue := hmacAlgorithm.Sum(nil)

	return hmacValue
}

func verifyPacket(packet []byte, sharedSecret string) bool {
	// Extract packet fields
	machineID := strings.TrimRight(string(packet[:MACHINE_ID_SIZE]), "\x00")
	nonce := binary.BigEndian.Uint16(packet[MACHINE_ID_SIZE : MACHINE_ID_SIZE+NONCE_SIZE])
	timestamp := binary.BigEndian.Uint64(packet[MACHINE_ID_SIZE+NONCE_SIZE : MACHINE_ID_SIZE+NONCE_SIZE+TIMESTAMP_SIZE])
	sourceIP := net.IP(packet[MACHINE_ID_SIZE+NONCE_SIZE+TIMESTAMP_SIZE : MACHINE_ID_SIZE+NONCE_SIZE+TIMESTAMP_SIZE+SOURCE_IP_SIZE])

	hmacValue := packet[len(packet)-HMAC_SIZE:]

	// Generate HMAC
	hmacCalculated := generateHMAC(sharedSecret, machineID, nonce, timestamp, sourceIP)

	fmt.Println("Received HMAC:", hmacValue)
	fmt.Println("Calculated HMAC:", hmacCalculated)

	// Compare HMAC values
	return hmac.Equal(hmacValue, hmacCalculated)
}

func main() {
	// Create UDP socket
	serverAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:12345")
	if err != nil {
		fmt.Println("Failed to resolve server address:", err)
		return
	}

	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		fmt.Println("Failed to create UDP socket:", err)
		return
	}

	defer serverConn.Close()

	sharedSecret := "secret123"

	// Receive and verify packets
	buffer := make([]byte, 1024)
	for {
		n, _, err := serverConn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("Failed to read UDP packet:", err)
			continue
		}

		receivedPacket := buffer[:n]

		if verifyPacket(receivedPacket, sharedSecret) {
			fmt.Println("Packet verification succeeded")
		} else {
			fmt.Println("Packet verification failed")
		}

		// Pretty print the received data
		fmt.Println("Received Data:")
		fmt.Println("MachineID:", strings.TrimRight(string(receivedPacket[:MACHINE_ID_SIZE]), "\x00"))
		fmt.Println("Nonce:", binary.BigEndian.Uint16(receivedPacket[MACHINE_ID_SIZE:MACHINE_ID_SIZE+NONCE_SIZE]))
		fmt.Println("Timestamp:", binary.BigEndian.Uint64(receivedPacket[MACHINE_ID_SIZE+NONCE_SIZE:MACHINE_ID_SIZE+NONCE_SIZE+TIMESTAMP_SIZE]))
		fmt.Println("Source IP:", net.IP(receivedPacket[MACHINE_ID_SIZE+NONCE_SIZE+TIMESTAMP_SIZE:MACHINE_ID_SIZE+NONCE_SIZE+TIMESTAMP_SIZE+SOURCE_IP_SIZE]))
		fmt.Println("HMAC:", receivedPacket[len(receivedPacket)-HMAC_SIZE:])
	}
}
