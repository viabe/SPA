package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"
)

const (
	MachineIDSize   = 36
	NonceSize       = 2
	TimestampSize   = 8
	HMACSize        = 32
	PacketSize      = MachineIDSize + NonceSize + TimestampSize + net.IPv4len + HMACSize
	SharedSecretFile = "shared_secret"
)

func generatePacket(machineID, sourceIP, sharedSecret string) []byte {
	// Set packet field values
	timestamp := time.Now().Unix()

	// Generate nonce value (between 0 and 65535)
	nonce := uint16(time.Now().Nanosecond() & 0xffff)

	// Generate HMAC
	hmacValue := generateHMAC(sharedSecret, machineID, nonce, timestamp, sourceIP)

	// Create packet
	packet := make([]byte, PacketSize)
	copy(packet[:MachineIDSize], machineID)
	binary.BigEndian.PutUint16(packet[MachineIDSize:MachineIDSize+NonceSize], nonce)
	binary.BigEndian.PutUint64(packet[MachineIDSize+NonceSize:MachineIDSize+NonceSize+TimestampSize], uint64(timestamp))
	copy(packet[MachineIDSize+NonceSize+TimestampSize:MachineIDSize+NonceSize+TimestampSize+net.IPv4len], net.ParseIP(sourceIP).To4())
	copy(packet[MachineIDSize+NonceSize+TimestampSize+net.IPv4len:], hmacValue)

	return packet
}

func generateHMAC(sharedSecret, machineID string, nonce uint16, timestamp int64, sourceIP string) []byte {
	// Prepare data for HMAC generation
	data := make([]byte, 0, MachineIDSize+NonceSize+TimestampSize+net.IPv4len)
	data = append(data, []byte(machineID)...)
	data = append(data, make([]byte, MachineIDSize-len(machineID))...)
	nonceBytes := make([]byte, NonceSize)
	binary.BigEndian.PutUint16(nonceBytes, nonce)
	data = append(data, nonceBytes...)
	timestampBytes := make([]byte, TimestampSize)
	binary.BigEndian.PutUint64(timestampBytes, uint64(timestamp))
	data = append(data, timestampBytes...)
	ip := net.ParseIP(sourceIP).To4()
	data = append(data, ip...)

	// key, err := os.ReadFile(SharedSecretFile)
	// if err != nil {
	// 	fmt.Println("Failed to read shared secret:", err)
	// 	os.Exit(1)
	// }

	key := []byte(sharedSecret)

	// Calculate HMAC
	h := hmac.New(sha256.New, key)
	h.Write(data)
	hmacValue := h.Sum(nil)

	fmt.Println("HMAC:", hex.EncodeToString(hmacValue))

	return hmacValue
}

func main() {
	serverAddress := "localhost:12345"

	// Generate packet
	machineID := "d9afb880-9a1a-103d-8002-1a506ad6292a"
	sourceIP := "192.168.1.100"
	packet := generatePacket(machineID, sourceIP, "secret123")

	// Create UDP socket
	clientConn, err := net.Dial("udp", serverAddress)
	if err != nil {
		fmt.Println("Failed to create socket:", err)
		os.Exit(1)
	}
	defer clientConn.Close()

	// Send packet
	_, err = clientConn.Write(packet)
	if err != nil {
		fmt.Println("Failed to send packet:", err)
		os.Exit(1)
	}

	fmt.Println("Packet sent successfully")
}

