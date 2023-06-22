#include <stdio.h>
#include "gnspa.h"

int main() {
    // Sample packet data
    const char* shared_secret = "secret123";
    const char* machine_id = "d9afb880-9a1a-103d-8002-1a506ad6292a";
    const char* source_ip = "192.168.0.100";
    const char* server_ip = "0.0.0.0";
    int server_port = 12345;

    // Create a packet and fill its fields
    struct Packet packet;
    if (spa_fill_packet(shared_secret, machine_id, source_ip, &packet) != 0) {
        printf("Packet filling failed\n");
        return -1;
    }

    // Send the packet to the server
    if (spa_send_packet(&packet, server_ip, server_port) != 0) {
        printf("Packet sending failed\n");
        return -1;
    }

    return 0;
}
