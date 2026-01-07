#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &server_addr.sin_addr);

    // Simple DNS query for example.com
    unsigned char dns_query[] = {
        0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61,
        0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
        0x00, 0x00, 0x01, 0x00, 0x01
    };

    printf("Sending DNS query to 8.8.8.8...\n");
    sendto(sockfd, dns_query, sizeof(dns_query), 0,
           (struct sockaddr*)&server_addr, sizeof(server_addr));

    char buffer[512];
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    printf("Waiting for response...\n");
    ssize_t n = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                        (struct sockaddr*)&client_addr, &addr_len);
    if (n > 0) {
        printf("Received %zd bytes response\n", n);
    }

    close(sockfd);
    return 0;
}
