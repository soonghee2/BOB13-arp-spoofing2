#include "ip.h"

#pragma pack(push, 1)

struct IpHdr {
    uint8_t ver_ihl;     // Version (4 bits) + Internet header length (4 bits)
    uint8_t tos;         // Type of service
    uint16_t tot_len;    // Total length
    uint16_t id;         // Identification
    uint16_t frag_off;   // Fragment offset field
    uint8_t ttl;         // Time to live
    uint8_t protocol;    // Protocol (TCP, UDP, ICMP, etc.)
    uint16_t checksum;   // IP checksum
    Ip sip_;       // Source IP address
    Ip dip_;       // Destination IP address

    uint8_t ihl() const { return ver_ihl & 0x0F; }
    uint8_t version() const { return ver_ihl >> 4; }
    uint16_t total_length() const { return ntohs(tot_len); }
    uint16_t fragment_offset() const { return ntohs(frag_off); }
    Ip sip() const { return ntohl(sip_); }
    Ip dip() const { return ntohl(dip_); }

    enum Protocol : uint8_t {
        ICMP = 1,
        TCP = 6,
        UDP = 17
    };

    Protocol get_protocol() const { return static_cast<Protocol>(protocol); }
};

#pragma pack(pop)
