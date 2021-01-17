#include <pcap.h>
#include <netinet/in.h>
#include <iostream>
#include <map>
#include <string>
#include "libnet-headers-sample.h"
#include "packetStat.h"

#define ETHERNET_LENGTH 14
#define IP_LENGTH       20
#define TCP_LENGTH      20
#define TCP_CHECK       6

using namespace std;


void usage() {
    cout << "syntax : packet-stat <pcap file>" << endl;
    cout << "sample : packet-stat test.pcap" << endl;
}

class KeyIP {
    
    private:
        struct in_addr addr;
    
    public:
        bool operator<(const KeyIP &compAddr) const{
            return addr.s_addr < compAddr.addr.s_addr; 
        }

        char* ntoaIP(){
            return inet_ntoa(addr);
        }

        KeyIP(uint32_t IPaddr){
            addr.s_addr = IPaddr;
        }
};

void updatePacketStat(map<KeyIP, PacketStat*> &IP2Packet,
                                struct pcap_pkthdr* header, const u_char* packet) {
    const ipv4_hdr*     ip;
    ip = (ipv4_hdr *)(packet + ETHERNET_LENGTH);
    
    KeyIP sIPAddr = KeyIP(htonl(ip->ip_src));
    //cout << htonl(ip->ip_src) <<endl;
    //cout << ntohl(ip->ip_src) <<endl;
    
    KeyIP dIPAddr = KeyIP(htonl(ip->ip_dst));
    //cout << htonl(ip->ip_dst) <<endl;
    //cout << ntohl(ip->ip_dst) <<endl;
    

    if(IP2Packet.find(sIPAddr) == IP2Packet.end()){
        PacketStat* newpckt = new PacketStat();
        IP2Packet.insert(pair<KeyIP, PacketStat*>(sIPAddr, newpckt));
    }

    if(IP2Packet.find(dIPAddr) == IP2Packet.end()){
        PacketStat* newpckt = new PacketStat();
        IP2Packet.insert(pair<KeyIP, PacketStat*>(dIPAddr, newpckt));
    }
    
    PacketStat* sPacketStat = IP2Packet[sIPAddr];
    PacketStat* dPacketStat = IP2Packet[dIPAddr];

    int bytesLen = header->caplen;

    sPacketStat->updateTxPacketStat(bytesLen);
    dPacketStat->updateRxPacketStat(bytesLen);

    return;
}


int main(int argc, char* argv[]) {
    // sample : packet-stat test.pcap
    if (argc != 2) {
        usage();
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(argv[1], errbuf);

    map<KeyIP, PacketStat*> IP2Packet;

    while(true) {
        struct pcap_pkthdr* header;
        const u_char*       packet;
        const ipv4_hdr*     ip;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        updatePacketStat(IP2Packet, header, packet);
    }

    for (auto iter = IP2Packet.begin() ; iter != IP2Packet.end() ; iter++){
        KeyIP nIP = iter->first;
        PacketStat* pstat = iter->second;
        printf("[ADDRESS : %s]\n", nIP.ntoaIP()); 
        printf("PACKETS BYTES TXPCKT TXBYTE RXPCKT RXBYTE\n"); 
        pstat->printPacketStat();

    }
}
