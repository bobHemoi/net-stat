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
#define UDP_CHECK       17

using namespace std;



void usage() {
    cout << "syntax : packet-stat <pcap file>" << endl;
    cout << "sample : packet-stat test.pcap" << endl;
}

class KeyIP {
    
    private:
        uint32_t addr;
    
    public:
        bool operator<(const KeyIP &compAddr) const{
            return addr < compAddr.addr; 
        }

        char* getIP(){
            return inet_ntoa(*(struct in_addr *)&addr);
        }

        KeyIP(uint32_t IPaddr){
            addr = IPaddr;
        }
};


class KeyMAC {
    
    private:
        string addr;

    public:
        bool operator<(const KeyMAC &compAddr) const{
            return addr < compAddr.addr; 
        }

        string getaddr() {
            return addr;
        }

        KeyMAC(char* mac){
            addr = mac;
        }
};

typedef pair<uint32_t, uint16_t> IPwPORT;

class KeyTCP {
    private:
        IPwPORT addr; // first : ip , second : tcp

    
    public:
        bool operator<(const KeyTCP &compAddr) const{
            uint32_t aAddr = addr.first;
            aAddr += addr.second;

            uint32_t bAddr = compAddr.addr.first;
            bAddr += compAddr.addr.second;

            return aAddr < bAddr; 
        }

        char* getIP(){
            return inet_ntoa(*(struct in_addr *)&addr.first);
        }

        uint16_t getPort(){
            return ntohs(addr.second);
        }

        KeyTCP(uint32_t ip, uint16_t port){
            addr.first = ip;
            addr.second = port;
        }
};


typedef map<KeyIP, PacketStat> IP2PCK;
typedef map<KeyMAC, PacketStat> MAC2PCK;
typedef map<KeyTCP, PacketStat> TCP2PCK;

void updatePacketStat(IP2PCK &IP2Packet,MAC2PCK &MAC2Packet, TCP2PCK &TCP2Packet,
                                struct pcap_pkthdr* header, const u_char* packet) {
                                
    int bytesLen = header->caplen;

    // MAC
    const ethernet_hdr* eth = (ethernet_hdr *)(packet);

    char smac[18];
    snprintf(smac, sizeof(smac), "%02x:%02x:%02x:%02x:%02x:%02x",
         eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);

    char dmac[18];
    snprintf(dmac, sizeof(smac), "%02x:%02x:%02x:%02x:%02x:%02x",
         eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    KeyMAC sMACAddr(smac);
    KeyMAC dMACAddr(dmac);

    if(MAC2Packet.find(sMACAddr) == MAC2Packet.end()){
        PacketStat newpckt = PacketStat();
        MAC2Packet.insert(pair<KeyMAC, PacketStat>(sMACAddr, newpckt));
    }

    if(MAC2Packet.find(dMACAddr) == MAC2Packet.end()){
        PacketStat newpckt = PacketStat();
        MAC2Packet.insert(pair<KeyMAC, PacketStat>(dMACAddr, newpckt));
    }

    MAC2Packet[sMACAddr].updateSMACPacketStat(bytesLen);
    MAC2Packet[dMACAddr].updateDMACPacketStat(bytesLen);


    // IP
    const ipv4_hdr*     ip;
    ip = (ipv4_hdr *)(packet + ETHERNET_LENGTH);
    
    KeyIP sIPAddr(ip->ip_src);
    KeyIP dIPAddr(ip->ip_dst);
    
    if(IP2Packet.find(sIPAddr) == IP2Packet.end()){
        PacketStat newpckt = PacketStat();
        IP2Packet.insert(pair<KeyIP, PacketStat>(sIPAddr, newpckt));
    }

    if(IP2Packet.find(dIPAddr) == IP2Packet.end()){
        PacketStat newpckt = PacketStat();
        IP2Packet.insert(pair<KeyIP, PacketStat>(dIPAddr, newpckt));
    }
    
    IP2Packet[sIPAddr].updateTxPacketStat(bytesLen);
    IP2Packet[dIPAddr].updateRxPacketStat(bytesLen);

    if (ip->ip_p != TCP_CHECK) return;

    // TCP
    const tcp_hdr*      tcp;
    tcp = (tcp_hdr *)(packet + ETHERNET_LENGTH + IP_LENGTH);


    KeyTCP sTCPAddr(ip->ip_src, tcp->th_sport);
    KeyTCP dTCPAddr(ip->ip_dst, tcp->th_dport);

    if(TCP2Packet.find(sTCPAddr) == TCP2Packet.end()){
        PacketStat newpckt = PacketStat();
        TCP2Packet.insert(pair<KeyTCP, PacketStat>(sTCPAddr, newpckt));
    }

    if(TCP2Packet.find(dTCPAddr) == TCP2Packet.end()){
        PacketStat newpckt = PacketStat();
        TCP2Packet.insert(pair<KeyTCP, PacketStat>(dTCPAddr, newpckt));
    }
    
    TCP2Packet[sTCPAddr].updateTxPacketStat(bytesLen);
    TCP2Packet[dTCPAddr].updateRxPacketStat(bytesLen);

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

    IP2PCK IP2Packet;
    MAC2PCK MAC2Packet;
    TCP2PCK TCP2Packet;

    while(true) {
        struct pcap_pkthdr* header;
        const u_char*       packet;
        const ipv4_hdr*     ip;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        updatePacketStat(IP2Packet, MAC2Packet, TCP2Packet, header, packet);

    }

    cout << "===================MAC===================" << endl; 
    for (auto iter = MAC2Packet.begin() ; iter != MAC2Packet.end() ; iter++){
        KeyMAC nMAC = iter->first;
        PacketStat pstat = iter->second;
        cout << "ADDRESS : " << nMAC.getaddr() << endl;
        cout << "PACKETS BYTES TXPCKT TXBYTE RXPCKT RXBYTE" << endl; 
        pstat.printPacketStat();
    }
    cout << "=========================================" << endl; 
    cout << "===================IP====================" << endl; 
    for (auto iter = IP2Packet.begin() ; iter != IP2Packet.end() ; iter++){
        KeyIP nIP = iter->first;
        PacketStat pstat = iter->second;
        cout << "ADDRESS : " << nIP.getIP() << endl;
        cout << "PACKETS BYTES TXPCKT TXBYTE RXPCKT RXBYTE" << endl; 
        pstat.printPacketStat();
    }
    cout << "=========================================" << endl; 
    cout << "==================TCP====================" << endl; 
    for (auto iter = TCP2Packet.begin() ; iter != TCP2Packet.end() ; iter++){
        KeyTCP nTCP = iter->first;
        PacketStat pstat = iter->second;
        cout << "IP : " << nTCP.getIP() << " PORT : " << nTCP.getPort() << endl;
        cout << "PACKETS BYTES TXPCKT TXBYTE RXPCKT RXBYTE" << endl; 
        pstat.printPacketStat();
    }
    cout << "=========================================" << endl; 

}
