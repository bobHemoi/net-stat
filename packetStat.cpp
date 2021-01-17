#include "packetStat.h"
#include "stdio.h"

void PacketStat::updateTxPacketStat(int bytesLen){
    bytes += bytesLen;
    txBytes += bytesLen;

    txPackets++;
    packets++;
}

void PacketStat::updateRxPacketStat(int bytesLen){
    bytes += bytesLen;
    rxBytes += bytesLen;

    rxPackets++;
    packets++;
}

void PacketStat::printPacketStat(){
    printf("%7d %5d %6d %6d %6d %6d\n\n", packets, bytes, txPackets, txBytes, rxPackets, rxBytes); 
}