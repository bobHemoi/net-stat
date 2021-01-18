class PacketStat {
    public:
        int packets;
        int bytes;
        int txPackets;
        int txBytes;
        int rxPackets;
        int rxBytes;

    public:
        void updateTxPacketStat(int);
        void updateRxPacketStat(int);
        void updateSMACPacketStat(int);
        void updateDMACPacketStat(int);

        void printPacketStat();


    PacketStat(){
        packets = 0;
        bytes = 0;
        txPackets = 0;
        txBytes = 0;
        rxPackets = 0;
        rxBytes = 0;
    }
};

