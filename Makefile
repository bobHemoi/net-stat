all		: packet-stat

packet-stat		: packetStat.o main.o
			g++ -o packet-stat packetStat.o main.o -lpcap

packetStat.o : packetStat.cpp packetStat.h
			g++ -c -o packetStat.o packetStat.cpp -lpcap

main.o 		: main.cpp packetStat.h
			g++ -c -o main.o main.cpp

clean 		:
			rm -f packet-stat *.o