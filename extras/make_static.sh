cd ../src
wget https://www.tcpdump.org/release/libpcap-1.10.0.tar.gz
tar -xf libpcap-1.10.0.tar.gz
cd libpcap-1.10.0
./configure --disable-shared --disable-dbus
make -j
cd ..

gcc -static -FPIC -O2 -o rooty rooty_unix.c rooty.c -I libpcap-1.10.0/pcap -I libpcap-1.10.0 -Llibpcap-1.10.0 -lpcap -lpthread
strip rooty
