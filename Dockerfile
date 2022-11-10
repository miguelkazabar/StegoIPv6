FROM fedora:latest

WORKDIR /opt/stegoipv6

COPY CMakeLists.txt stegoipv6.h stegoipv6.cpp ./

RUN dnf update -y && \
    dnf install gcc-c++ git libtool autoconf automake cmake -y && \
    dnf install cryptopp cryptopp-devel -y && \
    dnf install libpcap-devel -y && \
    git clone https://github.com/pellegre/libcrafter && \
    cd libcrafter/libcrafter && \
    ./autogen.sh --libdir=/usr/lib64 && \
    make && make install && \
    ldconfig && \
    cd /opt/stegoipv6 && cmake . && make

CMD ["./StegoIPv6"]