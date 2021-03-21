# StegoIPv6

StegoIPv6, as deduced from its name, is a small program created as a PoC for the implementation of a network steganographic method using IPv6 data packets.

## Dependencies

This project uses the following third party libraries:

- Package `libpcap-devel`, which provides libraries, include files, and other resources needed for developing libpcap applications for network packet manipulation.
- [Libcrater](https://github.com/pellegre/libcrafter), a "high level library for C++ designed to create and decode network packets", which uses the package `libpcap-devel` mentioned above.
- [Crypto++ Library](https://www.cryptopp.com/), a "free C++ class library of cryptographic schemes".

So, the first thing to do before building this project is to have them installed on your system.

### For RHEL/Fedora systems:

- Package `libpcap-devel`:
  ```console
  $ sudo dnf install libpcap-devel
  ```
  
- Libcrafter:
  ```console
  $ git clone https://github.com/pellegre/libcrafter
  $ cd libcrafter/libcrafter
  $ ./autogen.sh
  $ make
  $ sudo make install
  $ sudo ldconfig
  ```

- Crypto++:
  ```console
  $ sudo dnf install cryptopp cryptopp-devel
  ```

## Building

Once all the dependencies have been already installed, just execute the following commands to build StegoIPv6 application:

```console
$ cmake .
$ make
```

## Running

```console
$ sudo ./StegoIPv6
```

* Note that the application must be run as superuser, since it uses RAW sockets to do its job.

## Be aware of

Although the whole process is supposed to be really straight forward, it may happen that your system complains about locating linked library `libcrafter` when executing StegoIPv6. That's because Libcrafter installation stores the libraries in `/usr/local/lib` instead of the default folder used by your system to do this (`/usr/lib` or `/usr/lib64`). The error message when running StegoIPv6 could be the following:

```console
error while loading shared libraries: libcrafter.so.0: cannot open shared object file: No such file or directory
```

In that case, you could:

- Export your `LD_LIBRARY_PATH` (as root, since StegoIPv6 must be run as superuser) indicating the directory where libcrafter libraries are located.
  ```console
  # export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
  ```

- Or, as a better alternative, you could build Libcrafter by specifying the path used by your system as the default path for library storage:
  ```console
  $ git clone https://github.com/pellegre/libcrafter
  $ cd libcrafter/libcrafter
  $ ./autogen.sh --libdir=/usr/lib64
  $ make
  $ sudo make install
  $ sudo ldconfig
  ```

## Docker

This project contains a Dockerfile that lets you use the application in an easy and portable way. Based on a _Fedora_ image, it builds everything and gets it ready to be used:

```console
$ docker image build . -t stegoipv6:1.0.0
$ docker container run --rm -it --net=host stegoipv6:1.0.0
```

## Disclaimer

This project has been created only for research and educational purposes.

I will NOT take any responsibility and/or liability for how you choose to use any of the source code available here. By using any of the files available in this repository, you understand that you are AGREEING TO USE AT YOUR OWN RISK.

## License

`StegoIPv6` has been released under the GPL 3 license.