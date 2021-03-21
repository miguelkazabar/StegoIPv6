#include <crafter.h>
#include <iomanip>
#include <algorithm>
#include "cryptopp/hex.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/filters.h"
#include <time.h>
#include <ifaddrs.h>
#include "stegoipv6.h"


//Constants' definition
const int MAX_PAYLOAD = 101;					// Maximum payload size
const int MAX_ADDRESS = 40;						// Maximum IPv6 address size
const int MAX_SECRET = 301;						// Maximum secret message's size
const int MAX_PASSWORD = 16;					// Maximum decryption password's size
const std::string initVect = "FE20C7B43095A740DF1560D83A7032B8";	// Initialization vector


int main() {

  // Show banner
  printBanner();

  // Select the mode for StegoIPv6 to be used
  std::cout << "[+] Please, enter the mode for StegoIPv6" << std::endl;
  std::cout << "[1] --> Sender" << std::endl;
  std::cout << "[2] --> Receiver" << std::endl;
  std::cout << "> ";

  int iSelection;
  std::cin >> iSelection;
  std::cin.ignore(1, '\n');

  switch (iSelection)
  {
  // SENDER MODE SELECTED
  case 1 :
  {
    // Notify the beginning of StegoIPv6 Sender
    std::cout << std::endl << "********* StegoIPv6 Sender started **********" << std::endl << std::endl;

    // Select the local network interface used to send the packets
    std::vector<std::string> vNetInterfaces = getNetworkInterfaces();
    std::cout << "[+] Please, select the local network interface to use" << std::endl;
    for (unsigned int i = 0; i < vNetInterfaces.size(); ++i) {
        std::cout << "[" << i+1 << "] --> "<< vNetInterfaces.at(i) << std::endl;
    }
    std::cout << "> ";

    unsigned int iNetInterface;
    std::cin >> iNetInterface;
    while(std::cin.fail() || iNetInterface <= 0 || iNetInterface > vNetInterfaces.size()) {
      std::cin.clear();
      std::cin.ignore(256,'\n');
      std::cout << "[!] (Please, enter a value between 1 and " << vNetInterfaces.size() << ")" << std::endl;
      std::cout << "> ";
      std::cin >> iNetInterface;
    }
    std::cin.ignore(1, '\n');

    std::string strNetInterface = vNetInterfaces.at(iNetInterface - 1);

    // Source IPv6 address (different for each packet)
    std::string src_ipv6;

    // Ask the destination IPv6 address
    char destiny[MAX_ADDRESS];
    std::string dst_ipv6;
    bool repeat = false;
    std::cout << "[+] Enter IPv6 destination address :" << std::endl << "> ";
    while (!repeat) {
      fgets(destiny, MAX_ADDRESS, stdin);
      dst_ipv6 = std::string(destiny);
      dst_ipv6.erase(dst_ipv6.size()-1);
      repeat = validateIpv6Address(dst_ipv6);
      if (!repeat) {
        std::cout << "[!] IPv6 address format incorrect! Please, try again." << std::endl << "> ";
      }
    }

    // Ask the port number where stego receiver will be listen on
    int portNumber;
    std::cout << "[+] Enter destination port (1024 - 65535) :" << std::endl << "> ";
    std::cin >> portNumber;
    std::cin.ignore(1, '\n');

    // Check if the port number is an integer
    if (!portNumber) {
      showError("[!] Error: The port number must be an integer. Please, try again.");
    }

    // Check if the port number is between 1024 and 65535 (is not a well-known port number)
    if (!((1024 <= portNumber) && (portNumber <= 65535))) {
      showError("[!] Error: The port number must between 1024 and 65535. Please, try again.");
    }

    // Create a payload with a decoy message
    char decoy[MAX_PAYLOAD+2];
    std::cout << "[+] Enter a decoy message : (100 characters max.)" << std::endl << "> ";
    fgets(decoy, MAX_PAYLOAD+2, stdin);
    if (strlen(decoy) > MAX_PAYLOAD) {
      showError("[!] Error: Decoy's lenght can't be greater than 100 characters. Please, try again.");
    }
    decoy[strlen(decoy)-1] = '\0';
    
    // Set the character for padding if necessary
    std::string padding = "0";

    // Ask the secret message to send it to the stego receiver
    std::cout << "[+] Enter the secret message : (300 characters max.)" << std::endl << "> ";
    char strEstego[MAX_SECRET + 2];
    fgets(strEstego, MAX_SECRET + 2, stdin);
    if (strlen(strEstego)>MAX_SECRET) {
      showError("[!] Error: Secret message's lenght can't be greater than 300 characters. Please, try again.");
    }
    std::string plaintext(strEstego);
    plaintext.erase(plaintext.size());

    // Get the password to encrypt the stego message
    std::string password = getpass("[+] Enter the password to encrypt the stego message : (16 characters max.)\n> ");
    if (password.size()>MAX_PASSWORD) {
      showError("[!] Error: Password can't be greater than 16 characters. Please, try again.");
    }

    // Add some randomness to the Initialization Vector depending on the current execution time
    unsigned int iRand;
    srand(static_cast<unsigned int>(time(nullptr)));
    iRand = rand()% 90000 + 10000;
    std::string strRand = std::to_string(iRand);
    std::string strIniVectSend = generateRandomIV(strRand);

    // Cipher the stego message
    std::string ciphertext = encrypt(plaintext, password, strIniVectSend);

    // Add the flag to delimiter the end of secret message
    ciphertext += "f";

    // Add the random part of the Inicialization Vector
    ciphertext += strRand;

    // Number of packets neccesary to send the stego message
    unsigned long numberPackets = ciphertext.size() / 16;
    if (ciphertext.size() % 16) {
      numberPackets++;
      /* We add some padding if the stego message's lenght is NOT
      a multiple of 16 */
      for (unsigned long k = 0; k < ciphertext.size() % 16; ++k) {
        ciphertext += "0";
      }
    }

    // Format IPv6 addresses, packets and send them to the receiver
    int j = 0;
    for (unsigned long i = 0; i < numberPackets * 16; i = i + 16) {
      j++;
      src_ipv6 = "fe80::000";
      src_ipv6 += "f:";
      src_ipv6 += ciphertext.substr(i,4);
      src_ipv6 += ":";
      src_ipv6 += ciphertext.substr(i+4,4);
      src_ipv6 += ":";
      src_ipv6 += ciphertext.substr(i+8,4);
      src_ipv6 += ":";
      src_ipv6 += ciphertext.substr(i+12,4);
      sendStego(strNetInterface, src_ipv6, dst_ipv6, portNumber, decoy);
      std::cout << "[+] Packet "<< j << " sent with the IPv6 source address: "<< src_ipv6 << std::endl;
      usleep(1000);
    }

    // Send last packet to notify the end of transmissions
    src_ipv6 = "fe80::000f:1001:1001:1001:1001";
    sendStego(strNetInterface, src_ipv6, dst_ipv6, portNumber, decoy);
    std::cout << "[+] Last packet sent with the source address: "<< src_ipv6 << std::endl;
    
    // Notify the end of the Sender mode
    std::cout << "[+] Done!" << std::endl;
    break ;
  }

  // RECEIVER MODE SELECTED
  case 2 :
  {
    // Notify the beginning of StegoIPv6 Receiver
    std::cout << std::endl << "********* StegoIPv6 Receiver started **********" << std::endl << std::endl;

    // Variables to configure socket connection
    int sockfd, portNumber;			// socket and port

    // Buffer to store data from remote connection
    char buffer[256];
    memset(buffer, 0, sizeof(buffer));		// Set the buffer to "0"

    // sockaddr_in6 structures used to pass address information to the
    // socket function calls that require network address information
    struct sockaddr_in6 si_me, si_other;
    socklen_t slen = sizeof(struct sockaddr_in6);

    int n;		// Used when receiving incoming data from the socket

    // Buffers to store stego-sender IPv6 address and data
    char client_addr_ipv6[MAX_ADDRESS];
    char data[MAX_ADDRESS];
    memset(data, 0, sizeof(data));

    // String to store the data to be decrypted
    std::string finalAES = "";

    // Ask the port number where receiver is going to be listening on
    std::cout << "[+] Please, enter the port where listening incoming connection (1024 - 65535) :" << std::endl << "> ";
    std::cin >> portNumber;

    // Check if the port number is an integer
    if (!portNumber) {
      showError("[!] Error: The port number must be an integer. Please, try again.");
    }

    // Check if the port number is between 1024 and 65535 (is not a well-known port number)
    if (!((1024 <= portNumber) && (portNumber <= 65535))) {
      showError("[!] Error: The port number must between 1024 and 65535. Please, try again.");
    }

    std::cout << "[+] StegoIPv6 Receiver waiting for connection..." << std::endl;

    do {
      // Creation of a new raw socket
      sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
      if (sockfd < 0) {
        showError("ERROR opening socket");
      }

      // Setting to zero sockaddr_in6 structure used by the receiver
      bzero((char *) &si_me, sizeof(si_me));

      // sockaddr_in6 structure configuration used by the receiver
      si_me.sin6_family = AF_INET6;
      si_me.sin6_addr = in6addr_any;
      si_me.sin6_port = htons(portNumber);
      si_me.sin6_flowinfo = 0;

      // Binding the address to the socket so it can be refered
      if (bind(sockfd, (struct sockaddr *) &si_me, sizeof(si_me)) < 0) {
        showError("ERROR on binding");
      }

      // Receiving a message from the socket (stored in "buffer") and
      // the source IPv6 address of the incomming packet
      n = recvfrom(sockfd, buffer, 255, 0, (struct sockaddr *) &si_other, &slen);
      if (n < 0) {
        showError("ERROR reading from socket");
      }

      // Converting source IPv6 address from binary to text format
      inet_ntop(AF_INET6, &(si_other.sin6_addr),client_addr_ipv6, MAX_ADDRESS);

      // Parsing to string strData the source IPv6 address store previously in client_addr_ipv6
      strncpy(data, client_addr_ipv6, sizeof(client_addr_ipv6));
      std::string strData(data);

      // Checking if the source address is the final delimiter set in
      // the stego sender which allows us to get to know the end of the
      // packets transmition
      if (strData == "fe80::f:1001:1001:1001:1001") {
        break;
      }

      // Looking for the flag which tells us the beginning of the information
      // to be extracted
      ulong iFlag = strData.find("f:");
      strData = strData.substr(iFlag+2);

      // Variable to store the characters without colons
      std::string strStegano;

      // While there are colons in strData
      while (true) {
        // Look for next colon available
        unsigned long found = strData.find(":");

        // If there is no colon left, add final characters to finalAES
        // and break loop
        if (found == std::string::npos) {
          finalAES += strData;
          break;
        }

        // We set srtStegano with the left part of the colon. Normally,
        // strStegano will have four characters
        strStegano = strData.substr(0, found);

        // strData is set with the right part of the colon for next steps
        strData = strData.substr(found+1);

        // If the length of strStegano is less than four (due to the
        // automatic summarization of the IPv6 address fields) we add
        // some zeros to its left
        if (strStegano.size()<4) {
          strStegano.insert(strStegano.begin(),4-strStegano.size(),'0');
        }

        // Filling finalAES with each field of the IPv6 source address
        // without colons
        finalAES += strStegano;
      }

      // Closing the socket
      close(sockfd);

    } while (true);

    // Look for data delimiter "f" set by the stego sender to eliminate
    // the padding
    unsigned msgDelimiter = finalAES.find_last_of("f");

    // Extract the five characters of the Initialization Vector
    std::string varIV = finalAES.substr(msgDelimiter + 1);
    varIV = varIV.substr(0,5);
    std::string strIniVectRecv = generateRandomIV(varIV);

    // Store in finalAES the latest characters of the stego-message
    finalAES = finalAES.substr(0, msgDelimiter);

    // Show the decoy message
    std::cout << "[+] Decoy message : "<< buffer << std::endl;

    // Ask the password to decrypt the stego message
    std::string password = getpass("[+] Enter the password to decrypt the stego message : (16 characters max.)\n> ");
    if (password.size()>MAX_PASSWORD) {
      showError("[!] Error: Password can't be greater than 16 characters. Please, try again.");
    }

    // Decrypt the stego message
    std::string resultDescifrado = decrypt(finalAES, password, strIniVectRecv);

    // Show the stego message
    std::cout << "[!] SECRET MESSAGE FOUND : " << resultDescifrado << std::endl;
    break ;
  }

  default:
    std::cout << "[!] Incorrect mode! Please, try again." << std::endl;
  }

  return EXIT_SUCCESS;
}


/* *****	FUNCTIONS DEFINITION	***** */

// Function that implements the packet sending.
void sendStego(const std::string& interface, const std::string& source, const std::string& destiny, const uint16_t& portn, const char* strDecoy) {

  // Set the data with the decoy message
  Crafter::RawLayer raw_header(strDecoy);

  // Create an UDP header with the source and destination ports
  Crafter::UDP udp_header;
  udp_header.SetSrcPort(Crafter::RNG16());
  udp_header.SetDstPort(portn);

  // Create an IP header with the source and destination IPv6 addresses
  Crafter::IPv6 ip_header;
  ip_header.SetSourceIP(source);
  ip_header.SetDestinationIP(destiny);

  // Create a packet by encapsulating the different headers
  Crafter::Packet packet = ip_header / udp_header / raw_header;

  // Send the packet, this would fill the missing fields (checksum, lengths, etc)
  packet.Send(interface);
}


// Function that encrypt the stego message to be sent to the stego receiver.
std::string encrypt(const std::string& stegomessage, const std::string& strPass, const std::string& vector) {

  // Creating and setting up byte arrays Key and IV with the password
  // and initiation vector used by AES
  CryptoPP::byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ];
  CryptoPP::byte iv[ CryptoPP::AES::BLOCKSIZE ];

  ::memset( key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );
  ::memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );

  for (uint i = 0; i < strPass.size(); ++i) {
    key[i] = static_cast<CryptoPP::byte>(strPass[i]);
  }

  for (uint i = 0; i < vector.size(); ++i) {
    iv[i] = static_cast<CryptoPP::byte>(vector[i]);
  }

  // Encrypted Text
  std::string CipherText;

  // Encryptor
  CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption Encryptor( key, sizeof(key), iv);

  // Encryption
  CryptoPP::StringSource( stegomessage, true,
                          new CryptoPP::StreamTransformationFilter( Encryptor,
                                                                    new CryptoPP::StringSink( CipherText )));

  // Convert to hexadecimal the encrypted text
  std::string hexCipher = "";
  CryptoPP::StringSource(CipherText, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hexCipher)));

  return hexCipher;
}


// Function that validates the format of an IPv6 address.
bool validateIpv6Address(const std::string& ipAddress) {
  struct sockaddr_in6 addr;
  int result = inet_pton(AF_INET6, ipAddress.c_str(), &addr.sin6_addr);
  return result != 0;
}


// Function that generate an Initialization Vector with some randomness.
std::string generateRandomIV(const std::string& strRandom) {
  
  std::string strIV = initVect;
  // We change the value of the positions with zeros of the IV with the received characters
  unsigned int j = 3;
  for (unsigned int i = 0; i < 5; ++i) {
    strIV[j] = strRandom[i];
    j += 6;
  }
  return strIV;
}


// Function that shows possible errors while managing sockets.
void showError(const char *msg) {
  perror(msg);
  exit(EXIT_FAILURE);
}


// Function that decrypts the stego message sent by the stego sender.
std::string decrypt(const std::string& encText, const std::string& strPass, const std::string& vector) {

  // Hexadecimal decoding of the stego message sent in IPv6 source addresses
  std::string encrypted;
  CryptoPP::StringSource(encText, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(encrypted)));

  // Creating and setting up byte arrays Key and IV with the password
  // and initiation vector used by AES
  CryptoPP::byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ];
  CryptoPP::byte iv[ CryptoPP::AES::BLOCKSIZE ];

  ::memset( key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );
  ::memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );

  for (unsigned long i = 0; i < strPass.size(); i++) {
    key[i] = static_cast<CryptoPP::byte>(strPass[i]);
  }
    

  for (unsigned long i = 0; i < vector.size(); i++) {
    iv[i] = static_cast<CryptoPP::byte>(vector[i]);
  }

  // Decrypted Text
  std::string recovered;

  // Setting up the decryptor
  CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption Decryptor( key, sizeof(key), iv );

  // Stego message decryption
  CryptoPP::StringSource( encrypted, true,
                          new CryptoPP::StreamTransformationFilter( Decryptor,
                                                                    new CryptoPP::StringSink( recovered )));

  return recovered;
}

// Function that obtains the network interfaces available to send traffic.
std::vector<std::string> getNetworkInterfaces() {

  std::vector<std::string> vInterfaces;
  struct ifaddrs *ifaddr, *ifa;

  // Get a linked list of structures describing the network interfaces of the local system
  if (getifaddrs(&ifaddr) == -1) {
    showError("getifaddrs");
  }

  // Walk through the linked list 'ifaddr' maintaining head pointer so we can free list later
  for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
    // Only IPv6 interfaces (family AF_INET6 = Internet Protocols (TCP, UDP))
    if((ifa->ifa_addr != nullptr) && (ifa->ifa_addr->sa_family == AF_INET6)) {
      vInterfaces.push_back(ifa->ifa_name);
    }
  }

  freeifaddrs(ifaddr);
  return vInterfaces;
}

void printBanner() {
  // Clear screen
  std::cout << "\x1B[2J\x1B[H";

  std::cout << std::endl;
  std::cout << "*************************************" << std::endl;
  std::cout << "*************************************" << std::endl;
  std::cout << "****                             ****" << std::endl;
  std::cout << "****          STEGOIPV6          ****" << std::endl;
  std::cout << "****    Author: miguelkazabar    ****" << std::endl;
  std::cout << "****                             ****" << std::endl;
  std::cout << "*************************************" << std::endl;
  std::cout << "*************************************" << std::endl;
  std::cout << std::endl;
}