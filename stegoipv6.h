#ifndef STEGOIPV6_H_
#define STEGOIPV6_H_

#include <iostream>
#include <string>
#include <stdio.h>

void printBanner();
std::string generateRandomIV(const std::string& strRandom);
[[ noreturn ]] void showError(const char *msg);

// Sender functions declaration
std::string encrypt(const std::string& stegomessage, const std::string& strPass, const std::string& vector);
void sendStego(const std::string& interface, const std::string& source, const std::string& destiny, const uint16_t& portn, const char* strDecoy);
bool validateIpv6Address(const std::string& ipAddress);
std::vector<std::string> getNetworkInterfaces();

// Receiver functions declaration
std::string decrypt(const std::string& encText, const std::string& strPass, const std::string& vector);

#endif /* STEGOIPV6_H_ */