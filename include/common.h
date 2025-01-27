#ifndef COMMON_H
#define COMMON_H

#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <thread>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <termios.h>
#include <sys/ioctl.h>


struct ClientInfo {
    std::string ip;
    int port;
    bool available = true;
};

// Message parsing utilities
std::unordered_map<std::string, std::string> parse_headers(const std::string& data);
std::vector<std::string> split(const std::string& s, char delimiter);
std::string trim(const std::string& str);

#endif