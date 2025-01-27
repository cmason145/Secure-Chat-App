#include "../include/common.h"

std::unordered_map<std::string, std::string> parse_headers(const std::string& data) {
    std::unordered_map<std::string, std::string> headers;
    std::vector<std::string> lines = split(data, '\n');
    
    for (const auto& line : lines) {
        std::string trimmed = trim(line);
        if (trimmed.empty()) continue;
        
        size_t pos = trimmed.find(':');
        if (pos != std::string::npos) {
            std::string key = trim(trimmed.substr(0, pos));
            std::string value = trim(trimmed.substr(pos+1));
            headers[key] = value;
        }
    }
    return headers;
}

std::vector<std::string> split(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        if (!token.empty()) {  // Skip empty tokens
            tokens.push_back(trim(token));
        }
    }
    return tokens;
}

std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}