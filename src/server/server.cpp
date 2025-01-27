#include "../include/common.h"
#include <arpa/inet.h>
#include <cstring>
#include <stdexcept>

class Server
{
    int port;
    int server_fd;
    std::unordered_map<std::string, ClientInfo> clients;
    std::mutex clients_mutex;
    std::atomic<bool> running{true};

public:
    Server(int port) : port(port), server_fd(-1) {}

    void start()
    {
        struct sockaddr_in address;
        int opt = 1;

        if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
        {
            throw std::runtime_error("socket creation failed");
        }

        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
        {
            throw std::runtime_error("setsockopt failed");
        }

        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port);

        if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
        {
            throw std::runtime_error("bind failed");
        }

        if (listen(server_fd, 3) < 0)
        {
            throw std::runtime_error("listen failed");
        }

        std::cout << "Server listening on port " << port << std::endl;

        while (running)
        {
            int client_socket;
            struct sockaddr_in client_addr;
            socklen_t addrlen = sizeof(client_addr);

            if ((client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen)) < 0)
            {
                if (running)
                    std::cerr << "accept failed" << std::endl;
                continue;
            }

            std::thread([this, client_socket]()
                        { handle_client(client_socket); })
                .detach();
        }
    }

    void stop()
    {
        running = false;
        close(server_fd);
    }

private:
    void log(const std::string &message)
    {
        auto now = std::chrono::system_clock::now();
        std::time_t time = std::chrono::system_clock::to_time_t(now);
        std::cout << "[SERVER] " << std::ctime(&time) << "\t" << message << std::endl;
    }

    void handle_register(int socket, const std::unordered_map<std::string, std::string> &headers)
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        std::string client_id = headers.at("clientID");

        if (clients.find(client_id) != clients.end())
        {
            log("Registration failed - duplicate ID: " + client_id);
            std::string response = "ERROR\r\nmessage: Client ID already registered.\r\n\r\n";
            send(socket, response.c_str(), response.size(), 0);
            return;
        }

        ClientInfo info;
        info.ip = headers.at("IP");
        info.port = std::stoi(headers.at("Port"));
        clients[client_id] = info;

        log("Registered client: " + client_id + " (" + info.ip + ":" +
            std::to_string(info.port) + ")");
        std::string response = "REGACK\r\nclientID: " + client_id + "\r\nIP: " + info.ip +
                               "\r\nPort: " + std::to_string(info.port) + "\r\n\r\n";
        send(socket, response.c_str(), response.size(), 0);
    }

    void handle_unregister(int socket, const std::unordered_map<std::string, std::string> &headers)
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        std::string client_id = headers.at("clientID");

        if (clients.erase(client_id))
        {
            log("Unregistered client: " + client_id);
        }
    }

    void handle_bridge(int socket, const std::unordered_map<std::string, std::string> &headers)
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        std::string requester_id = headers.at("clientID");
        log("Bridge request from: " + requester_id);

        // Find first available peer that's not the requester
        for (auto &[peer_id, info] : clients)
        {
            if (peer_id != requester_id && info.available)
            {
                // Mark both as temporarily unavailable
                clients[requester_id].available = false;
                clients[peer_id].available = false;

                std::string response = "BRIDGEACK\r\nclientID: " + peer_id +
                                       "\r\nIP: " + info.ip + "\r\nPort: " +
                                       std::to_string(info.port) + "\r\n\r\n";
                send(socket, response.c_str(), response.size(), 0);
                log("Bridged " + requester_id + " with " + peer_id);
                return;
            }
        }

        log("No peers available for " + requester_id + " (waiting for peers)");
        std::string response = "BRIDGEACK\r\nclientID:\r\nIP:\r\nPort:\r\n\r\n";
        send(socket, response.c_str(), response.size(), 0);
    }

    void handle_client(int socket)
    {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        getpeername(socket, (struct sockaddr *)&client_addr, &addr_len);
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

        log(std::string("New connection from ") + client_ip + ":" +
            std::to_string(ntohs(client_addr.sin_port)));

        char buffer[1024];
        while (true)
        {
            ssize_t bytes_read = recv(socket, buffer, sizeof(buffer), 0);
            if (bytes_read <= 0)
            {
                log(std::string("Connection closed by ") + client_ip);
                break;
            }

            std::string data(buffer, bytes_read);
            log("Request received: " + data);

            // Process request but keep connection open
            std::vector<std::string> parts = split(data, '\r\n');
            std::string command = trim(parts[0]); // Add trim to remove \r if present

            auto headers = parse_headers(data);

            if (command.find("REGISTER") == 0)
            {
                handle_register(socket, headers);
            }
            else if (command.find("BRIDGE") == 0)
            {
                handle_bridge(socket, headers);
            }
            else if (command.find("UNREGISTER") == 0) {
                handle_unregister(socket, headers);
            }
            else
            {
                std::string response = "ERROR\r\nmessage: Invalid request type.\r\n\r\n";
                send(socket, response.c_str(), response.size(), 0);
            }
        }
        close(socket);
    }
};

int main(int argc, char *argv[])
{
    int port = 65432;
    if (argc > 1)
        port = atoi(argv[1]);

    try
    {
        Server server(port);
        server.start();
    }
    catch (const std::exception &e)
    {
        std::cerr << "Server error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}