#include "../include/common.h"
#include "../include/dh_utils.h"
#include <arpa/inet.h>
#include <cstring>
#include <stdexcept>

static std::unordered_map<std::string, std::string> g_user_db = {
    {"client1", "password1"},
    {"client2", "password2"}};

bool check_credentials(const std::string &user, const std::string &pass)
{
    auto it = g_user_db.find(user);
    if (it == g_user_db.end())
        return false;
    return (it->second == pass);
}

// Holds ephemeral, per-connection info
struct ConnectionContext
{
    // Ephemeral DH used to get session_key
    DH *ephemeral_dh = nullptr;
    // 32-byte session key after handshake
    std::string session_key;
    // Whether the handshake and auth are complete
    bool handshake_complete = false;
    bool authenticated = false;
    // For the existing chat logic
    std::string client_id;
    bool has_client_id = false;
    // The IP/port once they do REGISTER
    std::string client_ip;
    int client_port = 0;
};

class Server
{
    int port;
    int server_fd;
    std::unordered_map<std::string, ClientInfo> clients;
    std::mutex clients_mutex;
    std::atomic<bool> running{true};

    // For storing ephemeral session keys, etc.  (socket -> context)
    std::unordered_map<int, ConnectionContext> connection_map;
    std::mutex conn_map_mutex;

    // The server's global DH parameters (generated once)
    DH *dh_params = nullptr;

public:
    Server(int port) : port(port), server_fd(-1)
    {
        dh_params = create_dh_params(2048);
    }

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

            // Create a new connection context
            {
                std::lock_guard<std::mutex> lk(conn_map_mutex);
                connection_map[client_socket] = ConnectionContext{};
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

    void send_encrypted_response(int socket, const std::string &plaintext, ConnectionContext &ctx)
    {
        try
        {
            std::string secure_msg = prepare_secure_message(plaintext, ctx.session_key);
            // Add the double-CRLF to mark message boundary
            send(socket, secure_msg.data(), secure_msg.size(), 0);
        }
        catch (const CryptoError &e)
        {
            log("Encryption failed: " + std::string(e.what()));
            throw;
        }
    }

    void handle_register(int socket, const std::unordered_map<std::string, std::string> &headers, ConnectionContext &ctx)
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        std::string client_id = headers.at("clientID");

        if (clients.find(client_id) != clients.end())
        {
            log("Registration failed - duplicate ID: " + client_id);
            std::string response = "ERROR\r\nmessage: Client ID already registered.\r\n\r\n";
            send_encrypted_response(socket, response, ctx);
            return;
        }

        ClientInfo info;
        info.ip = headers.at("IP");
        info.port = std::stoi(headers.at("Port"));
        info.available = true;

        clients[client_id] = info;

        ctx.client_id = client_id;
        ctx.has_client_id = true;
        ctx.client_ip = info.ip;
        ctx.client_port = info.port;

        log("Registered client: " + client_id + " (" + info.ip + ":" +
            std::to_string(info.port) + ")");

        // Create registration response with session key
        std::string response = "REGACK\r\n"
                               "clientID: " +
                               client_id + "\r\n"
                                           "IP: " +
                               info.ip + "\r\n"
                                         "Port: " +
                               std::to_string(info.port) + "\r\n\r\n";

        // Send encrypted response using server_key
        send_encrypted_response(socket, response, ctx);
    }

    void handle_unregister(int socket, const std::unordered_map<std::string, std::string> &headers, ConnectionContext &ctx)
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        std::string client_id = headers.at("clientID");

        if (clients.erase(client_id))
        {
            log("Unregistered client: " + client_id);

            std::string response = "UNREGACK\r\nclientID: " + client_id + "\r\n\r\n";
            send_encrypted_response(socket, response, ctx);
        }
    }

    void handle_bridge(int socket, const std::unordered_map<std::string, std::string> &headers, ConnectionContext &ctx)
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        std::string requester_id = headers.at("clientID");

        log("Bridge request from: " + requester_id);

        // Ensure the requester is marked as available before searching
        clients[requester_id].available = true;

        // Find first available peer that's not the requester
        for (auto &[peer_id, info] : clients)
        {
            if (peer_id != requester_id && info.available)
            {
                clients[requester_id].available = false;
                info.available = false;

                std::string response = "BRIDGEACK\r\nclientID: " + peer_id +
                                       "\r\nIP: " + info.ip + "\r\nPort: " +
                                       std::to_string(info.port) + "\r\n\r\n";

                send_encrypted_response(socket, response, ctx);
                log("Bridged " + requester_id + " with " + peer_id);
                return;
            }
        }

        log("No peers available for " + requester_id + " (waiting for peers)");
        send_encrypted_response(socket, "BRIDGEACK\r\nclientID:\r\nIP:\r\nPort:\r\n\r\n",
                                ctx);
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

        char buffer[4096];
        std::string accumulated_data;

        while (running)
        {
            ssize_t bytes_read = recv(socket, buffer, sizeof(buffer), 0);
            if (bytes_read <= 0)
            {
                log(std::string("Connection closed by ") + client_ip);
                break;
            }

            log("Received " + std::to_string(bytes_read) + " bytes of data");
            accumulated_data.append(buffer, bytes_read);

            // Process complete messages
            size_t pos;
            while ((pos = accumulated_data.find("\r\n\r\n")) != std::string::npos)
            {
                std::string message = accumulated_data.substr(0, pos);
                accumulated_data.erase(0, pos + 4);

                if (message.empty()) {
                    continue;
                }

                log("Processing message: " + message);

                try
                {
                    handle_incoming_message(socket, message);
                }
                catch (const CryptoError &e)
                {
                    log("Decryption failed: " + std::string(e.what()));
                    // send_encrypted_response(socket, "ERROR\r\nmessage: Invalid or tampered message\r\n\r\n", ctx);
                }
                catch (const std::exception &e)
                {
                    log("Error processing message: " + std::string(e.what()));
                }
            }
        }
        close(socket);
        std::lock_guard<std::mutex> lk(conn_map_mutex);
        connection_map.erase(socket);
    }

    void handle_incoming_message(int socket, const std::string &raw_msg)
    {
        std::lock_guard<std::mutex> lk(conn_map_mutex);
        auto &ctx = connection_map[socket];

        if (!ctx.handshake_complete)
        {
            // The handshake has not completed yet, so parse as plaintext
            parse_handshake_message(socket, raw_msg, ctx);
        }
        else
        {
            // We already have a session key, so decrypt
            std::string decrypted = process_secure_message(raw_msg, ctx.session_key);
            parse_encrypted_message(socket, decrypted, ctx);
        }
    }

    void parse_handshake_message(int socket, const std::string &raw_msg, ConnectionContext &ctx)
    {
        // Typically you'd parse lines. For example:
        // "DH_START\r\nPublic: <base64>\r\n\r\n"
        // or after that step: "AUTH\r\nusername: X\r\npassword: Y\r\n\r\n" (encrypted if you prefer).

        // Let’s split by newlines:
        std::vector<std::string> lines = split(raw_msg, '\n');
        if (lines.empty())
            return;

        std::string command = trim(lines[0]);
        if (command == "DH_START")
        {
            // Next line might be "Public: <base64>"
            if (lines.size() < 2)
                return;
            auto pub_line = split(lines[1], ':');
            if (pub_line.size() < 2)
                return;
            std::string client_pub_b64 = trim(pub_line[1]);

            // 1) Generate ephemeral DH for server
            auto dh_keypair = generate_dh_keypair(dh_params);
            ctx.ephemeral_dh = dh_keypair.dh; // store in context (we'll free later if needed)

            // 2) Compute shared secret from client's public
            std::string shared_secret = compute_dh_shared_secret(ctx.ephemeral_dh, client_pub_b64);
            ctx.session_key = shared_secret; // 32-byte key
            // We do NOT mark handshake_complete yet,
            // because we still want an AUTH step.

            // 3) Send "DH_RESPONSE" with the server's ephemeral public key
            std::string response = "DH_RESPONSE\r\nPublic: " + dh_keypair.public_key + "\r\n\r\n";
            send(socket, response.c_str(), response.size(), 0);
        }
        else if (command == "AUTH")
        {
            // If we do "AUTH" in plaintext, we parse lines[1], lines[2], etc.
            // But it’s recommended to do AUTH encrypted under the ephemeral key.
            // For simplicity, let's assume it's still plaintext here
            // (so we do not do GCM yet).
            // If you prefer encryption, you'd actually do:
            //   std::string decrypted = process_secure_message(raw_msg, ctx.session_key);
            //   parse that for user/pass
            // Then you'd call parse_handshake_message again with that plaintext.

            if (lines.size() < 3)
                return;
            auto user_line = split(lines[1], ':');
            auto pass_line = split(lines[2], ':');
            if (user_line.size() < 2 || pass_line.size() < 2)
                return;

            std::string user = trim(user_line[1]);
            std::string pass = trim(pass_line[1]);

            if (check_credentials(user, pass))
            {
                ctx.authenticated = true;
                ctx.handshake_complete = true;
                // Send success
                std::string resp = "AUTH_OK\r\n\r\n";
                // Possibly encrypt if you want:
                //   resp = prepare_secure_message(resp, ctx.session_key);
                send(socket, resp.c_str(), resp.size(), 0);
            }
            else
            {
                std::string resp = "AUTH_FAIL\r\n\r\n";
                send(socket, resp.c_str(), resp.size(), 0);
                // Optionally close or let them retry
            }
        }
        else
        {
            // Unknown handshake command
            std::string resp = "ERROR\r\nUnknown handshake command\r\n\r\n";
            send(socket, resp.c_str(), resp.size(), 0);
        }
    }

    void parse_encrypted_message(int socket, const std::string &plaintext, ConnectionContext &ctx)
    {
        // Now we handle your existing REGISTER/BRIDGE logic,
        // but it’s all inside the decrypted 'plaintext'.

        std::vector<std::string> lines = split(plaintext, '\n');
        if (lines.empty())
            return;

        std::string command = trim(lines[0]);
        auto headers = parse_headers(plaintext);

        if (command == "REGISTER")
        {
            handle_register(socket, headers, ctx);
        }
        else if (command == "BRIDGE")
        {
            handle_bridge(socket, headers, ctx);
        }
        else if (command == "UNREGISTER")
        {
            handle_unregister(socket, headers, ctx);
        }
        else
        {
            send_encrypted_response(socket, "ERROR\r\nmessage: Invalid request.\r\n\r\n", ctx);
        }
    }
};

int main(int argc, char *argv[])
{
    int port = 65432;
    if (argc > 1)
    {
        int specified_port = std::atoi(argv[1]);
        if (specified_port <= 0 || specified_port > 65535)
        {
            std::cerr << "Invalid port number. Using default port " << port << std::endl;
        }
        else
        {
            port = specified_port;
        }
    }

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