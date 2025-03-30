#include "../include/common.h"
#include "../include/crypto.h"
#include "../include/dh_utils.h"

#include <arpa/inet.h>
#include <atomic>
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#include <mutex>
#include <iostream>
#include <iomanip>
#include <thread>
#include <unordered_map>

/**
 * Utility function that hides password input on terminal.
 */
static std::string prompt_hidden(const std::string &prompt)
{
    std::cout << prompt;
    fflush(stdout);

    // Turn off echo
    termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    std::string input;
    std::getline(std::cin, input);

    // Restore echo
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << std::endl;

    return input;
}

/**
 * Optionally, a blocking read that waits until "\r\n\r\n"
 * to help parse handshake messages.
 */
static std::string blocking_recv_until_double_crlf(int sock)
{
    std::string data;
    char buf[4096];
    while (true)
    {
        ssize_t r = recv(sock, buf, sizeof(buf), 0);
        if (r <= 0)
        {
            throw std::runtime_error("Connection closed during handshake");
        }
        data.append(buf, r);
        size_t pos = data.find("\r\n\r\n");
        if (pos != std::string::npos)
        {
            return data.substr(0, pos + 4);
        }
    }
}

void client_print_status(const std::string &message)
{
    std::cout << "[CLIENT] " << message << std::endl;
}

/**
 * Utility to get local IP (if not localhost).
 */
std::string get_local_ip()
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in google_dns{};
    google_dns.sin_family = AF_INET;
    google_dns.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &google_dns.sin_addr);

    connect(sock, (const sockaddr *)&google_dns, sizeof(google_dns));

    sockaddr_in local_addr{};
    socklen_t addr_len = sizeof(local_addr);
    getsockname(sock, (sockaddr *)&local_addr, &addr_len);
    char buffer[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &local_addr.sin_addr, buffer, INET_ADDRSTRLEN);
    close(sock);
    return buffer;
}

class Client
{
private:
    int server_socket = -1;
    std::string client_id;
    int client_port;
    std::string server_ip;
    int server_port;
    std::string client_ip;

    // For bridging logic
    std::atomic<bool> is_first_client{false};
    int peer_socket = -1;
    std::atomic<bool> running{true};
    std::unordered_map<std::string, std::string> peer_info;

    // For chat and bridging states
    std::atomic<bool> registered{false};
    std::atomic<bool> bridged{false};

    // For console/graphics
    std::mutex console_mtx;
    std::vector<std::pair<std::string, std::string>> message_history;
    std::mutex history_mtx;
    std::atomic<bool> redraw_needed{false};
    std::atomic<bool> redraw_needs_update{false};

    // **Ephemeral session key** derived via DH handshake
    std::string session_key;
    std::atomic<bool> has_session_key{false};

    // Whether we encrypt messages to peer
    bool encryption_enabled = true;

    // Credentials for basic auth
    std::string username_;
    std::string password_;

public:
    /**
     * The constructor now also receives username/password.
     * We'll do:
     *   1) connect_to_server()
     *   2) Diffie–Hellman handshake
     *   3) Basic AUTH
     * Then the rest of the logic proceeds in run().
     */
    Client(const std::string &id, int port, const std::string &server_addr,
           const std::string &username, const std::string &password)
        : client_id(id), client_port(port), username_(username), password_(password)
    {
        // Parse server address: "IP:PORT"
        size_t colon = server_addr.find(':');
        if (colon == std::string::npos)
        {
            throw std::runtime_error("Invalid server address (use IP:PORT)");
        }
        server_ip = server_addr.substr(0, colon);
        server_port = std::stoi(server_addr.substr(colon + 1));

        if (client_port == server_port)
        {
            throw std::runtime_error("Client port cannot match server port");
        }

        // Determine local IP if not 127.0.0.1
        client_ip = (server_ip == "127.0.0.1") ? "127.0.0.1" : get_local_ip();

        // 1) Connect to server
        connect_to_server();
        client_print_status("Connected to server");

        // 2) Perform ephemeral Diffie–Hellman handshake
        perform_dh_handshake();

        // 3) Perform basic username/password auth
        //    (plaintext for demonstration).
        perform_auth();
    }

    /**
     * Kick off the rest of the client flow:
     *   - register_client()
     *   - try bridging
     *   - enter chat mode
     */
    void run()
    {
        // 1) REGISTER
        register_client();

        // 2) Attempt bridging (like your original code)
        bridge_with_retries();

        // 3) Start the interactive chat UI
        //    (with bridging to a peer if found)
        chat_mode();
    }

    ~Client()
    {
        cleanup();
    }

private:
    //------------------------------------------------------------------------------
    // Setup / DH / Auth
    //------------------------------------------------------------------------------

    void connect_to_server()
    {
        if (server_socket != -1)
            return;

        server_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (server_socket < 0)
        {
            throw std::runtime_error("socket creation failed");
        }

        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(server_port);
        inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr);

        if (connect(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        {
            close(server_socket);
            server_socket = -1;
            throw std::runtime_error("connection to server failed");
        }
    }

    /**
     * Perform ephemeral Diffie–Hellman handshake with the server.
     * We'll:
     *   - generate DH params & ephemeral key
     *   - send "DH_START" with our public key
     *   - get "DH_RESPONSE" with server public key
     *   - compute session_key
     */
    void perform_dh_handshake()
    {
        // Generate ephemeral DH.
        // Could store or reuse known params, but we generate fresh for example:
        DH *params = create_dh_params(2048); // can be slow
        auto dh_keypair = generate_dh_keypair(params);
        DH_free(params); // not needed after ephemeral is created

        // 1) Send "DH_START\r\nPublic: <b64>\r\n\r\n"
        {
            std::string msg = "DH_START\r\nPublic: " + dh_keypair.public_key + "\r\n\r\n";
            send(server_socket, msg.c_str(), msg.size(), 0);
        }

        // 2) Receive "DH_RESPONSE\r\nPublic: <b64>\r\n\r\n"
        std::string resp = blocking_recv_until_double_crlf(server_socket);
        auto lines = split(resp, '\n');
        if (lines.empty() || trim(lines[0]) != "DH_RESPONSE")
        {
            throw std::runtime_error("Invalid DH_RESPONSE from server");
        }
        auto pub_line = split(lines[1], ':');
        if (pub_line.size() < 2)
        {
            throw std::runtime_error("Missing server public key line");
        }
        std::string server_pub_b64 = trim(pub_line[1]);

        // 3) Compute the shared secret => session key
        session_key = compute_dh_shared_secret(dh_keypair.dh, server_pub_b64);
        has_session_key = true;

        // Cleanup ephemeral
        DH_free(dh_keypair.dh);

        client_print_status("DH handshake complete; ephemeral session key established");
    }

    /**
     * Perform a basic username/password auth step.
     * We send "AUTH\r\nusername: X\r\npassword: Y\r\n\r\n" in plaintext
     * to match the example server code. If your server expects it encrypted,
     * you'd just call `prepare_secure_message(...)` with `session_key`
     * before sending.
     */
    void perform_auth()
    {
        std::string auth_msg = "AUTH\r\nusername: " + username_ +
                               "\r\npassword: " + password_ + "\r\n\r\n";

        send(server_socket, auth_msg.c_str(), auth_msg.size(), 0);

        // read response
        std::string resp = blocking_recv_until_double_crlf(server_socket);
        if (trim(resp) == "AUTH_OK")
        {
            client_print_status("Authentication succeeded");
        }
        else
        {
            client_print_status("Authentication failed. Server says:\n" + resp);
            throw std::runtime_error("Auth failure");
        }
    }

    //------------------------------------------------------------------------------
    // Registration, bridging, normal chat
    //------------------------------------------------------------------------------

    /**
     * Send "REGISTER\r\nclientID: ...\r\nIP: ...\r\nPort: ...\r\n\r\n"
     * **encrypted** with session_key.
     */
    void register_client()
    {
        std::string message = "REGISTER\r\n"
                              "clientID: " +
                              client_id + "\r\n"
                                          "IP: " +
                              client_ip + "\r\n"
                                          "Port: " +
                              std::to_string(client_port) + "\r\n\r\n";

        std::string response = send_request(message);
        process_registration_response(response);
    }

    /**
     * Called after sending REGISTER. Checks for "REGACK" or "ERROR"
     */
    void process_registration_response(const std::string &response)
    {
        auto headers = parse_headers(response);
        std::vector<std::string> lines = split(response, '\r');
        if (lines.empty())
            return;

        std::string response_type = trim(lines[0]);

        if (response_type == "REGACK")
        {
            registered = true;
            client_print_status("Successfully registered with server");
        }
        else if (response_type == "ERROR")
        {
            throw std::runtime_error("Registration failed: " + headers["message"]);
        }
    }

    /**
     * We attempt bridging multiple times.
     * Each "BRIDGE" request is also encrypted with session_key.
     */
    void bridge_with_retries()
    {
        const int max_attempts = 5;
        int attempts = 0;

        while (running && attempts < max_attempts)
        {
            std::string message = "BRIDGE\r\nclientID: " + client_id + "\r\n\r\n";
            std::string response = send_request(message);
            auto headers = parse_headers(response);

            if (headers.find("clientID") != headers.end() && !headers["clientID"].empty())
            {
                peer_info = headers;
                start_chat(); // we have a peer
                return;
            }

            {
                std::lock_guard<std::mutex> lock(console_mtx);
                std::cout << "Searching for peers... ("
                          << (attempts + 1) << "/" << max_attempts << ")\n";
            }

            std::this_thread::sleep_for(std::chrono::seconds(2));
            attempts++;
        }

        if (peer_info.empty())
        {
            std::lock_guard<std::mutex> lock(console_mtx);
            std::cout << "Failed to find peer after " << attempts << " attempts\n";
        }
    }

    //------------------------------------------------------------------------------
    // Chat Interface
    //------------------------------------------------------------------------------

    /**
     * Start chat with the discovered peer (or become a listener if no peer found).
     */
    void start_chat()
    {
        client_print_status("Found a peer: " + peer_info["clientID"] +
                            " (" + peer_info["IP"] + ":" + peer_info["Port"] + ")");
        client_print_status("Attempting to connect to peer...");

        // Attempt to connect to peer
        peer_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (peer_socket < 0)
        {
            client_print_status("Failed to create peer socket");
            return;
        }

        sockaddr_in peer_addr{};
        peer_addr.sin_family = AF_INET;
        peer_addr.sin_port = htons(std::stoi(peer_info["Port"]));
        inet_pton(AF_INET, peer_info["IP"].c_str(), &peer_addr.sin_addr);

        if (connect(peer_socket, (struct sockaddr *)&peer_addr, sizeof(peer_addr)) == 0)
        {
            client_print_status("Connected to peer. Starting chat mode.");
            chat_mode();
        }
        else
        {
            client_print_status("Failed to connect to peer. Falling back to listen mode.");
            close(peer_socket);
            peer_socket = -1;
            enter_wait_mode();
        }
    }

    /**
     * If no peer was available, listen on client_port for a peer to connect to us.
     */
    void enter_wait_mode()
    {
        client_print_status("Entering LISTEN MODE on port " + std::to_string(client_port));
        is_first_client = true;

        int listen_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_socket < 0)
        {
            throw std::runtime_error("socket creation failed");
        }

        int opt = 1;
        setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(client_port);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(listen_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        {
            close(listen_socket);
            throw std::runtime_error("bind failed - port may be in use");
        }

        listen(listen_socket, 1);
        client_print_status("Listening for incoming peer connections...");

        sockaddr_in peer_addr;
        socklen_t addr_len = sizeof(peer_addr);
        peer_socket = accept(listen_socket, (struct sockaddr *)&peer_addr, &addr_len);
        close(listen_socket);

        if (peer_socket < 0)
        {
            throw std::runtime_error("accept failed");
        }

        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer_addr.sin_addr, buf, INET_ADDRSTRLEN);
        client_print_status(std::string("Peer connected from ") + buf + ":" + std::to_string(ntohs(peer_addr.sin_port)));

        // Now we do the same chat mode
        chat_mode();
    }

    /**
     * Your existing interactive chat method, which spawns threads
     * to read from peer and read from console, etc.
     */
    void chat_mode()
    {
        // Clear screen initially
        std::cout << "\033[2J\033[H";

        // Start interface threads
        std::thread input_manager([this]()
                                  { input_line_manager(); });
        std::thread read_thread([this]()
                                { message_receiver(); });

        // Input handling loop
        std::string input;
        while (running)
        {
            char c;
            if (read(STDIN_FILENO, &c, 1) == 1)
            {
                {
                    std::lock_guard<std::mutex> lock(console_mtx);
                    if (c == '\n')
                    { // Enter pressed
                        if (!input.empty())
                        {
                            if (input == "/quit")
                            {
                                send_quit();
                                break;
                            }

                            {
                                std::lock_guard<std::mutex> lock(history_mtx);
                                message_history.emplace_back("You", input);
                            }
                            send_to_peer(input);
                            input.clear();
                            redraw_needed = true;
                        }
                    }
                    else if (c == 127)
                    { // Backspace
                        if (!input.empty())
                        {
                            input.pop_back();
                            redraw_needs_update = true;
                        }
                    }
                    else if (isprint(c))
                    {
                        input += c;
                        redraw_needs_update = true;
                    }
                }

                // Handle redraw
                if (redraw_needed)
                {
                    redraw_interface(input);
                    redraw_needed = false;
                }
                if (redraw_needs_update)
                {
                    redraw_input_line(input);
                    redraw_needs_update = false;
                }
            }
        }

        running = false;
        read_thread.join();
        input_manager.join();
        cleanup();
    }

    /**
     * Thread that continuously reads from peer_socket
     * and appends messages to chat.
     */
    void message_receiver()
    {
        char buffer[4096];
        std::string accumulated_data;

        while (running)
        {
            ssize_t bytes_read = recv(peer_socket, buffer, sizeof(buffer), 0);
            if (bytes_read <= 0)
            {
                std::lock_guard<std::mutex> lock(console_mtx);
                std::cout << "\nPeer disconnected\n";
                running = false;
                break;
            }

            accumulated_data.append(buffer, bytes_read);

            // Process complete messages delimited by "\r\n"
            size_t pos;
            while ((pos = accumulated_data.find("\r\n")) != std::string::npos)
            {
                std::string message = accumulated_data.substr(0, pos);
                accumulated_data.erase(0, pos + 2);

                try
                {
                    std::lock_guard<std::mutex> lock(history_mtx);
                    if (encryption_enabled)
                    {
                        // Decrypt with ephemeral session key
                        std::string plaintext = process_secure_message(message, session_key);
                        message_history.emplace_back("Peer", plaintext);
                    }
                    else
                    {
                        message_history.emplace_back("Peer", message);
                    }
                    redraw_needed = true;
                }
                catch (const CryptoError &e)
                {
                    client_print_status("Decryption failed: " + std::string(e.what()));
                }
            }
        }
    }

    /**
     * Thread that updates the input line.
     * In your code, it’s an empty loop that checks flags.
     * We'll preserve it.
     */
    void input_line_manager()
    {
        while (running)
        {
            if (redraw_needs_update)
            {
                redraw_input_line("");
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
    }

    /**
     * Send a /quit to peer, then cleanup.
     */
    void send_quit()
    {
        if (peer_socket != -1)
        {
            send_to_peer("/quit");
        }
        cleanup();
    }

    /**
     * Send a message to the peer_socket, encrypted if enabled.
     */
    void send_to_peer(const std::string &message)
    {
        if (peer_socket == -1)
        {
            client_print_status("No active peer connection");
            return;
        }

        try
        {
            if (encryption_enabled)
            {
                std::string secure_message = prepare_secure_message(message, session_key);
                std::string framed_message = secure_message + "\r\n";
                if (send(peer_socket, framed_message.c_str(), framed_message.size(), 0) < 0)
                {
                    client_print_status("Failed to send encrypted message: " + std::string(strerror(errno)));
                    cleanup();
                }
            }
            else
            {
                std::string framed_message = message + "\r\n";
                if (send(peer_socket, framed_message.c_str(), framed_message.size(), 0) < 0)
                {
                    client_print_status("Failed to send message: " + std::string(strerror(errno)));
                }
            }
        }
        catch (const CryptoError &e)
        {
            client_print_status("Encryption failed: " + std::string(e.what()));
        }
    }

    /**
     * General function to send a request to the server
     * (REGISTER, BRIDGE, UNREGISTER, etc.) encrypted with ephemeral session_key,
     * then read/decrypt the response.
     */
    std::string send_request(const std::string &message)
    {
        try
        {
            connect_to_server();

            std::string secure_message = prepare_secure_message(message, session_key);

            if (send(server_socket, secure_message.c_str(), secure_message.size(), 0) < 0)
            {
                throw std::runtime_error("send failed");
            }

            // read response
            std::string raw_enc = blocking_recv_until_double_crlf(server_socket);
            // decrypt
            std::string decrypted = process_secure_message(raw_enc, session_key);
            return decrypted;
        }
        catch (const std::exception &e)
        {
            client_print_status("Error in send_request: " + std::string(e.what()));
            cleanup();
            throw;
        }
    }

    //------------------------------------------------------------------------------
    // UI/Console Helpers
    //------------------------------------------------------------------------------

    void redraw_interface(const std::string &current_input)
    {
        std::lock_guard<std::mutex> lock(console_mtx);
        std::cout << "\033[s"; // Save cursor position

        // Clear only the message area
        std::cout << "\033[1;1H\033[J"; // Clear from cursor to end of screen

        // Print header
        std::cout << "=== CHAT ACTIVE (type /quit to exit) ===\n";

        // Print message history
        for (const auto &[sender, msg] : message_history)
        {
            auto now = std::chrono::system_clock::now();
            std::time_t time = std::chrono::system_clock::to_time_t(now);
            std::cout << std::put_time(std::localtime(&time), "%H:%M:%S") << " "
                      << std::left << std::setw(12) << (sender + ":")
                      << msg << "\n";
        }

        std::cout << "\033[u"; // Restore cursor position
        std::cout << "You> " << current_input << std::flush;
    }

    void redraw_input_line(const std::string &current_input)
    {
        std::lock_guard<std::mutex> lock(console_mtx);
        std::cout << "\033[s";    // Save cursor position
        std::cout << "\033[1;1H"; // Move to top-left
        std::cout << "\033[2K";   // Clear line
        std::cout << "You> " << current_input;
        std::cout << "\033[u" << std::flush; // Restore cursor
    }

    //------------------------------------------------------------------------------
    // Cleanup
    //------------------------------------------------------------------------------

    void cleanup()
    {
        if (server_socket != -1)
        {
            // Optionally notify server we're disconnecting
            std::string message = "UNREGISTER\r\n"
                                  "clientID: " +
                                  client_id + "\r\n\r\n";
            try
            {
                std::string secure_message = prepare_secure_message(message, session_key);
                secure_message += "\r\n\r\n";
                send(server_socket, secure_message.c_str(), secure_message.size(), 0);
            }
            catch (...)
            {
                // Ignore
            }
            close(server_socket);
            server_socket = -1;
        }
        if (peer_socket != -1)
        {
            close(peer_socket);
            peer_socket = -1;
        }
        running = false;
        client_print_status("Client terminated");
    }
};

/**
 * Main: parse command line, prompt for credentials, run the client
 */
int main(int argc, char *argv[])
{
    if (argc < 4)
    {
        std::cerr << "Usage: " << argv[0] << " --id CLIENT_ID --port CLIENT_PORT --server SERVER_IP:PORT\n";
        return 1;
    }

    std::string id, server_addr;
    int port = 0;

    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "--id" && i + 1 < argc)
            id = argv[++i];
        else if (arg == "--port" && i + 1 < argc)
            port = std::stoi(argv[++i]);
        else if (arg == "--server" && i + 1 < argc)
            server_addr = argv[++i];
    }

    if (id.empty() || port == 0 || server_addr.empty())
    {
        std::cerr << "Invalid arguments" << std::endl;
        return 1;
    }

    // Prompt for username/password
    std::cout << "Username: ";
    std::string username;
    std::getline(std::cin, username);
    std::string password = prompt_hidden("Password: ");

    try
    {
        Client client(id, port, server_addr, username, password);
        client_print_status("Client started (ID: " + id + ")");
        client_print_status("Automatic commands:");
        client_print_status("  /quit     - Exit program");
        client_print_status("Type messages directly to chat");

        // Kick off the rest of the logic
        client.run();
    }
    catch (const std::exception &e)
    {
        std::cerr << "Client error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
