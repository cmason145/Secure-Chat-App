#include "../include/common.h"
#include <arpa/inet.h>
#include <atomic>
#include <signal.h>

void client_print_status(const std::string &message)
{
    std::cout << "[CLIENT] " << message << std::endl;
}

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
    int server_socket = -1;
    std::string client_id;
    int client_port;
    std::string server_ip;
    int server_port;
    std::string client_ip;
    std::atomic<bool> is_first_client{false};
    int peer_socket = -1;
    std::atomic<bool> running{true};
    std::unordered_map<std::string, std::string> peer_info;
    std::atomic<bool> registered{false};
    std::atomic<bool> bridged{false};
    std::mutex console_mtx;
    std::vector<std::pair<std::string, std::string>> message_history;
    std::mutex history_mtx;
    std::atomic<bool> redraw_needed{false};
    std::atomic<bool> redraw_needs_update{false};

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

        internal_print("Connected to server");
    }

    void disconnect_server()
    {
        if (server_socket != -1)
        {
            close(server_socket);
            server_socket = -1;
        }
    }

public:
    Client(const std::string &id, int port, const std::string &server_addr)
        : client_id(id), client_port(port)
    {
        size_t colon = server_addr.find(':');
        server_ip = server_addr.substr(0, colon);
        server_port = std::stoi(server_addr.substr(colon + 1));

        if (client_port == server_port)
        {
            throw std::runtime_error("Client port cannot match server port");
        }

        // Get local IP
        client_ip = (server_ip == "127.0.0.1") ? "127.0.0.1" : get_local_ip();

        try
        {
            register_client();
        }
        catch (const std::exception &e)
        {
            std::cerr << "Registration failed: " << e.what() << std::endl;
            throw;
        }
    }

    void run()
    {
        signal(SIGINT, [](int) {});

        try
        {
            // Auto-register and bridge
            register_client();
            bridge_with_retries();

            // Configure terminal
            struct termios original_settings;
            tcgetattr(STDIN_FILENO, &original_settings);

            struct termios raw_settings = original_settings;
            raw_settings.c_lflag &= ~(ICANON | ECHO);
            tcsetattr(STDIN_FILENO, TCSANOW, &raw_settings);

            // Start chat interface
            chat_mode();

            // Restore terminal settings
            tcsetattr(STDIN_FILENO, TCSANOW, &original_settings);
        }
        catch (const std::exception &e)
        {
            std::cerr << "Fatal error: " << e.what() << std::endl;
            cleanup();
        }
    }

    ~Client()
    {
        disconnect_server();
    }

private:
    void internal_print(const std::string &message)
    {
        client_print_status(message);
    }

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
        std::cout << "\033[1;1H"; // Move to bottom of history
        std::cout << "\033[2K";   // Clear line
        std::cout << "You> " << current_input;
        std::cout << "\033[u" << std::flush; // Restore cursor
    }

    void display_chat_message(const std::string &sender, const std::string &message)
    {
        {
            std::lock_guard<std::mutex> lock(history_mtx);
            message_history.emplace_back(sender, message);
        }
        redraw_needed = true;
    }

    void message_receiver()
    {
        char buffer[1024];
        while (running)
        {
            ssize_t bytes_read = recv(peer_socket, buffer, sizeof(buffer), 0);
            if (bytes_read <= 0)
            {
                {
                    std::lock_guard<std::mutex> lock(console_mtx);
                    std::cout << "\nPeer disconnected\n";
                }
                running = false;
                break;
            }

            std::string received(buffer, bytes_read);
            size_t pos;
            while ((pos = received.find("\r\n")) != std::string::npos)
            {
                std::string message = received.substr(0, pos);
                received.erase(0, pos + 2);

                {
                    std::lock_guard<std::mutex> lock(history_mtx);
                    message_history.emplace_back("Peer", message);
                }
                redraw_needed = true;
            }
        }
    }

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

    void bridge_with_retries()
    {
        const int max_attempts = 5;
        int attempts = 0;

        while (running && attempts < max_attempts)
        {
            std::string response = send_request("BRIDGE\r\nclientID: " + client_id + "\r\n\r\n");
            process_response(response);

            if (!peer_info.empty())
            {
                start_chat();
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
            {
                std::lock_guard<std::mutex> lock(console_mtx);
                std::cout << "Failed to find peer after " << attempts << " attempts\n";
            }
            cleanup();
        }
    }

    void send_quit()
    {
        if (peer_socket != -1)
        {
            // Notify peer about disconnection
            send_to_peer("/quit");
        }
        cleanup();
    }

    void send_to_peer(const std::string &message)
    {
        if (peer_socket == -1)
        {
            internal_print("No active peer connection");
            return;
        }

        // Add proper message framing
        std::string framed_message = message + "\r\n";

        ssize_t bytes_sent = send(peer_socket, framed_message.c_str(),
                                  framed_message.size(), 0);
        if (bytes_sent < 0)
        {
            internal_print("Failed to send message: " + std::string(strerror(errno)));
            cleanup();
        }
    }

    std::string send_request(const std::string &message)
    {
        try
        {
            connect_to_server();

            if (send(server_socket, message.c_str(), message.size(), 0) < 0)
            {
                throw std::runtime_error("send failed");
            }

            char buffer[1024];
            ssize_t bytes_read = recv(server_socket, buffer, sizeof(buffer), 0);
            if (bytes_read <= 0)
            {
                disconnect_server();
                return "";
            }

            return std::string(buffer, bytes_read);
        }
        catch (const std::exception &e)
        {
            disconnect_server();
            throw;
        }
    }

    void register_client()
    {
        if (server_socket == -1)
            connect_to_server();
        std::string message = "REGISTER\r\nclientID: " + client_id +
                              "\r\nIP: " + client_ip +
                              "\r\nPort: " + std::to_string(client_port) + "\r\n\r\n";
        std::string response = send_request(message);
        process_response(response);
    }

    void bridge_request()
    {
        if (server_socket == -1)
            connect_to_server();
        std::string message = "BRIDGE\r\nclientID: " + client_id + "\r\n\r\n";
        std::string response = send_request(message);
        process_response(response);
    }

    void process_response(const std::string &response)
    {
        std::vector<std::string> lines = split(response, '\r');
        if (lines.empty())
            return;

        std::string response_type = trim(lines[0]);

        if (response_type == "REGACK")
        {
            internal_print("Successfully registered with server");
        }
        else if (response_type == "BRIDGEACK")
        {
            auto headers = parse_headers(response);
            if (headers.find("clientID") != headers.end() && !headers["clientID"].empty())
            {
                peer_info = headers;
                internal_print("Found peer: " + headers["clientID"] +
                               " (" + headers["IP"] + ":" + headers["Port"] + ")");

                start_chat();
            }
            else
            {
                internal_print("No peers available - waiting for incoming connection");
                enter_wait_mode(); // This client becomes the listener
            }
        }
        else if (response_type == "ERROR")
        {
            auto headers = parse_headers(response);
            internal_print("Error: " + headers["message"]);
        }
    }

    void enter_wait_mode()
    {
        internal_print("Entering LISTEN MODE on port " + std::to_string(client_port));
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
        internal_print("Listening for incoming connections...");

        sockaddr_in peer_addr;
        socklen_t addr_len = sizeof(peer_addr);
        peer_socket = accept(listen_socket, (struct sockaddr *)&peer_addr, &addr_len);
        close(listen_socket);

        if (peer_socket < 0)
        {
            throw std::runtime_error("accept failed");
        }

        internal_print("Peer connected from " +
                       std::string(inet_ntoa(peer_addr.sin_addr)) + ":" +
                       std::to_string(ntohs(peer_addr.sin_port)));

        chat_mode();
    }

    void start_chat()
    {
        internal_print("Attempting connection to peer at " + peer_info["IP"] +
                       ":" + peer_info["Port"]);

        if (peer_info.empty())
        {
            // Enter listen mode if no peer info
            internal_print("Starting listener on port " + std::to_string(client_port));
            enter_wait_mode();
            return;
        }

        if (peer_socket != -1)
        {
            internal_print("Already in chat session");
            return;
        }

        internal_print("Initiating chat connection...");

        const int max_retries = 3;
        int retry_count = 0;
        const int retry_delay = 2000;

        while (retry_count < max_retries && running)
        {
            internal_print("Attempting connection to peer (attempt " +
                           std::to_string(retry_count + 1) + "/3)");

            try
            {
                peer_socket = socket(AF_INET, SOCK_STREAM, 0);
                if (peer_socket < 0)
                {
                    throw std::runtime_error("socket creation failed");
                }

                timeval tv{};
                tv.tv_sec = 2;
                setsockopt(peer_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

                sockaddr_in peer_addr;
                peer_addr.sin_family = AF_INET;
                peer_addr.sin_port = htons(std::stoi(peer_info["Port"]));
                inet_pton(AF_INET, peer_info["IP"].c_str(), &peer_addr.sin_addr);

                if (connect(peer_socket, (struct sockaddr *)&peer_addr, sizeof(peer_addr)) == 0)
                {
                    // Reset timeout to block indefinitely
                    timeval tv{};
                    tv.tv_sec = 0;
                    setsockopt(peer_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

                    internal_print("Successfully connected to peer");
                    is_first_client = false;
                    chat_mode();
                    return;
                }

                close(peer_socket);
                peer_socket = -1;

                // Wait before retrying
                std::this_thread::sleep_for(std::chrono::milliseconds(retry_delay));
                retry_count++;
            }
            catch (const std::exception &e)
            {
                internal_print("Connection failed: " + std::string(e.what()));
                retry_count++;
            }
        }

        internal_print("Failed to connect after 3 attempts. Check if peer is listening.");
    }

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

                // Handle redraws atomically
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

    void cleanup()
    {
        if (server_socket != -1)
        {
            // Notify server we're available again
            std::string message = "UNREGISTER\r\nclientID: " + client_id + "\r\n\r\n";
            send(server_socket, message.c_str(), message.size(), 0);
        }

        disconnect_server();
        if (peer_socket != -1)
        {
            close(peer_socket);
            peer_socket = -1;
        }
        running = false;
        internal_print("Client terminated");
    }
};

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

    try
    {
        Client client(id, port, server_addr);
        client_print_status("Client started (ID: " + id + ")");
        client_print_status("Connected to server");
        client_print_status("Automatic commands:");
        client_print_status("  /quit     - Exit program");
        client_print_status("Type messages directly to chat");
        client.run();
    }
    catch (const std::exception &e)
    {
        std::cerr << "Client error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}