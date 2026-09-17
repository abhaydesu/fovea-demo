#include "monitor.hpp"

#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <csignal>
#include <atomic>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>

namespace {
std::atomic<bool> g_stop{false};

void signal_handler(int sig)
{
    (void)sig;
    g_stop.store(true);
}

std::string to_lower(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

void print_usage(const char *prog_name)
{
    std::cout << "Usage: " << prog_name << " [options]\n\n"
              << "A lightweight Linux eBPF network monitor capturing packet metadata.\n\n"
              << "Options:\n"
              << "  -i, --interface <iface>      Network interface to monitor (e.g., eth0, wlp2s0, lo)\n"
              << "  -a, --address <ipv4>         Filter traffic by IPv4 address (matches source or destination)\n"
              << "  -p, --proto <tcp|udp|icmp>   Filter traffic by protocol (case-insensitive)\n"
              << "  -d, --direction <in|out|both>Filter traffic by direction (in, out, or both; default: both)\n"
              << "      --port <1-65535>         Filter traffic by L4 port (matches source or destination for TCP/UDP)\n"
              << "  -c, --count <N>              Exit after capturing N matching packets\n"
              << "      --no-color               Disable ANSI color output\n"
              << "  -h, --help                   Display this help message and exit\n\n"
              << "Examples:\n"
              << "  sudo " << prog_name << "\n"
              << "  sudo " << prog_name << " --interface wlp0s20f3\n"
              << "  sudo " << prog_name << " -i wlp0s20f3 -a 8.8.8.8\n"
              << "  sudo " << prog_name << " -i wlp0s20f3 -p tcp --port 443\n"
              << "  sudo " << prog_name << " -i wlp0s20f3 -d in -p icmp\n"
              << "  sudo " << prog_name << " -i lo -a 127.0.0.1 -c 10\n";
}

std::vector<std::string> get_available_interfaces()
{
    std::vector<std::string> ifaces;
    struct ifaddrs *addrs = nullptr;
    if (getifaddrs(&addrs) != 0 || !addrs) {
        return ifaces;
    }

    for (struct ifaddrs *cur = addrs; cur != nullptr; cur = cur->ifa_next) {
        if (!cur->ifa_name) continue;
        std::string name = cur->ifa_name;
        bool found = false;
        for (const auto &existing : ifaces) {
            if (existing == name) {
                found = true;
                break;
            }
        }
        if (!found) {
            ifaces.push_back(name);
        }
    }
    freeifaddrs(addrs);
    return ifaces;
}

std::string auto_detect_interface()
{
    struct ifaddrs *addrs = nullptr;
    if (getifaddrs(&addrs) != 0 || !addrs) {
        return "";
    }

    std::string candidate_up;
    std::string candidate_loopback;

    for (struct ifaddrs *cur = addrs; cur != nullptr; cur = cur->ifa_next) {
        if (!cur->ifa_name) continue;
        std::string name = cur->ifa_name;
        unsigned int flags = cur->ifa_flags;

        // Skip non-UP interfaces
        if (!(flags & IFF_UP)) continue;

        if (flags & IFF_LOOPBACK) {
            if (candidate_loopback.empty()) {
                candidate_loopback = name;
            }
        } else if (flags & IFF_RUNNING) {
            // Active running non-loopback interface
            candidate_up = name;
            break;
        } else if (candidate_up.empty()) {
            candidate_up = name;
        }
    }

    freeifaddrs(addrs);

    if (!candidate_up.empty()) {
        return candidate_up;
    }
    return candidate_loopback;
}
} // namespace

int main(int argc, char *argv[])
{
    MonitorConfig config;
    config.use_color = isatty(STDOUT_FILENO) != 0;

    std::string filter_ip_str;
    std::string port_str;
    std::string count_str;
    std::string proto_str;
    std::string dir_str;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "-i" || arg == "--interface") {
            if (i + 1 < argc) {
                config.iface_name = argv[++i];
            } else {
                std::cerr << "Error: " << arg << " requires an interface argument.\n";
                print_usage(argv[0]);
                return 1;
            }
        } else if (arg == "-a" || arg == "--address") {
            if (i + 1 < argc) {
                filter_ip_str = argv[++i];
            } else {
                std::cerr << "Error: " << arg << " requires an IPv4 address argument.\n";
                print_usage(argv[0]);
                return 1;
            }
        } else if (arg == "-p" || arg == "--proto") {
            if (i + 1 < argc) {
                proto_str = argv[++i];
            } else {
                std::cerr << "Error: " << arg << " requires a protocol argument (tcp, udp, icmp, all).\n";
                print_usage(argv[0]);
                return 1;
            }
        } else if (arg == "-d" || arg == "--direction") {
            if (i + 1 < argc) {
                dir_str = argv[++i];
            } else {
                std::cerr << "Error: " << arg << " requires a direction argument (in, out, both).\n";
                print_usage(argv[0]);
                return 1;
            }
        } else if (arg == "--port") {
            if (i + 1 < argc) {
                port_str = argv[++i];
            } else {
                std::cerr << "Error: --port requires a port number argument (1-65535).\n";
                print_usage(argv[0]);
                return 1;
            }
        } else if (arg == "-c" || arg == "--count") {
            if (i + 1 < argc) {
                count_str = argv[++i];
            } else {
                std::cerr << "Error: " << arg << " requires a packet count argument.\n";
                print_usage(argv[0]);
                return 1;
            }
        } else if (arg == "--no-color") {
            config.use_color = false;
        } else {
            std::cerr << "Error: Unrecognized option '" << arg << "'.\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    // ── Validate IPv4 address filter ──
    if (!filter_ip_str.empty()) {
        struct in_addr addr{};
        if (inet_pton(AF_INET, filter_ip_str.c_str(), &addr) != 1) {
            std::cerr << "Error: Invalid IPv4 address '" << filter_ip_str << "'.\n"
                      << "Please specify a valid dot-decimal IPv4 address (e.g., 8.8.8.8).\n";
            return 1;
        }
        config.filter_ip = ntohl(addr.s_addr);
    }

    // ── Validate protocol filter ──
    if (!proto_str.empty()) {
        std::string p = to_lower(proto_str);
        if (p == "tcp") {
            config.proto_filter = ProtocolFilter::TCP;
        } else if (p == "udp") {
            config.proto_filter = ProtocolFilter::UDP;
        } else if (p == "icmp") {
            config.proto_filter = ProtocolFilter::ICMP;
        } else if (p == "all") {
            config.proto_filter = ProtocolFilter::ALL;
        } else {
            std::cerr << "Error: Invalid protocol '" << proto_str << "'.\n"
                      << "Allowed values: tcp, udp, icmp, all.\n";
            return 1;
        }
    }

    // ── Validate direction filter ──
    if (!dir_str.empty()) {
        std::string d = to_lower(dir_str);
        if (d == "in" || d == "ingress") {
            config.dir_filter = DirectionFilter::INGRESS_ONLY;
        } else if (d == "out" || d == "egress") {
            config.dir_filter = DirectionFilter::EGRESS_ONLY;
        } else if (d == "both") {
            config.dir_filter = DirectionFilter::BOTH;
        } else {
            std::cerr << "Error: Invalid direction '" << dir_str << "'.\n"
                      << "Allowed values: in, out, both.\n";
            return 1;
        }
    }

    // ── Validate port filter ──
    if (!port_str.empty()) {
        try {
            size_t idx = 0;
            int port = std::stoi(port_str, &idx);
            if (idx != port_str.size() || port < 1 || port > 65535) {
                std::cerr << "Error: Port '" << port_str << "' is outside valid range (1-65535).\n";
                return 1;
            }
            config.filter_port = static_cast<uint16_t>(port);
        } catch (...) {
            std::cerr << "Error: Invalid port number '" << port_str << "'. Must be 1-65535.\n";
            return 1;
        }
    }

    // ── Validate count limit ──
    if (!count_str.empty()) {
        try {
            size_t idx = 0;
            long long cnt = std::stoll(count_str, &idx);
            if (idx != count_str.size() || cnt <= 0) {
                std::cerr << "Error: Count '" << count_str << "' must be a positive integer greater than zero.\n";
                return 1;
            }
            config.max_packet_count = static_cast<uint64_t>(cnt);
        } catch (...) {
            std::cerr << "Error: Invalid count value '" << count_str << "'.\n";
            return 1;
        }
    }

    // ── Interface selection ──
    if (config.iface_name.empty()) {
        config.iface_name = auto_detect_interface();
        if (config.iface_name.empty()) {
            std::cerr << "Error: No suitable network interface detected.\n"
                      << "Please specify an interface using --interface <name>.\n";
            return 1;
        }
        std::cout << "Auto-selected active network interface: " << config.iface_name << "\n";
    }

    // ── Root privilege notice ──
    if (geteuid() != 0) {
        std::cerr << "Warning: Running as non-root user. Loading eBPF programs and attaching\n"
                  << "Traffic Control filters typically requires root privileges (sudo).\n\n";
    }

    // ── Setup signal handlers ──
    struct sigaction sa{};
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    NetworkMonitor monitor(config);
    if (!monitor.start()) {
        std::cerr << "\nFailed to initialize network monitor on interface '" << config.iface_name << "'.\n";
        auto available = get_available_interfaces();
        if (!available.empty()) {
            std::cerr << "Available interfaces on this system:\n";
            for (const auto &iface : available) {
                std::cerr << "  - " << iface << "\n";
            }
        }
        return 1;
    }

    if (config.max_packet_count > 0) {
        std::cout << "Capturing up to " << config.max_packet_count << " packets... Press Ctrl+C to stop early.\n\n";
    } else {
        std::cout << "Capturing packets... Press Ctrl+C to stop.\n\n";
    }

    while (!g_stop.load() && !monitor.limit_reached()) {
        monitor.poll(100);
    }

    if (monitor.limit_reached()) {
        std::cout << "\nPacket count limit (" << config.max_packet_count << ") reached.\n";
    } else {
        std::cout << "\nStopping monitor and cleaning up eBPF resources...\n";
    }

    monitor.stop();
    monitor.print_summary();
    std::cout << "\nClean shutdown completed.\n";

    return 0;
}
