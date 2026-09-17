#pragma once

#include <string>
#include <memory>
#include <atomic>
#include <cstdint>
#include <chrono>
#include <bpf/libbpf.h>

struct netmon_bpf;
struct ring_buffer;

// ─── ANSI colour helpers ─────────────────────────────────────────────────────
namespace Color {
    inline constexpr const char *RESET   = "\033[0m";
    inline constexpr const char *BOLD    = "\033[1m";
    inline constexpr const char *DIM     = "\033[2m";

    // Directions
    inline constexpr const char *IN_CLR  = "\033[38;5;82m";   // green
    inline constexpr const char *OUT_CLR = "\033[38;5;214m";  // orange

    // Protocols
    inline constexpr const char *TCP_CLR  = "\033[38;5;39m";  // sky blue
    inline constexpr const char *UDP_CLR  = "\033[38;5;183m"; // lavender
    inline constexpr const char *ICMP_CLR = "\033[38;5;220m"; // yellow

    // UI chrome
    inline constexpr const char *HEADER_BG = "\033[38;5;68m"; // steel blue
    inline constexpr const char *LIVE_CLR  = "\033[38;5;82m"; // green
    inline constexpr const char *FILTER_CLR= "\033[38;5;215m";// peach
    inline constexpr const char *STAT_CLR  = "\033[38;5;245m";// grey
    inline constexpr const char *WARN_CLR  = "\033[38;5;196m";// red
} // namespace Color

// ─── Filtering configuration ─────────────────────────────────────────────────
enum class DirectionFilter {
    BOTH = 0,
    INGRESS_ONLY = 1,
    EGRESS_ONLY = 2
};

enum class ProtocolFilter {
    ALL = 0,
    TCP = 1,
    UDP = 2,
    ICMP = 3
};

struct MonitorConfig {
    std::string iface_name;
    uint32_t filter_ip{0};          // host byte order; 0 = any
    uint16_t filter_port{0};        // host byte order; 0 = any (matches src or dst for TCP/UDP)
    ProtocolFilter proto_filter{ProtocolFilter::ALL};
    DirectionFilter dir_filter{DirectionFilter::BOTH};
    uint64_t max_packet_count{0};    // 0 = unlimited
    bool use_color{true};
};

// ─── Runtime statistics ───────────────────────────────────────────────────────
struct MonitorStats {
    uint64_t total_received{0};   // events received from ring buffer
    uint64_t total_displayed{0};  // events printed (after filters)
    uint64_t ingress_count{0};
    uint64_t egress_count{0};
    uint64_t total_bytes{0};      // sum of packet_len for all received events
    uint64_t malformed_dropped{0};// malformed/invalid events ignored
    std::chrono::steady_clock::time_point start_time{};
};

// ─── NetworkMonitor class ─────────────────────────────────────────────────────
class NetworkMonitor {
public:
    explicit NetworkMonitor(MonitorConfig config);
    explicit NetworkMonitor(std::string iface_name, uint32_t filter_ip = 0,
                            bool use_color = true)
        : NetworkMonitor(MonitorConfig{std::move(iface_name), filter_ip, 0,
                                       ProtocolFilter::ALL, DirectionFilter::BOTH, 0, use_color}) {}
    ~NetworkMonitor();

    // Non-copyable, non-movable
    NetworkMonitor(const NetworkMonitor &) = delete;
    NetworkMonitor &operator=(const NetworkMonitor &) = delete;
    NetworkMonitor(NetworkMonitor &&) = delete;
    NetworkMonitor &operator=(NetworkMonitor &&) = delete;

    bool start();
    void stop();
    void poll(int timeout_ms = 100);

    bool is_running() const { return running_; }
    bool limit_reached() const {
        return config_.max_packet_count > 0 && stats_.total_displayed >= config_.max_packet_count;
    }
    const std::string &interface_name() const { return config_.iface_name; }
    const MonitorStats &stats() const { return stats_; }
    const MonitorConfig &config() const { return config_; }

    void print_summary() const;

private:
    static int handle_event(void *ctx, void *data, size_t data_sz);
    void process_event(const void *data, size_t data_sz);
    void print_header_banner() const;
    void print_table_header() const;

    // UI helpers
    const char *dir_color(uint8_t direction) const;
    const char *proto_color(uint8_t protocol) const;
    std::string format_size(uint32_t bytes) const;
    std::string format_rate(double bytes_per_sec) const;
    std::string colorize(const char *color, const std::string &text) const;

    // TC constants & inspection helpers
    static constexpr uint32_t NETMON_TC_PRIO_DEFAULT   = 5050;
    static constexpr uint32_t NETMON_TC_HANDLE_DEFAULT = 1;

    bool check_clsact_qdisc_exists(int ifindex) const;
    int count_existing_tc_filters(int ifindex, uint32_t parent) const;
    uint32_t allocate_unique_filter_priority(int ifindex, uint32_t parent, uint32_t base_priority) const;

    MonitorConfig config_;
    int ifindex_{-1};

    struct netmon_bpf  *skel_{nullptr};
    struct ring_buffer *rb_{nullptr};
    std::atomic<bool>   running_{false};

    // Traffic Control hooks
    struct bpf_tc_hook hook_ingress_{};
    struct bpf_tc_opts opts_ingress_{};
    bool attached_ingress_{false};

    struct bpf_tc_hook hook_egress_{};
    struct bpf_tc_opts opts_egress_{};
    bool attached_egress_{false};

    bool     hook_created_{false};      // true ONLY if this process created clsact
    bool     qdisc_preexisted_{false};  // true if clsact was already present
    int      existing_ingress_filters_{0};
    int      existing_egress_filters_{0};
    uint64_t boot_to_realtime_ns_{0};

    MonitorStats stats_{};
};
