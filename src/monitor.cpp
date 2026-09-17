#include "monitor.hpp"
#include "netmon.h"
#include "netmon.skel.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <ctime>
#include <cstring>
#include <string>
#include <vector>
#include <net/if.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <cstdarg>

// ─── Custom libbpf print callback ──────────────────────────────────────────────
static int libbpf_print_callback(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_WARN) {
        va_list args_copy;
        va_copy(args_copy, args);
        char buf[256];
        vsnprintf(buf, sizeof(buf), fmt, args_copy);
        va_end(args_copy);
        // Classify and suppress known harmless kernel exclusivity message
        if (std::strstr(buf, "Exclusivity flag on")) {
            return 0;
        }
    }
    if (level == LIBBPF_DEBUG) {
        return 0;
    }
    // Preserve all genuine warnings and errors
    return vfprintf(stderr, fmt, args);
}

// ─── Terminal width helper ─────────────────────────────────────────────────────
static int terminal_width()
{
    struct winsize ws{};
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
        return static_cast<int>(ws.ws_col);
    }
    return 80; // safe fallback
}

// ─── UTF-8 repeat helper ──────────────────────────────────────────────────────
static std::string repeat_utf8(const std::string &glyph, int count)
{
    std::string s;
    s.reserve(glyph.size() * static_cast<size_t>(count));
    for (int i = 0; i < count; ++i) s += glyph;
    return s;
}

// ─── Box-drawing helpers ───────────────────────────────────────────────────────
static std::string box_top(int w)
{
    return "╭" + repeat_utf8("─", w - 2) + "╮";
}
static std::string box_sep(int w)
{
    return "├" + repeat_utf8("─", w - 2) + "┤";
}
static std::string box_bot(int w)
{
    return "╰" + repeat_utf8("─", w - 2) + "╯";
}
static std::string box_row(const std::string &content, int w)
{
    int inner = w - 4;
    if (inner < 0) inner = 0;
    std::string s = content;
    if (static_cast<int>(s.size()) > inner) {
        s = s.substr(0, static_cast<size_t>(inner));
    }
    std::string row = "│ ";
    row += s;
    int pad = inner - static_cast<int>(s.size());
    if (pad > 0) row += std::string(static_cast<size_t>(pad), ' ');
    row += " │";
    return row;
}
static std::string box_centre(const std::string &text, int w)
{
    int inner = w - 4;
    if (inner < 0) inner = 0;
    int textlen = static_cast<int>(text.size());
    int total_pad = inner - textlen;
    if (total_pad < 0) total_pad = 0;
    int left_pad  = total_pad / 2;
    int right_pad = total_pad - left_pad;
    return "│ " + std::string(static_cast<size_t>(left_pad), ' ')
                + text
                + std::string(static_cast<size_t>(right_pad), ' ')
                + " │";
}

// ─── TC Inspection via Netlink ────────────────────────────────────────────────
bool NetworkMonitor::check_clsact_qdisc_exists(int target_ifindex) const
{
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) return false;

    struct {
        struct nlmsghdr n;
        struct tcmsg t;
    } req{};

    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.n.nlmsg_type = RTM_GETQDISC;
    req.t.tcm_family = AF_UNSPEC;
    req.t.tcm_ifindex = target_ifindex;

    if (send(fd, &req, req.n.nlmsg_len, 0) < 0) {
        close(fd);
        return false;
    }

    char buf[8192];
    bool found = false;
    while (true) {
        ssize_t len = recv(fd, buf, sizeof(buf), 0);
        if (len <= 0) break;
        auto *nlh = reinterpret_cast<struct nlmsghdr *>(buf);
        if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) break;

        for (; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
            if (nlh->nlmsg_type == NLMSG_DONE) {
                len = 0;
                break;
            }
            if (nlh->nlmsg_type != RTM_NEWQDISC) continue;
            auto *tcm = reinterpret_cast<struct tcmsg *>(NLMSG_DATA(nlh));
            if (tcm->tcm_ifindex != target_ifindex) continue;

            auto *rta = reinterpret_cast<struct rtattr *>(
                reinterpret_cast<char *>(tcm) + NLMSG_ALIGN(sizeof(struct tcmsg)));
            int rta_len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(struct tcmsg));
            for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
                if (rta->rta_type == TCA_KIND) {
                    const char *kind = reinterpret_cast<const char *>(RTA_DATA(rta));
                    if (kind && std::strcmp(kind, "clsact") == 0) {
                        found = true;
                    }
                }
            }
        }
    }
    close(fd);
    return found;
}

int NetworkMonitor::count_existing_tc_filters(int target_ifindex, uint32_t parent) const
{
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) return 0;

    struct {
        struct nlmsghdr n;
        struct tcmsg t;
    } req{};

    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.n.nlmsg_type = RTM_GETTFILTER;
    req.t.tcm_family = AF_UNSPEC;
    req.t.tcm_ifindex = target_ifindex;
    req.t.tcm_parent = parent;

    if (send(fd, &req, req.n.nlmsg_len, 0) < 0) {
        close(fd);
        return 0;
    }

    char buf[8192];
    int count = 0;
    while (true) {
        ssize_t len = recv(fd, buf, sizeof(buf), 0);
        if (len <= 0) break;
        auto *nlh = reinterpret_cast<struct nlmsghdr *>(buf);
        if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) break;

        for (; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
            if (nlh->nlmsg_type == NLMSG_DONE) {
                len = 0;
                break;
            }
            if (nlh->nlmsg_type != RTM_NEWTFILTER) continue;
            auto *tcm = reinterpret_cast<struct tcmsg *>(NLMSG_DATA(nlh));
            if (tcm->tcm_ifindex == target_ifindex) {
                ++count;
            }
        }
    }
    close(fd);
    return count;
}

uint32_t NetworkMonitor::allocate_unique_filter_priority(int target_ifindex, uint32_t parent, uint32_t base_priority) const
{
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) return base_priority;

    struct {
        struct nlmsghdr n;
        struct tcmsg t;
    } req{};

    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.n.nlmsg_type = RTM_GETTFILTER;
    req.t.tcm_family = AF_UNSPEC;
    req.t.tcm_ifindex = target_ifindex;
    req.t.tcm_parent = parent;

    if (send(fd, &req, req.n.nlmsg_len, 0) < 0) {
        close(fd);
        return base_priority;
    }

    std::vector<uint32_t> used_prios;
    char buf[8192];
    while (true) {
        ssize_t len = recv(fd, buf, sizeof(buf), 0);
        if (len <= 0) break;
        auto *nlh = reinterpret_cast<struct nlmsghdr *>(buf);
        if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) break;

        for (; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
            if (nlh->nlmsg_type == NLMSG_DONE) {
                len = 0;
                break;
            }
            if (nlh->nlmsg_type != RTM_NEWTFILTER) continue;
            auto *tcm = reinterpret_cast<struct tcmsg *>(NLMSG_DATA(nlh));
            if (tcm->tcm_ifindex == target_ifindex) {
                uint32_t prio = tcm->tcm_info >> 16;
                if (prio > 0) {
                    used_prios.push_back(prio);
                }
            }
        }
    }
    close(fd);

    uint32_t chosen = base_priority;
    while (true) {
        bool in_use = false;
        for (uint32_t p : used_prios) {
            if (p == chosen) {
                in_use = true;
                break;
            }
        }
        if (!in_use) break;
        ++chosen;
    }
    return chosen;
}

// ─── Constructor / Destructor ─────────────────────────────────────────────────
NetworkMonitor::NetworkMonitor(MonitorConfig config)
    : config_(std::move(config))
{
    // Compute offset from CLOCK_MONOTONIC to CLOCK_REALTIME for timestamps
    struct timespec ts_real{}, ts_mono{};
    clock_gettime(CLOCK_REALTIME, &ts_real);
    clock_gettime(CLOCK_MONOTONIC, &ts_mono);

    uint64_t real_ns = static_cast<uint64_t>(ts_real.tv_sec) * 1000000000ULL
                       + ts_real.tv_nsec;
    uint64_t mono_ns = static_cast<uint64_t>(ts_mono.tv_sec) * 1000000000ULL
                       + ts_mono.tv_nsec;
    boot_to_realtime_ns_ = (real_ns > mono_ns) ? (real_ns - mono_ns) : 0;
}

NetworkMonitor::~NetworkMonitor()
{
    stop();
}

// ─── Colour & Format helpers ──────────────────────────────────────────────────
std::string NetworkMonitor::colorize(const char *color, const std::string &text) const
{
    if (!config_.use_color) return text;
    return std::string(color) + text + Color::RESET;
}

const char *NetworkMonitor::dir_color(uint8_t direction) const
{
    return (direction == DIR_INGRESS) ? Color::IN_CLR : Color::OUT_CLR;
}

const char *NetworkMonitor::proto_color(uint8_t protocol) const
{
    switch (protocol) {
    case NETMON_PROTO_TCP:  return Color::TCP_CLR;
    case NETMON_PROTO_UDP:  return Color::UDP_CLR;
    case NETMON_PROTO_ICMP: return Color::ICMP_CLR;
    default:                return Color::RESET;
    }
}

std::string NetworkMonitor::format_size(uint32_t bytes) const
{
    if (bytes < 1024) {
        return std::to_string(bytes) + " B";
    } else if (bytes < 1024 * 1024) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(1)
            << (static_cast<double>(bytes) / 1024.0) << " KB";
        return oss.str();
    } else {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2)
            << (static_cast<double>(bytes) / (1024.0 * 1024.0)) << " MB";
        return oss.str();
    }
}

std::string NetworkMonitor::format_rate(double bytes_per_sec) const
{
    if (bytes_per_sec < 1024.0) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(1) << bytes_per_sec << " B/s";
        return oss.str();
    } else if (bytes_per_sec < 1024.0 * 1024.0) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(1) << (bytes_per_sec / 1024.0) << " KB/s";
        return oss.str();
    } else {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2) << (bytes_per_sec / (1024.0 * 1024.0)) << " MB/s";
        return oss.str();
    }
}

// ─── Startup banner ───────────────────────────────────────────────────────────
void NetworkMonitor::print_header_banner() const
{
    const int w = std::min(terminal_width(), 68);

    auto col = [&](const char *c, const std::string &s) -> std::string {
        return config_.use_color ? (std::string(c) + s + Color::RESET) : s;
    };

    std::cout << "\n";
    std::cout << col(Color::HEADER_BG, box_top(w)) << "\n";
    std::cout << col(Color::HEADER_BG, box_centre(
                    col(Color::BOLD, "ebpf-netmon"), w)) << "\n";
    std::cout << col(Color::HEADER_BG, box_centre(
                    "eBPF Network Traffic Monitor", w)) << "\n";
    std::cout << col(Color::HEADER_BG, box_sep(w)) << "\n";

    // Interface line
    std::ostringstream iface_line;
    iface_line << "Interface : " << config_.iface_name
               << "  (index " << ifindex_ << ")";
    std::cout << col(Color::HEADER_BG, box_row(iface_line.str(), w)) << "\n";

    // Capture line
    std::string cap_mode;
    if (config_.dir_filter == DirectionFilter::INGRESS_ONLY) {
        cap_mode = "INGRESS ONLY";
    } else if (config_.dir_filter == DirectionFilter::EGRESS_ONLY) {
        cap_mode = "EGRESS ONLY";
    } else {
        cap_mode = "INGRESS + EGRESS";
    }
    std::cout << col(Color::HEADER_BG, box_row("Capture   : " + cap_mode, w)) << "\n";

    // Protocol filter line (if active)
    if (config_.proto_filter != ProtocolFilter::ALL) {
        std::string pstr;
        if (config_.proto_filter == ProtocolFilter::TCP) pstr = "TCP only";
        else if (config_.proto_filter == ProtocolFilter::UDP) pstr = "UDP only";
        else if (config_.proto_filter == ProtocolFilter::ICMP) pstr = "ICMP only";
        std::cout << col(Color::HEADER_BG, box_row("Filter Prt: " + pstr, w)) << "\n";
    }

    // IP filter line (if active)
    if (config_.filter_ip != 0) {
        struct in_addr addr{};
        addr.s_addr = htonl(config_.filter_ip);
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, buf, sizeof(buf));
        std::cout << col(Color::HEADER_BG, box_row("Filter IP : " + std::string(buf), w)) << "\n";
    }

    // Port filter line (if active)
    if (config_.filter_port != 0) {
        std::cout << col(Color::HEADER_BG,
                         box_row("Filter Port: " + std::to_string(config_.filter_port), w)) << "\n";
    }

    // Packet limit line (if active)
    if (config_.max_packet_count > 0) {
        std::cout << col(Color::HEADER_BG,
                         box_row("Limit     : " + std::to_string(config_.max_packet_count) + " packets", w)) << "\n";
    }

    // TC Qdisc status line
    std::string tc_status = qdisc_preexisted_
        ? "Reusing existing clsact"
        : "Created new clsact";
    if (existing_ingress_filters_ > 0 || existing_egress_filters_ > 0) {
        tc_status += " (" + std::to_string(existing_ingress_filters_) + " in, " +
                     std::to_string(existing_egress_filters_) + " out preserved)";
    }
    std::cout << col(Color::HEADER_BG,
                     box_row("TC Qdisc  : " + tc_status, w)) << "\n";

    // TC Filters info line
    std::ostringstream tc_filter_line;
    tc_filter_line << "TC Filters: pref " << opts_ingress_.priority
                   << " handle " << opts_ingress_.handle;
    std::cout << col(Color::HEADER_BG,
                     box_row(tc_filter_line.str(), w)) << "\n";

    // Status line
    std::string live_dot = config_.use_color
        ? (std::string(Color::LIVE_CLR) + "●" + Color::RESET + Color::HEADER_BG + " LIVE")
        : "● LIVE";
    std::cout << col(Color::HEADER_BG,
                     box_row("Status    : " + live_dot, w)) << "\n";

    std::cout << col(Color::HEADER_BG, box_bot(w)) << "\n\n";
}

// ─── Table header ─────────────────────────────────────────────────────────────
void NetworkMonitor::print_table_header() const
{
    auto bold = [&](const std::string &s) -> std::string {
        return config_.use_color ? (std::string(Color::BOLD) + s + Color::RESET) : s;
    };
    auto dim = [&](const std::string &s) -> std::string {
        return config_.use_color ? (std::string(Color::DIM) + s + Color::RESET) : s;
    };

    std::cout << bold("TIME      ")
              << bold("DIR  ")
              << bold("PROTO    ")
              << bold("SOURCE                ")
              << bold("DESTINATION           ")
              << bold("   SIZE")
              << "\n";
    std::cout << dim(repeat_utf8("─", 76)) << "\n" << std::flush;
}

// ─── start() ─────────────────────────────────────────────────────────────────
bool NetworkMonitor::start()
{
    if (running_) {
        return true;
    }

    // Install libbpf log callback to catch/classify any library warnings
    libbpf_set_print(libbpf_print_callback);

    ifindex_ = static_cast<int>(if_nametoindex(config_.iface_name.c_str()));
    if (ifindex_ == 0) {
        std::cerr << "Error: Interface '" << config_.iface_name << "' not found.\n";
        return false;
    }

    // 1. Open and load eBPF skeleton
    skel_ = netmon_bpf__open_and_load();
    if (!skel_) {
        std::cerr << "Error: Failed to open and load eBPF skeleton.\n";
        return false;
    }

    // 2. Inspect existing TC qdisc and filter setup via Netlink
    qdisc_preexisted_ = check_clsact_qdisc_exists(ifindex_);
    existing_ingress_filters_ = count_existing_tc_filters(
        ifindex_, TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS));
    existing_egress_filters_ = count_existing_tc_filters(
        ifindex_, TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS));

    // Prepare TC hook structures
    std::memset(&hook_ingress_, 0, sizeof(hook_ingress_));
    hook_ingress_.sz        = sizeof(hook_ingress_);
    hook_ingress_.ifindex   = ifindex_;
    hook_ingress_.attach_point = BPF_TC_INGRESS;

    std::memset(&hook_egress_, 0, sizeof(hook_egress_));
    hook_egress_.sz        = sizeof(hook_egress_);
    hook_egress_.ifindex   = ifindex_;
    hook_egress_.attach_point = BPF_TC_EGRESS;

    // Idempotent TC qdisc management:
    // If clsact is already present on this interface, reuse it directly.
    if (qdisc_preexisted_) {
        hook_created_ = false;
    } else {
        int err = bpf_tc_hook_create(&hook_ingress_);
        if (err == 0) {
            hook_created_ = true;
        } else if (err == -EEXIST) {
            hook_created_ = false;
            qdisc_preexisted_ = true;
        } else {
            std::cerr << "Error: Failed to create TC clsact hook: "
                      << std::strerror(-err) << "\n";
            netmon_bpf__destroy(skel_);
            skel_ = nullptr;
            return false;
        }
    }

    // 3. Attach ingress TC filter with unique, collision-free priority and handle
    uint32_t ingress_prio = allocate_unique_filter_priority(
        ifindex_, TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS), NETMON_TC_PRIO_DEFAULT);

    std::memset(&opts_ingress_, 0, sizeof(opts_ingress_));
    opts_ingress_.sz       = sizeof(opts_ingress_);
    opts_ingress_.prog_fd  = bpf_program__fd(skel_->progs.tc_ingress);
    opts_ingress_.priority = ingress_prio;
    opts_ingress_.handle   = NETMON_TC_HANDLE_DEFAULT;

    int err = bpf_tc_attach(&hook_ingress_, &opts_ingress_);
    if (err) {
        std::cerr << "Error: Failed to attach ingress TC filter: "
                  << std::strerror(-err) << "\n";
        stop();
        return false;
    }
    attached_ingress_ = true;

    // 4. Attach egress TC filter with unique, collision-free priority and handle
    uint32_t egress_prio = allocate_unique_filter_priority(
        ifindex_, TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS), NETMON_TC_PRIO_DEFAULT);

    std::memset(&opts_egress_, 0, sizeof(opts_egress_));
    opts_egress_.sz       = sizeof(opts_egress_);
    opts_egress_.prog_fd  = bpf_program__fd(skel_->progs.tc_egress);
    opts_egress_.priority = egress_prio;
    opts_egress_.handle   = NETMON_TC_HANDLE_DEFAULT;

    err = bpf_tc_attach(&hook_egress_, &opts_egress_);
    if (err) {
        std::cerr << "Error: Failed to attach egress TC filter: "
                  << std::strerror(-err) << "\n";
        stop();
        return false;
    }
    attached_egress_ = true;

    // 5. Setup ring buffer consumer
    rb_ = ring_buffer__new(bpf_map__fd(skel_->maps.rb),
                           handle_event, this, nullptr);
    if (!rb_) {
        std::cerr << "Error: Failed to create ring buffer.\n";
        stop();
        return false;
    }

    stats_.start_time = std::chrono::steady_clock::now();
    running_ = true;

    print_header_banner();
    print_table_header();

    return true;
}

// ─── stop() ───────────────────────────────────────────────────────────────────
void NetworkMonitor::stop()
{
    running_ = false;

    if (rb_) {
        ring_buffer__free(rb_);
        rb_ = nullptr;
    }

    if (attached_ingress_) {
        opts_ingress_.flags   = 0;
        opts_ingress_.prog_fd = 0;
        opts_ingress_.prog_id = 0;
        int err = bpf_tc_detach(&hook_ingress_, &opts_ingress_);
        if (err) {
            std::cerr << "Warning: Failed to detach ingress TC filter: "
                      << std::strerror(-err) << "\n";
        }
        attached_ingress_ = false;
    }

    if (attached_egress_) {
        opts_egress_.flags   = 0;
        opts_egress_.prog_fd = 0;
        opts_egress_.prog_id = 0;
        int err = bpf_tc_detach(&hook_egress_, &opts_egress_);
        if (err) {
            std::cerr << "Warning: Failed to detach egress TC filter: "
                      << std::strerror(-err) << "\n";
        }
        attached_egress_ = false;
    }

    if (hook_created_) {
        bpf_tc_hook_destroy(&hook_ingress_);
        hook_created_ = false;
    }

    if (skel_) {
        netmon_bpf__destroy(skel_);
        skel_ = nullptr;
    }
}

// ─── poll() ───────────────────────────────────────────────────────────────────
void NetworkMonitor::poll(int timeout_ms)
{
    if (!running_ || !rb_) return;
    int res = ring_buffer__poll(rb_, timeout_ms);
    if (res < 0 && res != -EINTR) {
        std::cerr << "Error while polling ring buffer: "
                  << std::strerror(-res) << "\n";
    }
}

// ─── Ring buffer callback ─────────────────────────────────────────────────────
int NetworkMonitor::handle_event(void *ctx, void *data, size_t data_sz)
{
    auto *self = static_cast<NetworkMonitor *>(ctx);
    self->process_event(data, data_sz);
    return 0;
}

// ─── process_event() ─────────────────────────────────────────────────────────
void NetworkMonitor::process_event(const void *data, size_t data_sz)
{
    // Sanity / boundary check for received event buffer
    if (data_sz < sizeof(struct packet_event)) {
        ++stats_.malformed_dropped;
        return;
    }

    const auto *ev = static_cast<const struct packet_event *>(data);

    // Validate plausible packet length (minimum Ethernet + IPv4 = 34 bytes)
    if (ev->packet_len < 34 || ev->packet_len > 65535) {
        ++stats_.malformed_dropped;
        return;
    }

    // ── Update raw statistics (always, regardless of filter) ──
    ++stats_.total_received;
    stats_.total_bytes += ev->packet_len;
    if (ev->direction == DIR_INGRESS) ++stats_.ingress_count;
    else                              ++stats_.egress_count;

    // ── Direction Filter ──
    if (config_.dir_filter == DirectionFilter::INGRESS_ONLY && ev->direction != DIR_INGRESS) {
        return;
    }
    if (config_.dir_filter == DirectionFilter::EGRESS_ONLY && ev->direction != DIR_EGRESS) {
        return;
    }

    // ── Protocol Filter ──
    if (config_.proto_filter == ProtocolFilter::TCP && ev->protocol != NETMON_PROTO_TCP) {
        return;
    }
    if (config_.proto_filter == ProtocolFilter::UDP && ev->protocol != NETMON_PROTO_UDP) {
        return;
    }
    if (config_.proto_filter == ProtocolFilter::ICMP && ev->protocol != NETMON_PROTO_ICMP) {
        return;
    }

    // ── IPv4 Endpoint Filter ──
    if (config_.filter_ip != 0) {
        uint32_t src_host = ntohl(ev->src_ip);
        uint32_t dst_host = ntohl(ev->dst_ip);
        if (src_host != config_.filter_ip && dst_host != config_.filter_ip) {
            return;
        }
    }

    // ── Port Filter (applies to TCP and UDP; ICMP has no ports) ──
    if (config_.filter_port != 0) {
        if (ev->protocol != NETMON_PROTO_TCP && ev->protocol != NETMON_PROTO_UDP) {
            return;
        }
        uint16_t src_p = ntohs(ev->src_port);
        uint16_t dst_p = ntohs(ev->dst_port);
        if (src_p != config_.filter_port && dst_p != config_.filter_port) {
            return;
        }
    }

    // Check packet limit (stop displaying if max count reached)
    if (config_.max_packet_count > 0 && stats_.total_displayed >= config_.max_packet_count) {
        return;
    }

    ++stats_.total_displayed;

    // ── Format timestamp ─────────────────────────────────────────────────────
    uint64_t wall_ns = boot_to_realtime_ns_ + ev->timestamp_ns;
    time_t sec = static_cast<time_t>(wall_ns / 1000000000ULL);
    struct tm tm_info{};
    localtime_r(&sec, &tm_info);

    char time_buf[16];
    std::strftime(time_buf, sizeof(time_buf), "%H:%M:%S", &tm_info);

    // ── Format IP addresses & ports ──────────────────────────────────────────
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ev->src_ip, src_ip_str, sizeof(src_ip_str));
    inet_ntop(AF_INET, &ev->dst_ip, dst_ip_str, sizeof(dst_ip_str));

    std::string src_ep = src_ip_str;
    std::string dst_ep = dst_ip_str;
    std::string proto_str;

    if (ev->protocol == NETMON_PROTO_TCP) {
        proto_str = "TCP";
        src_ep += ":" + std::to_string(ntohs(ev->src_port));
        dst_ep += ":" + std::to_string(ntohs(ev->dst_port));
    } else if (ev->protocol == NETMON_PROTO_UDP) {
        proto_str = "UDP";
        src_ep += ":" + std::to_string(ntohs(ev->src_port));
        dst_ep += ":" + std::to_string(ntohs(ev->dst_port));
    } else if (ev->protocol == NETMON_PROTO_ICMP) {
        proto_str = "ICMP";
    } else {
        proto_str = "PROTO-" + std::to_string(ev->protocol);
    }

    std::string size_str = format_size(ev->packet_len);

    // ── Direction label ──────────────────────────────────────────────────────
    std::string dir_str = (ev->direction == DIR_INGRESS) ? "IN " : "OUT";

    // ── Output line ───────────────────────────────────────────────────────────
    if (config_.use_color) {
        auto pad_right = [](const std::string &s, int w) -> std::string {
            if (static_cast<int>(s.size()) >= w)
                return s.substr(0, static_cast<size_t>(w));
            return s + std::string(static_cast<size_t>(w - static_cast<int>(s.size())), ' ');
        };

        std::cout
            << Color::DIM   << time_buf    << Color::RESET << "  "
            << dir_color(ev->direction) << Color::BOLD << dir_str << Color::RESET << "  "
            << proto_color(ev->protocol) << pad_right(proto_str, 8) << Color::RESET
            << pad_right(src_ep,  22)
            << pad_right(dst_ep,  22)
            << std::right << std::setw(7) << size_str
            << "\n" << std::flush;
    } else {
        std::cout << std::left
                  << std::setw(10) << time_buf
                  << std::setw(5)  << dir_str
                  << std::setw(9)  << proto_str
                  << std::setw(22) << src_ep
                  << std::setw(22) << dst_ep
                  << std::right << std::setw(7) << size_str
                  << "\n" << std::flush;
    }
}

// ─── print_summary() ─────────────────────────────────────────────────────────
void NetworkMonitor::print_summary() const
{
    auto dim = [&](const std::string &s) -> std::string {
        return config_.use_color ? (std::string(Color::DIM) + s + Color::RESET) : s;
    };
    auto bold = [&](const std::string &s) -> std::string {
        return config_.use_color ? (std::string(Color::BOLD) + s + Color::RESET) : s;
    };

    double elapsed_sec = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - stats_.start_time).count();
    if (elapsed_sec < 0.001) elapsed_sec = 0.001;

    double rcvd_pps = stats_.total_received / elapsed_sec;
    double disp_pps = stats_.total_displayed / elapsed_sec;
    double byte_rate = stats_.total_bytes / elapsed_sec;

    std::cout << "\n" << dim(repeat_utf8("─", 76)) << "\n";
    std::cout << bold("Session Summary\n");

    std::ostringstream dur_oss;
    dur_oss << std::fixed << std::setprecision(1) << elapsed_sec << "s";
    std::cout << "  Duration          : " << dur_oss.str() << "\n";

    std::ostringstream rcvd_oss;
    rcvd_oss << stats_.total_received << " (" << std::fixed << std::setprecision(1) << rcvd_pps << " pkts/s)";
    std::cout << "  Packets received  : " << rcvd_oss.str() << "\n";

    std::ostringstream disp_oss;
    disp_oss << stats_.total_displayed << " (" << std::fixed << std::setprecision(1) << disp_pps << " pkts/s)";
    std::cout << "  Packets displayed : " << disp_oss.str() << "\n";

    std::cout << "  Ingress           : " << stats_.ingress_count   << "\n";
    std::cout << "  Egress            : " << stats_.egress_count    << "\n";

    std::cout << "  Total bytes       : "
              << format_size(static_cast<uint32_t>(std::min(stats_.total_bytes, static_cast<uint64_t>(UINT32_MAX))))
              << " (" << format_rate(byte_rate) << ")\n";

    if (stats_.malformed_dropped > 0) {
        std::cout << "  Malformed/dropped : " << stats_.malformed_dropped << "\n";
    }

    // Active filters summary
    std::vector<std::string> active_filters;
    if (config_.filter_ip != 0) {
        struct in_addr a{};
        a.s_addr = htonl(config_.filter_ip);
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &a, buf, sizeof(buf));
        active_filters.push_back("IP=" + std::string(buf));
    }
    if (config_.filter_port != 0) {
        active_filters.push_back("Port=" + std::to_string(config_.filter_port));
    }
    if (config_.proto_filter == ProtocolFilter::TCP) active_filters.push_back("Proto=TCP");
    else if (config_.proto_filter == ProtocolFilter::UDP) active_filters.push_back("Proto=UDP");
    else if (config_.proto_filter == ProtocolFilter::ICMP) active_filters.push_back("Proto=ICMP");

    if (config_.dir_filter == DirectionFilter::INGRESS_ONLY) active_filters.push_back("Dir=IN");
    else if (config_.dir_filter == DirectionFilter::EGRESS_ONLY) active_filters.push_back("Dir=OUT");

    if (config_.max_packet_count > 0) {
        active_filters.push_back("Limit=" + std::to_string(config_.max_packet_count));
    }

    if (active_filters.empty()) {
        std::cout << "  Active filters    : none (captured all IPv4 TCP/UDP/ICMP)\n";
    } else {
        std::cout << "  Active filters    : ";
        for (size_t i = 0; i < active_filters.size(); ++i) {
            std::cout << active_filters[i] << (i + 1 < active_filters.size() ? " | " : "\n");
        }
    }

    std::cout << "  TC Filters        : Detached ingress/egress (pref "
              << opts_ingress_.priority << ", handle " << opts_ingress_.handle << ")\n";
    std::cout << "  TC Qdisc          : "
              << (qdisc_preexisted_ ? "Preserved existing clsact" : "Cleaned up created clsact")
              << "\n";
    std::cout << std::flush;
}
