#include <unistd.h>
#include <iostream>
#include <sys/stat.h>
#include <string>
#include <cmath>
#include <ctime>
#include <unordered_map>
#include <vector>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include "SystemUtils.h"
#include "Layer.h"
#include "Packet.h"
#include "ProtocolType.h"
#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "HttpLayer.h"
#include "IcmpLayer.h"
#include "ArpLayer.h"
#include "PacketTrailerLayer.h"


using namespace pcpp;
using namespace std;


const int size_of_buffer = 500;
int current_index = 0;
int index_of_writing = 0;

// Files to write captured data's
char files_to_write[5][51] = {  "/etc/firewall/csv-files/network_traffic1.csv", 
                                "/etc/firewall/csv-files/network_traffic2.csv", 
                                "/etc/firewall/csv-files/network_traffic3.csv",
                                "/etc/firewall/csv-files/network_traffic4.csv", 
                                "/etc/firewall/csv-files/network_traffic5.csv" };

// Index of files to write captured data's
int csv_counter = 0;



struct packet_stats
{
    uint64_t packetcount = 0;
    pcpp::IPAddress src_ip;
    uint64_t src_port;
    pcpp::IPAddress dest_ip;
    uint64_t dest_port;
    uint64_t protocol;
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t num_pkts_in;
    uint64_t num_pkts_out;
    _Float64 entropy;
    _Float64 total_entropy;
    _Float64 avg_ipt;
    uint64_t time_start;
    uint64_t time_end;
    uint64_t duration;
};

packet_stats last_packet_stats[size_of_buffer];

PcapLiveDevice* open_interface(std::string interface_name, PcapLiveDevice* dev)
{
    // Open network interface
    dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interface_name);
    if (dev == nullptr)
    {
        cerr << "Network interface not found." << endl;
        exit(1);
    }
    else
    {
        return dev;
    }
}


//
_Float64 get_packet_arrival_time(pcpp::Packet& packet) {
    timespec timestamp = packet.getRawPacket()->getPacketTimeStamp();
    _Float64 time_start = static_cast<double>(timestamp.tv_sec) + (static_cast<double>(timestamp.tv_nsec) / 1000000000.0);
    return time_start;
}


//
_Float64 calculate_entropy_bit(Packet& packet) {
    uint32_t length = packet.getRawPacket()->getRawDataLen();
    const uint8_t* data = packet.getRawPacket()->getRawData();
    double freq[256] = {0};
    for (uint32_t i = 0; i < length; i++) {
        freq[data[i]]++;
    }
    _Float64 entropy = 0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p = freq[i] / length;
        entropy -= p * log2(p);
    }
    return entropy;
}


//
_Float64 calculate_tcp_entropy(pcpp::Packet& packet)
{
    pcpp::TcpLayer* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
    if (!tcpLayer)
        return 0.0;

    pcpp::PacketTrailerLayer* trailerLayer = packet.getLayerOfType<pcpp::PacketTrailerLayer>();
    size_t payloadLength = trailerLayer ? trailerLayer->getTrailerLen() : tcpLayer->getLayerPayloadSize();

    std::map<uint8_t, size_t> byteCounts;
    for (size_t i = 0; i < payloadLength; i++)
    {
        uint8_t byte = *(tcpLayer->getLayerPayload() + i);
        byteCounts[byte]++;
    }

    _Float64 entropy = 0.0;
    for (auto it = byteCounts.begin(); it != byteCounts.end(); it++)
    {
        _Float64 p = static_cast<double>(it->second) / payloadLength;
        entropy -= p * log2(p);
    }

    return entropy;
}


//
_Float64 calculate_udp_entropy(pcpp::Packet& packet)
{
    pcpp::UdpLayer* udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
    if (!udpLayer)
        return 0.0;

    pcpp::PacketTrailerLayer* trailerLayer = packet.getLayerOfType<pcpp::PacketTrailerLayer>();
    size_t payloadLength = trailerLayer ? trailerLayer->getTrailerLen() : udpLayer->getLayerPayloadSize();

    std::map<uint8_t, size_t> byteCounts;
    for (size_t i = 0; i < payloadLength; i++)
    {
        uint8_t byte = *(udpLayer->getLayerPayload() + i);
        byteCounts[byte]++;
    }

    _Float64 entropy = 0.0;
    for (auto it = byteCounts.begin(); it != byteCounts.end(); it++)
    {
        _Float64 p = static_cast<double>(it->second) / payloadLength;
        entropy -= p * log2(p);
    }

    return entropy;
}


//
_Float64 calculate_icmp_entropy(pcpp::Packet& packet)
{
    pcpp::IcmpLayer* icmpLayer = packet.getLayerOfType<pcpp::IcmpLayer>();
    if (!icmpLayer)
        return 0.0;

    pcpp::PacketTrailerLayer* trailerLayer = packet.getLayerOfType<pcpp::PacketTrailerLayer>();
    size_t payloadLength = trailerLayer ? trailerLayer->getTrailerLen() : icmpLayer->getLayerPayloadSize();

    std::map<uint8_t, size_t> byteCounts;
    for (size_t i = 0; i < payloadLength; i++)
    {
        uint8_t byte = *(icmpLayer->getLayerPayload() + i);
        byteCounts[byte]++;
    }

    _Float64 entropy = 0.0;
    for (auto it = byteCounts.begin(); it != byteCounts.end(); it++)
    {
        _Float64 p = static_cast<double>(it->second) / payloadLength;
        entropy -= p * log2(p);
    }

    return entropy;
}


//
_Float64 calculate_arp_entropy(pcpp::Packet& packet)
{
    // ARP header'i yakalayalım
    pcpp::ArpLayer* arpLayer = packet.getLayerOfType<pcpp::ArpLayer>();
    if (!arpLayer) {
        // ARP katmanı yoksa entropi hesaplanamaz
        return 0;
    }

    // ARP mesajında kullanılan tüm byte'ları bir diziye ekleyelim
    std::vector<uint8_t> bytes;
    bytes.reserve(arpLayer->getHeaderLen());
    bytes.insert(bytes.end(), arpLayer->getSenderMacAddress().getRawData(), arpLayer->getSenderMacAddress().getRawData()+6);
    bytes.insert(bytes.end(), arpLayer->getTargetMacAddress().getRawData(), arpLayer->getTargetMacAddress().getRawData()+6);
    bytes.insert(bytes.end(), arpLayer->getSenderIpAddr().toBytes(), arpLayer->getSenderIpAddr().toBytes()+4);
    bytes.insert(bytes.end(), arpLayer->getTargetIpAddr().toBytes(), arpLayer->getTargetIpAddr().toBytes()+4);

    // Byte'ların sıklığını sayalım
    std::unordered_map<uint8_t, int> byteCount;
    for (uint8_t b : bytes) {
        byteCount[b]++;
    }

    // Entropiyi hesaplayalım
    _Float64 entropy = 0;
    int numBytes = bytes.size();
    for (auto& pair : byteCount) {
        _Float64 p = static_cast<double>(pair.second) / numBytes;
        entropy -= p * std::log2(p);
    }

    return entropy; // Entropiyi bit/byte cinsinden döndürelim
}


//
uint64_t index_of_flow(pcpp::Packet& packet, pcpp::IPAddress src_ip, uint16_t src_port, pcpp::IPAddress dest_ip, uint16_t dest_port, uint64_t protocol)
{
    uint64_t index = 255;
    for (uint64_t i = 0; i < size_of_buffer; i++)
    {
        if ((last_packet_stats[i].src_ip == src_ip || last_packet_stats[i].src_ip == dest_ip) &&
            (last_packet_stats[i].dest_ip == dest_ip || last_packet_stats[i].dest_ip == src_ip) &&
            (last_packet_stats[i].src_port == src_port || last_packet_stats[i].src_port == dest_port) &&
            (last_packet_stats[i].dest_port == dest_port || last_packet_stats[i].dest_port == src_port) &&
            last_packet_stats[i].protocol == protocol)
        {
            index = i;
            break;
        }
    }
    return index;
}


//
bool is_ip_in_range(pcpp::IPAddress src_ip)
{
    pcpp::IPAddress minIP = IPAddress("192.168.1.100");
    pcpp::IPAddress maxIP = IPAddress("192.168.1.200");

    return (minIP.operator<(src_ip) && src_ip.operator<(maxIP));
}


//
uint64_t get_packet_bytes_in(pcpp::Packet& packet, pcpp::IPAddress src_ip)
{
    if (is_ip_in_range(src_ip))
    {
        return packet.getRawPacket()->getRawDataLen();
    }
    
    return 0; 
}


//
bool is_packet_going_out(pcpp::IPAddress src_ip)
{
    if (is_ip_in_range(src_ip))
    {
        return true;
    }
    
    return false;
}


//
uint64_t get_packet_bytes_out(pcpp::Packet& packet, pcpp::IPAddress src_ip)
{
    if (is_ip_in_range(src_ip))
    {
        return 0;
    }

    return packet.getRawPacket()->getRawDataLen();
}


// a function for the returning the number associated with the given packets protocol type
uint64_t get_protocol_type(pcpp::Packet& packet)
{
    if (packet.isPacketOfType(pcpp::TCP))
    {
        return 6; //  TCP protokolü numarası
    }
    else if (packet.isPacketOfType(pcpp::UDP))
    {
        return 17; //  UDP protokolü numarası
    }
    else if (packet.isPacketOfType(pcpp::ICMP))
    {
        return 1; //  ICMP protokolü numarası
    }
    else if (packet.isPacketOfType(pcpp::ARP))
    {
        return 2054; //  ARP protokolü numarası
    }
    else if (packet.isPacketOfType(pcpp::IPv4))
    {
        return 4; //  IPv4 protokolü numarası
    }
    else if (packet.isPacketOfType(pcpp::IPv6))
    {
        return 41; //  IPv6 protokolü numarası
    }
    else if (packet.isPacketOfType(pcpp::HTTPRequest))
    {
        return 72; //  HTTP request protokolü numarası
    }
    else if (packet.isPacketOfType(pcpp::HTTPResponse))
    {
        return 73; //  HTTP response protokolü numarası
    }
    else if (packet.isPacketOfType(pcpp::DNS))
    {
        return 53; //  DNS protokolü numarası
    }
    else if (packet.isPacketOfType(pcpp::MPLS))
    {
        return 34887; //  MPLS protokolü numarası
    }
    else if (packet.isPacketOfType(pcpp::PPP_PPTP))
    {
        return 34827; //  PPP_PPTP protokolü numarası
    }
    else if (packet.isPacketOfType(pcpp::SSL))
    {
        return 443; //  SSL protokolü numarası
    }
    else if (packet.isPacketOfType(pcpp::DHCP))
    {
        return 67; //  DHCP protokolü numarası
    }
    else if (packet.isPacketOfType(pcpp::IGMP))
    {
        return 2; //  IGMP protokolü numarası
    }
    else if (packet.isPacketOfType(pcpp::VXLAN))
    {
        return 4789; //  VXLAN protokolü numarası
    }
    else if (packet.isPacketOfType(pcpp::SIPRequest))
    {
        return 5060; //  SIP request protokolü numarası
    }
    else if (packet.isPacketOfType(pcpp::SIPResponse))
    {
        return 5060; //  SIP response protokolü numarası
    }
    else if (packet.isPacketOfType(pcpp::Radius))
    {
        return 1812;
    }
    else if (packet.isPacketOfType(pcpp::GTP))
    {
        return 2123;
    }
    else if (packet.isPacketOfType(pcpp::BGP))
    {
        return 179;
    }
    else if (packet.isPacketOfType(pcpp::SSH))
    {
        return 22;
    }
    else if (packet.isPacketOfType(pcpp::AuthenticationHeader))
    {
        return 51;
    }
    else if (packet.isPacketOfType(pcpp::ESP))
    {
        return 50;
    }
    else if (packet.isPacketOfType(pcpp::IPSec))
    {
        return 0;
    }
    else if (packet.isPacketOfType(pcpp::DHCPv6))
    {
        return 546;
    }
    else
    {
        return pcpp::UnknownProtocol;
    }
}


// a function for the returning source IP address of given packet
pcpp::IPAddress get_src_IP_address(pcpp::Packet& packet)
{
    pcpp::IPLayer* ip_layer = packet.getLayerOfType<pcpp::IPLayer>();
    if (ip_layer == NULL)
    {
        std::cerr << "Something went wrong, couldn't find IP layer" << std::endl;
        return (pcpp::IPAddress)"0";
    }
    else
    {
        return ip_layer->getSrcIPAddress();
    }
}


// a function for the returning destination IP adress of given packet
pcpp::IPAddress get_dest_IP_address(pcpp::Packet& packet)
{
    pcpp::IPLayer* ip_layer = packet.getLayerOfType<pcpp::IPLayer>();
    if (ip_layer == NULL)
    {
        std::cerr << "Something went wrong, couldn't find IP layer" << std::endl;
        return (pcpp::IPAddress)"0";
    }
    else
    {
        return ip_layer->getDstIPAddress();
    }
}


// a function for the returning source port number of given packet
uint64_t get_src_port_numbers(pcpp::Packet& packet)
{
    if (packet.isPacketOfType(pcpp::TCP))
    {
        return packet.getLayerOfType<pcpp::TcpLayer>()->getDstPort();
    }
    if (packet.isPacketOfType(pcpp::UDP))
    {
        return packet.getLayerOfType<pcpp::UdpLayer>()->getSrcPort();
    }
    else
    {
        return 0;
    }
}


// a function for the returning destination port number of given packet
uint64_t get_dest_port_numbers(pcpp::Packet& packet)
{
    if (packet.isPacketOfType(pcpp::TCP))
    {
        return packet.getLayerOfType<pcpp::TcpLayer>()->getSrcPort();
    }
    if (packet.isPacketOfType(pcpp::UDP))
    {
        return packet.getLayerOfType<pcpp::UdpLayer>()->getDstPort();
    }
    else
    {
        return 0;
    }
}


// a function for the write the statistic of a flow to .csv file
void write_data_to_csv(const packet_stats& stats)
{
    std::ofstream outfile(files_to_write[csv_counter], std::ios::app); // open file in append mode
    if (outfile.is_open())
    {
        // write data to file
        outfile << stats.src_ip << ","
                << stats.src_port << ","
                << stats.dest_ip << ","
                << stats.dest_port << ","
                << stats.protocol << ","
                << stats.bytes_in << ","
                << stats.bytes_out << ","
                << stats.num_pkts_in << ","
                << stats.num_pkts_out << ","
                << stats.entropy << ","
                << stats.total_entropy << ","
                << stats.avg_ipt << ","
                << stats.time_start << ","
                << stats.time_end << ","
                << stats.duration << std::endl;

        outfile.close(); // close the file
    }
    else
    {
        std::cerr << "Error: Unable to open file for writing!" << std::endl;
    }
}


// a function for the consume statistics of the captured packet
void consume_packet(pcpp::Packet parsedPacket)
{
    bool should_write = false;
    packet_stats stats2;
    stats2.time_start = get_packet_arrival_time(parsedPacket);
    for (int i = 0; i < size_of_buffer; i++)
    {
        if (stats2.time_start - last_packet_stats[i].time_start > 100.0 && last_packet_stats[i].time_start != 0)
        {
            index_of_writing = i;
            should_write = true;
            current_index = i;
        }
    }
    if (should_write)
    {
        last_packet_stats[index_of_writing].entropy = last_packet_stats[index_of_writing].entropy / last_packet_stats[index_of_writing].packetcount;
        last_packet_stats[index_of_writing].avg_ipt = last_packet_stats[index_of_writing].avg_ipt / (last_packet_stats[index_of_writing].packetcount - 1);
        write_data_to_csv(last_packet_stats[index_of_writing]);
        memset(&last_packet_stats[index_of_writing], 0, sizeof(last_packet_stats[index_of_writing]));
    }

    // collect stats from packet
    stats2.time_start = get_packet_arrival_time(parsedPacket);
    stats2.time_end = get_packet_arrival_time(parsedPacket);
    stats2.packetcount = 1;
    stats2.src_ip = get_src_IP_address(parsedPacket);
    stats2.dest_ip = get_dest_IP_address(parsedPacket);
    stats2.src_port = get_src_port_numbers(parsedPacket);
    stats2.dest_port = get_dest_port_numbers(parsedPacket);
    stats2.protocol = get_protocol_type(parsedPacket);
    stats2.bytes_in = get_packet_bytes_in(parsedPacket, stats2.src_ip);
    stats2.bytes_out = get_packet_bytes_out(parsedPacket, stats2.src_ip);
    if (is_packet_going_out(stats2.src_ip))
    {
        stats2.num_pkts_in = 0;
        stats2.num_pkts_out = 1;   
    }
    else
    {
        stats2.num_pkts_in = 1;
        stats2.num_pkts_out = 0;
    }
    stats2.entropy = calculate_entropy_bit(parsedPacket);
    if (stats2.protocol == 6)
    {
        stats2.total_entropy = calculate_tcp_entropy(parsedPacket);
    }
    else if (stats2.protocol == 17)
    {
        stats2.total_entropy = calculate_udp_entropy(parsedPacket);
    }
    else if (stats2.protocol == 1)
    {
        stats2.total_entropy = calculate_arp_entropy(parsedPacket);
    }
    else if (stats2.protocol == 2054)
    {
        stats2.total_entropy = calculate_icmp_entropy(parsedPacket);
    }
    stats2.avg_ipt = 0;
    stats2.duration = 0;
    std::string is_new_flow;
    uint8_t idx_of_flow = index_of_flow(parsedPacket, stats2.src_ip, stats2.src_port, stats2.dest_ip, stats2.dest_port, stats2.protocol);
    if(idx_of_flow == 255)
    {
        last_packet_stats[current_index] = stats2;
        is_new_flow = "Yes";
        current_index++;
    }
    else
    {
        last_packet_stats[idx_of_flow].packetcount++;
        last_packet_stats[idx_of_flow].bytes_in += stats2.bytes_in;
        last_packet_stats[idx_of_flow].bytes_out += stats2.bytes_out;
        last_packet_stats[idx_of_flow].num_pkts_in += stats2.num_pkts_in;
        last_packet_stats[idx_of_flow].num_pkts_out += stats2.num_pkts_out;
        last_packet_stats[idx_of_flow].entropy += stats2.entropy;
        last_packet_stats[idx_of_flow].total_entropy += stats2.total_entropy;
        last_packet_stats[idx_of_flow].avg_ipt = last_packet_stats[idx_of_flow].avg_ipt + stats2.time_start - last_packet_stats[idx_of_flow].time_start;
        last_packet_stats[idx_of_flow].time_end = stats2.time_end;
        last_packet_stats[idx_of_flow].duration = stats2.time_end - last_packet_stats[idx_of_flow].time_start;
        is_new_flow = "No";
    }

    cout << "\nSource IP:" << stats2.src_ip <<
        "\nDestination IP: " << stats2.dest_ip <<
        "\nSource Port: " << stats2.src_port <<
        "\nDestination Port: " << stats2.dest_port << 
        "\nProtocol: " << stats2.protocol << 
        "\nNew Flow: " << is_new_flow <<
        "\nTime Start: " << stats2.time_start << endl;
}


// A callback function for the async capture which is called each time a packet is captured
static void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
    // extract the stats object form the cookie
    packet_stats* stats = (packet_stats*)cookie;

    // parsed the raw packet
    pcpp::Packet parsedPacket(packet);

    consume_packet(parsedPacket);
}


std::vector<std::string> GetNetworkInterfaces()
{
    std::vector<std::string> interfaces;

    struct ifaddrs* ifAddrStruct = nullptr;
    struct ifaddrs* ifa = nullptr;

    if (getifaddrs(&ifAddrStruct) == 0)
    {
        for (ifa = ifAddrStruct; ifa != nullptr; ifa = ifa->ifa_next)
        {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET)
            {
                std::string interfaceName(ifa->ifa_name);
                interfaces.push_back(interfaceName);
            }
        }
    }

    if (ifAddrStruct)
        freeifaddrs(ifAddrStruct);

    return interfaces;
}


// main function
int main(int argc, char* argv[])
{
    pid_t pid = fork();

    if (pid == 0) {
        // Child process
        const char* args[] = {"python3", "/etc/firewall/predict.py", NULL}; // Name and arguments of the Python code to execute
        execvp("python3", (char* const*)args); // Execute the Python code

        // If execvp function fails, the following code will run
        std::cerr << "An error occurred while executing the Python code!" << std::endl;
        exit(1);
    }

    else if (pid > 0)
    {
    	// Create files and write headers
    	for (int i = 0; i < 5; i++)
    	{
            ofstream file(files_to_write[i]);
            chmod(files_to_write[i], 0666); // adjust permissions
            file << "src_ip,src_port,dest_ip,dest_port,protocol,bytes_in,bytes_out,num_pkts_in,num_pkts_out,entropy,total_entropy,mean_ipt,time_start,time_end,duration\n";
        }


        std::vector<std::string> interfaces = GetNetworkInterfaces();

        std::cout << "Available network interfaces:" << std::endl;
        for (const auto& interface : interfaces)
        {
            std::cout << "- " << interface << std::endl;
        }

        std::string selectedInterface;
        std::cout << "Enter name of the desired network interface: ";
        std::getline(std::cin, selectedInterface);

        // Validate if the selectedInterface exists in the available interfaces list
        bool validInterface = false;
        for (const auto& interface : interfaces)
        {
            if (interface == selectedInterface)
            {
                validInterface = true;
                break;
            }
        }

        if (validInterface)
        {
            // Proceed with the selectedInterface
            std::cout << "Selected network interface: " << selectedInterface << std::endl;
        }
        else
        {
            std::cout << "Invalid network interface selection!" << std::endl;
            return 0;
        }

        // Open interface
        pcpp::PcapLiveDevice* device;
        device = open_interface(selectedInterface, device);

        // Open network interface and start capturing packets
        if (!device->open())
        {
            cerr << "Network interface could not be opened." << endl;
            return 1;
        }

        // create the stats object
        packet_stats stats;

        device->startCapture(onPacketArrives, &stats);
        while (1)
        {
            // sleep for 10 seconds in main thread, in the meantime packets are captured in the async thread
            pcpp::multiPlatformSleep(100);
            csv_counter++;
            if (csv_counter > 4)
            {
                csv_counter = 0;
            }
        }

        // stop capturing packets
        device->stopCapture();
    }
    else
    {
        // If the fork function fails, the following code will run
        std::cerr << "Failed to create a new process!" << std::endl;
        exit(1);
    }
}
