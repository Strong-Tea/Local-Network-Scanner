#include <iostream>
#include <Winsock2.h>
#include <iphlpapi.h>
#include <string>
#include <ws2tcpip.h>
#include <future>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma warning(disable:4996)

#define FUTURE_ARRAY_SIZE 40

using namespace std;


/**
 * \brief Getting the device name by ipv4 address.
 *
 * \context The gethostbyaddr function is used to retrieve the host information associated with a given IP address.
 * It performs a reverse DNS lookup to find the hostname corresponding to the provided IP address.
 * However, there are a few reasons why gethostbyaddr might return NULL:
 * Reverse DNS not configured, DNS resolution issues, Firewall or security settings.
 *
 * \return If the function completes successfully, it returns true,
 * otherwise it returns false.
 */
bool get_name(unsigned char* name, char dest[32])
{
    struct in_addr destip;
    struct hostent* info;

    destip.s_addr = inet_addr(dest);

    info = gethostbyaddr((char*)&destip, 4, AF_INET);

    if (info == NULL)
        return false;

    strcpy((char*)name, info->h_name);

    return true;
}


/**
 * \brief Getting a mac address
 *
 * \context The SendARP function sends an Address Resolution Protocol (ARP) request to obtain
 * the physical address that corresponds to the specified destination IPv4 address.
 *
 * \return If the function completes successfully, it returns true,
 * otherwise it returns false.
 */
bool get_mac(unsigned char* mac, char dest[32])
{
    struct in_addr destip;
    ULONG mac_address[2];
    ULONG mac_address_len = 6;

    destip.s_addr = inet_addr(dest);

    SendARP((IPAddr)destip.S_un.S_addr, 0, mac_address, &mac_address_len);

    if (!mac_address_len)
        return false;

    BYTE* mac_address_buffer = (BYTE*)&mac_address;
    for (int i = 0; i < (int)mac_address_len; i++)
        mac[i] = (char)mac_address_buffer[i];

    return true;
}


/**
 * \brief The function checks the IP address in the local network.
 *
 * \context This function is run in a separate thread because of Future.
 * If the device is online, then we get the mac address of the device and its name.
 *
 * \return The function returns information about the device that is online.
 */
string checkAddress(uint32_t uaddress) {
    struct in_addr addr;
    char ipAddress[16];
    unsigned char mac[6] = { '\0' };
    char result[256] = { '\0' };
    unsigned char name[100] = { '\0' };

    addr.s_addr = htonl(uaddress);

    strcpy(ipAddress, inet_ntoa(addr));

    if (get_mac(mac, ipAddress)) {
        sprintf(result, "IP: %s\tMAC-ADDRESS: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\t NAME: %s\n", ipAddress, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], (get_name(name, ipAddress)) ? (char*)name : "NONE");
    }

    return result;
}


/**
 * \brief The function checks the IP address in the local network.
 *
 * \context The function that initializes Winsock gets network adapters,
 * calculates the range of ip addresses to check the local network and their subnet mask,
 * performs tasks using Future and displays the result on the screen.
 *
 * \return If the function was executed successfully, it returns 0.
 */
int main() {

    WSADATA wsaData;

    struct in_addr hostAddr;
    struct in_addr subnetMask;
    struct in_addr networkAddr;
    struct hostent* host;
    char hostname[NI_MAXHOST];
    string ipAddress;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cout << "Failed to initialize Winsock." << endl;
        return 1;
    }

    if (gethostname(hostname, NI_MAXHOST) != 0) {
        cout << "Error getting hostname." << endl;
        return 1;
    }

    host = gethostbyname(hostname);
    if (host == nullptr) {
        cout << "Error getting host information." << endl;
        return 1;
    }

    if (host->h_addrtype != AF_INET) {
        cout << "Unsupported address type." << endl;
        return 1;
    }

    hostAddr = *(reinterpret_cast<in_addr*>(*(host->h_addr_list)));
    ipAddress = inet_ntoa(hostAddr);

    ULONG adapterInfoSize = 0;
    if (GetAdaptersInfo(nullptr, &adapterInfoSize) != ERROR_BUFFER_OVERFLOW) {
        cout << "Failed to retrieve network adapter information." << endl;
        return 1;
    }

    PIP_ADAPTER_INFO adapterInfo = static_cast<IP_ADAPTER_INFO*>(malloc(adapterInfoSize));
    if (adapterInfo == nullptr) {
        cout << "Failed to allocate memory for adapter info." << endl;
        return 1;
    }

    if (GetAdaptersInfo(adapterInfo, &adapterInfoSize) != NO_ERROR) {
        cout << "Failed to retrieve network adapter information." << endl;
        free(adapterInfo);
        return 1;
    }

    uint32_t mask;
    uint32_t networkIP;
    uint32_t networkMin;
    uint32_t networkMax;
    IP_ADAPTER_INFO* adapter = adapterInfo;

    while (adapter) {
        IP_ADDR_STRING* ipAddressString = &adapter->IpAddressList;
        while (ipAddressString) {
            if (ipAddress == ipAddressString->IpAddress.String) {
                subnetMask.S_un.S_addr = inet_addr(ipAddressString->IpMask.String);
                mask = ntohl(subnetMask.S_un.S_addr);
                networkIP = ntohl(hostAddr.S_un.S_addr) & mask;
                networkAddr.s_addr = htonl(networkIP);
                networkMin = networkIP & mask;
                networkMax = networkMin | (~mask);
                break;
            }
            ipAddressString = ipAddressString->Next;
        }
        adapter = adapter->Next;
    }

    std::cout << "Hostname: " << hostname << std::endl;
    std::cout << "IP Address: " << ipAddress << std::endl;
    std::cout << "Subnet Mask: " << inet_ntoa(subnetMask) << std::endl;
    std::cout << "Network IP: " << inet_ntoa(networkAddr) << std::endl;
    std::cout << "--------------------------------------" << std::endl;

    // Iterate over IP addresses from any range. for example 192.168.100.1 - 192.168.100.254 /24
    std::future<string> futureArray[FUTURE_ARRAY_SIZE];
    for (uint32_t address = networkMin; address < networkMax; address) {
        int count = 0;
        for (; count < FUTURE_ARRAY_SIZE; count++) {
            if (++address >= networkMax)
                break;

            futureArray[count] = async(launch::async, checkAddress, address);
        }

        for (int i = 0; i < count; i++) {
            cout << futureArray[i].get();
        }
    }

    free(adapterInfo);
    WSACleanup();

    return 0;
}