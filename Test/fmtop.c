//gcc fmtop.c -o fmtop -lpcap -lmaxminddb -lpthread 
//fmtop.c
//11
#include "packet_sniffer.h"
#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <math.h>
#define _XOPEN_SOURCE 700
#include <time.h>
#include <unistd.h> 
#include <maxminddb.h>


volatile sig_atomic_t running = 1; 
time_t firstPacketTime = 0; 
time_t lastPacketTime = 0;  
volatile int intervalSeconds = 1; 

volatile uint64_t totalTrafficSize = 0;
pcap_t *handle = NULL;



typedef struct {
    char value[50]; 
    int count;      
} StatItem;

typedef struct {
    StatItem* items; 
    int size;        
    int capacity;    
} StatList;

typedef struct DataNode {
    int single_data; 
    int data; 
    int flowCount; 
    struct FlowNode* flow;
    struct TimeNode* time;
    struct DataNode* nextData;
    struct DataNode* prevData; 
} DataNode;


typedef struct FlowNode {
    char src_IP[50];
    char dst_IP[50];
    int src_port;
    int dst_port;
    char protocol[10];
    int totalData; 
    int flowCount; 
    struct DataNode* datas; 
    struct DataNode* lastData;
    struct FlowNode* nextFlow;
    struct FlowNode* prevFlow;
} FlowNode;


typedef struct TimeNode {
    char timestamp[50];
    FlowNode* flows;
    struct TimeNode* nextTime;
    struct TimeNode* prevTime;
} TimeNode;


typedef struct FlowSummary {
    char src_IP[50];
    char dst_IP[50];
    int src_port;
    int dst_port;
    char protocol[10];
    int totalData; 
} FlowSummary;

typedef struct {
    FlowNode* flow;
    int flowCountDifference;
} FlowCountDiff;


const char* protocolToString(int protocolNum) {
    static char unknownProtocol[30];

    switch (protocolNum) {
        case 0: return "HOPOPT";
        case 1: return "ICMP";
        case 2: return "IGMP";
        case 3: return "GGP";
        case 4: return "IP-in-IP";
        case 5: return "ST";
        case 6: return "TCP";
        case 7: return "CBT";
        case 8: return "EGP";
        case 9: return "IGP";
        case 10: return "BBN-RCC-MON";
        case 11: return "NVP-II";
        case 12: return "PUP";
        case 13: return "ARGUS";
        case 14: return "EMCON";
        case 15: return "XNET";
        case 16: return "CHAOS";
        case 17: return "UDP";
        case 18: return "MUX";
        case 19: return "DCN-MEAS";
        case 20: return "HMP";
        case 21: return "PRM";
        case 22: return "XNS-IDP";
        case 23: return "TRUNK-1";
        case 24: return "TRUNK-2";
        case 25: return "LEAF-1";
        case 26: return "LEAF-2";
        case 27: return "RDP";
        case 28: return "IRTP";
        case 29: return "ISO-TP4";
        case 30: return "NETBLT";
        case 31: return "MFE-NSP";
        case 32: return "MERIT-INP";
        case 33: return "DCCP";
        case 34: return "3PC";
        case 35: return "IDPR";
        case 36: return "XTP";
        case 37: return "DDP";
        case 38: return "IDPR-CMTP";
        case 39: return "TP++";
        case 40: return "IL";
        case 41: return "IPv6";
        case 42: return "SDRP";
        case 43: return "IPv6-Route";
        case 44: return "IPv6-Frag";
        case 45: return "IDRP";
        case 46: return "RSVP";
        case 47: return "GRE";
        case 48: return "DSR";
        case 49: return "BNA";
        case 50: return "ESP";
        case 51: return "AH";
        case 52: return "I-NLSP";
        case 53: return "SWIPE";
        case 54: return "NARP";
        case 55: return "MOBILE";
        case 56: return "TLSP";
        case 57: return "SKIP";
        case 58: return "IPv6-ICMP";
        case 59: return "IPv6-NoNxt";
        case 60: return "IPv6-Opts";
        case 61: return "Any host internal protocol";
        case 62: return "CFTP";
        case 63: return "Any local network";
        case 64: return "SAT-EXPAK";
        case 65: return "KRYPTOLAN";
        case 66: return "RVD";
        case 67: return "IPPC";
        case 68: return "Any distributed file system";
        case 69: return "SAT-MON";
        case 70: return "VISA";
        case 71: return "IPCU";
        case 72: return "CPNX";
        case 73: return "CPHB";
        case 74: return "WSN";
        case 75: return "PVP";
        case 76: return "BR-SAT-MON";
        case 77: return "SUN-ND";
        case 78: return "WB-MON";
        case 79: return "WB-EXPAK";
        case 80: return "ISO-IP";
        case 81: return "VMTP";
        case 82: return "SECURE-VMTP";
        case 83: return "VINES";
        case 84: return "TTP or IPTM";
        case 85: return "NSFNET-IGP";
        case 86: return "DGP";
        case 87: return "TCF";
        case 88: return "EIGRP";
        case 89: return "OSPFIGP";
        case 90: return "Sprite-RPC";
        case 91: return "LARP";
        case 92: return "MTP";
        case 93: return "AX.25";
        case 94: return "IPIP";
        case 95: return "MICP (deprecated)";
        case 96: return "SCC-SP";
        case 97: return "ETHERIP";
        case 98: return "ENCAP";
        case 99: return "Any private encryption scheme";
        case 100: return "GMTP";
        case 101: return "IFMP";
        case 102: return "PNNI";
        case 103: return "PIM";
        case 104: return "ARIS";
        case 105: return "SCPS";
        case 106: return "QNX";
        case 107: return "A/N";
        case 108: return "IPComp";
        case 109: return "SNP";
        case 110: return "Compaq-Peer";
        case 111: return "IPX-in-IP";
        case 112: return "VRRP";
        case 113: return "PGM";
        case 114: return "Any 0-hop protocol";
        case 115: return "L2TP";
        case 116: return "DDX";
        case 117: return "IATP";
        case 118: return "STP";
        case 119: return "SRP";
        case 120: return "UTI";
        case 121: return "SMP";
        case 122: return "SM (deprecated)";
        case 123: return "PTP";
        case 124: return "ISIS over IPv4";
        case 125: return "FIRE";
        case 126: return "CRTP";
        case 127: return "CRUDP";
        case 128: return "SSCOPMCE";
        case 129: return "IPLT";
        case 130: return "SPS";
        case 131: return "PIPE";
        case 132: return "SCTP";
        case 133: return "FC";
        case 134: return "RSVP-E2E-IGNORE";
        case 135: return "Mobility Header";
        case 136: return "UDPLite";
        case 137: return "MPLS-in-IP";
        case 138: return "manet";
        case 139: return "HIP";
        case 140: return "Shim6";
        case 141: return "WESP";
        case 142: return "ROHC";
        default:
            sprintf(unknownProtocol, "Unknown %d", protocolNum); 
            return unknownProtocol;
    }
}



MMDB_s mmdb;
FlowNode* globalFlowsHead = NULL;
TimeNode* headTime = NULL; 
TimeNode* lastTime = NULL; 
StatList srcIPList = {NULL, 0, 10};
StatList dstIPList = {NULL, 0, 10};
StatList srcPortList = {NULL, 0, 10};
StatList dstPortList = {NULL, 0, 10};
StatList protocolList = {NULL, 0, 10};


void handleExitSignal(int sig);
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
FlowNode* findOrAddFlow(char* src_IP, char* dst_IP, int src_port, int dst_port, char* protocol);
TimeNode* findOrAddTimeNode(char* timestamp);
void insertData(FlowNode* flow, TimeNode* time, int data);
void updateFlowAttribute(FlowNode* flow, const char* attribute, int newValue);
void queryFlow(FlowNode* headFlow, const char* src_IP, const char* src_port_str, const char* dst_IP, const char* dst_port_str, const char* protocol, time_t startTime, time_t endTime);
void freeDataNodes(DataNode* headData);
void freeFlowNodes(FlowNode* headFlow);
void freeTimeNodes(TimeNode* headTime);
double calculateDataStructureSizeMB(TimeNode* headTime);
char* getProtocolString(unsigned int protocolNum);
void printDataStructure(TimeNode* headTime);
int compareFlowSummary(const void* a, const void* b);
time_t convertStringToTime(const char* timeStr);


void updateStatList(StatList* list, const char* value) {
    for (int i = 0; i < list->size; ++i) {
        if (strcmp(list->items[i].value, value) == 0) {
            list->items[i].count++;
            return;
        }
    }

    // If the list is full, increase its capacity
    if (list->size == list->capacity) {
        list->capacity *= 2;
        list->items = (StatItem*)realloc(list->items, list->capacity * sizeof(StatItem));
    }

    // Add the new value
    strcpy(list->items[list->size].value, value);
    list->items[list->size].count = 1;
    list->size++;
}



void initializeStatLists() {
    srcIPList.items = (StatItem*)malloc(srcIPList.capacity * sizeof(StatItem));
    srcIPList.size = 0;
    srcIPList.capacity = 10;

    dstIPList.items = (StatItem*)malloc(dstIPList.capacity * sizeof(StatItem));
    dstIPList.size = 0;
    dstIPList.capacity = 10;

    srcPortList.items = (StatItem*)malloc(srcPortList.capacity * sizeof(StatItem));
    srcPortList.size = 0;
    srcPortList.capacity = 10;

    dstPortList.items = (StatItem*)malloc(dstPortList.capacity * sizeof(StatItem));
    dstPortList.size = 0;
    dstPortList.capacity = 10;

    protocolList.items = (StatItem*)malloc(protocolList.capacity * sizeof(StatItem));
    protocolList.size = 0;
    protocolList.capacity = 10;
}


void handleExitSignal(int sig) {
    running = 0;
}

void* capturePackets(void* arg) {
    pcap_t* handle = (pcap_t*)arg;

    pcap_loop(handle, 0, packetHandler, (u_char *)handle);
    return NULL;
}

void accumulateFlowData(FlowNode* flow, int dataSize) {
    if (flow != NULL) {
        flow->totalData += dataSize; 
    }
}


void adjustTimestampForInterval(char* timestamp) {
    struct tm tmTime;
    time_t originalTime, adjustedTime;
int year, month, day, hour, minute, second;

if (sscanf(timestamp, "%d-%d-%d-%d:%d:%d", &year, &month, &day, &hour, &minute, &second) == 6) {
    struct tm tmTime = {0};
    tmTime.tm_year = year - 1900;
    tmTime.tm_mon = month - 1;   
    tmTime.tm_mday = day;
    tmTime.tm_hour = hour;
    tmTime.tm_min = minute;
    tmTime.tm_sec = second;

    time_t originalTime = mktime(&tmTime);
    if (originalTime == -1) {
        fprintf(stderr, "Failed to convert tm to time_t.\n");
        return;
    }

    time_t adjustedTime = originalTime - (originalTime % intervalSeconds);

    struct tm *adjustedTm = localtime(&adjustedTime);
    if (adjustedTm == NULL) {
        fprintf(stderr, "Failed to convert adjusted time_t to tm.\n");
        return;
    }

    snprintf(timestamp, 50, "%04d-%02d-%02d-%02d:%02d:%02d",
             adjustedTm->tm_year + 1900, adjustedTm->tm_mon + 1, adjustedTm->tm_mday,
             adjustedTm->tm_hour, adjustedTm->tm_min, adjustedTm->tm_sec);
} else {
    fprintf(stderr, "Failed to parse timestamp.\n");
}

}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    
     static int packetCount = 0; // 增加一个静态计数器

    // 增加计数器的值
    packetCount++;

    // 检查是否已经处理了1000个包
    if (packetCount >= 100000) {
        pcap_breakloop((pcap_t *)userData); // 停止pcap循环
        return; // 提前退出函数
    }

    const struct ip* ipHeader = (struct ip*)(packet + 14); 
    char srcIP[INET_ADDRSTRLEN], dstIP[INET_ADDRSTRLEN];
    int srcPort = 0, dstPort = 0;
    char protocolStr[10]; 

    inet_ntop(AF_INET, &(ipHeader->ip_src), srcIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIP, INET_ADDRSTRLEN);

    if (ipHeader->ip_p == IPPROTO_TCP) {
        struct tcphdr* tcpHeader = (struct tcphdr*)(packet + 14 + ipHeader->ip_hl * 4);
        srcPort = ntohs(tcpHeader->th_sport);
        dstPort = ntohs(tcpHeader->th_dport);
        strcpy(protocolStr, "TCP");
    } else if (ipHeader->ip_p == IPPROTO_UDP) {
        struct udphdr* udpHeader = (struct udphdr*)(packet + 14 + ipHeader->ip_hl * 4);
        srcPort = ntohs(udpHeader->uh_sport);
        dstPort = ntohs(udpHeader->uh_dport);
        strcpy(protocolStr, "UDP");
    } else {
        strcpy(protocolStr, protocolToString(ipHeader->ip_p));
    }

    char timestamp[50];
    time_t now = time(NULL);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d-%H:%M:%S", localtime(&now));
    adjustTimestampForInterval(timestamp);
    TimeNode* timeNode = findOrAddTimeNode(timestamp);
    FlowNode* flowNode = findOrAddFlow(srcIP, dstIP, srcPort, dstPort, protocolStr);
    accumulateFlowData(flowNode, pkthdr->len); 
    insertData(flowNode, timeNode, pkthdr->len); 
    if (firstPacketTime == 0) {
        firstPacketTime = pkthdr->ts.tv_sec; 
    }
    lastPacketTime = pkthdr->ts.tv_sec; 
    
    char srcPortStr[6], dstPortStr[6];
    sprintf(srcPortStr, "%d", srcPort);
    sprintf(dstPortStr, "%d", dstPort);

    updateStatList(&srcIPList, srcIP);
    updateStatList(&dstIPList, dstIP);
    updateStatList(&srcPortList, srcPortStr);
    updateStatList(&dstPortList, dstPortStr);
    updateStatList(&protocolList, protocolStr);
}





TimeNode* findOrAddTimeNode(char* timestamp) {
    if (headTime == NULL) {
        // No TimeNodes exist, so create the first one.
        TimeNode* newNode = (TimeNode*)malloc(sizeof(TimeNode));
        if (newNode == NULL) {
            fprintf(stderr, "Memory allocation failed for TimeNode.\n");
            exit(EXIT_FAILURE);
        }
        strcpy(newNode->timestamp, timestamp);
        newNode->flows = NULL;
        newNode->nextTime = newNode; // Circular list, points to itself.
        newNode->prevTime = newNode; // Circular list, points to itself.
        headTime = lastTime = newNode;
        return newNode;
    }

    // Search for an existing TimeNode with the same timestamp.
    TimeNode* current = headTime;
    do {
        if (strcmp(current->timestamp, timestamp) == 0) {
            // Found an existing TimeNode, return it.
            return current;
        }
        current = current->nextTime;
    } while (current != headTime); // Continue until we've checked all nodes.

    // If we're here, no matching TimeNode was found. Create a new one.
    TimeNode* newNode = (TimeNode*)malloc(sizeof(TimeNode));
    if (newNode == NULL) {
        fprintf(stderr, "Memory allocation failed for TimeNode.\n");
        exit(EXIT_FAILURE);
    }
    strcpy(newNode->timestamp, timestamp);
    newNode->flows = NULL;
    // Insert the new TimeNode at the end of the circular list.
    newNode->nextTime = headTime; // New node points to the first node.
    newNode->prevTime = lastTime; // New node points to what was the last node.
    lastTime->nextTime = newNode; // Old last node points to new node.
    headTime->prevTime = newNode; // First node points back to new node as prev.
    lastTime = newNode; // Update lastTime to the new node.

    return newNode;
}



FlowNode* findOrAddFlow(char* src_IP, char* dst_IP, int src_port, int dst_port, char* protocol) {
    FlowNode* current = globalFlowsHead;
    while (current != NULL) {
        if (strcmp(current->src_IP, src_IP) == 0 && strcmp(current->dst_IP, dst_IP) == 0 &&
            current->src_port == src_port && current->dst_port == dst_port && strcmp(current->protocol, protocol) == 0) {
            current->flowCount++; // 找到现有流时递增流计数
            return current;
        }
        current = current->nextFlow;
    }

    FlowNode* newNode = (FlowNode*)malloc(sizeof(FlowNode));
    strcpy(newNode->src_IP, src_IP);
    strcpy(newNode->dst_IP, dst_IP);
    newNode->src_port = src_port;
    newNode->dst_port = dst_port;
    strcpy(newNode->protocol, protocol);
    newNode->datas = NULL;
    newNode->totalData = 0;
    newNode->flowCount = 1;
    newNode->nextFlow = globalFlowsHead;
    if (globalFlowsHead != NULL) {
        globalFlowsHead->prevFlow = newNode; // 设置原头节点的前驱指针
    }
    globalFlowsHead = newNode;

    return newNode;
}


time_t adjustTime(time_t baseTime, const char* input) {
    struct tm* timeinfo = localtime(&baseTime);
    int value;
    char unit;

    printf("Original baseTime: %s", asctime(timeinfo));


    if (sscanf(input, "%d%c", &value, &unit) != 2) {
        fprintf(stderr, "Invalid time adjustment input: %s\n", input);
        return -1;
    }


    printf("Adjusting by: %d%c\n", value, unit);


    switch (unit) {
        case 's': timeinfo->tm_sec += value; break;
        case 'm': timeinfo->tm_min += value; break;
        case 'h': timeinfo->tm_hour += value; break;
        case 'd': timeinfo->tm_mday += value; break;
        default:
            fprintf(stderr, "Invalid time adjustment unit: %c\n", unit);
            return -1;
    }


    time_t adjustedTime = mktime(timeinfo);
    printf("Adjusted time: %s", asctime(timeinfo));

    if (adjustedTime == -1) {
        fprintf(stderr, "Error adjusting time.\n");
        return -1;
    }

    return adjustedTime;
}


void insertData(FlowNode* flow, TimeNode* time, int data) {
    if (flow == NULL || time == NULL) {
        fprintf(stderr, "Null flow or time node.\n");
        return;
    }

    // Check if there's already a DataNode for this time
    DataNode* currentData = flow->datas;
    while (currentData != NULL) {
        if (currentData->time == time) {
            // If found, update the data and exit
            currentData->data += data;
            currentData->single_data += data;
            return;
        }
        currentData = currentData->nextData;
    }

    // Create a new DataNode
    DataNode* newData = (DataNode*)malloc(sizeof(DataNode));
    if (newData == NULL) {
        fprintf(stderr, "Memory allocation failed for DataNode.\n");
        exit(EXIT_FAILURE);
    }

    // Initialize the new DataNode
    newData->single_data = data;
    newData->data = data;
    newData->flow = flow;
    newData->time = time;
    newData->nextData = NULL; // As it will be the last node
    newData->flowCount = flow->flowCount; 

    // Append the new DataNode at the end of the list
    if (flow->datas == NULL) {
        // If it's the first DataNode
        newData->prevData = NULL;
        flow->datas = newData;
        flow->lastData = newData;
    } else {
        // Update the cumulative data by adding the last data node's count
        newData->data += flow->lastData->data;
        
        // Append and update pointers
        flow->lastData->nextData = newData;
        newData->prevData = flow->lastData;
        flow->lastData = newData; // Update the lastData pointer to the new node
    }
}






void updateFlowAttribute(FlowNode* flow, const char* attribute, int newValue) {
    if (strcmp(attribute, "src_port") == 0) {
        flow->src_port = newValue;
    } else if (strcmp(attribute, "dst_port") == 0) {
        flow->dst_port = newValue;
    } else {
        printf("未知属性或属性不支持直接整数更新。\n");
    }
}

void updateFlowProtocol(FlowNode* flow, const char* newProtocol) {
    strncpy(flow->protocol, newProtocol, sizeof(flow->protocol) - 1);
    flow->protocol[sizeof(flow->protocol) - 1] = '\0';  
}


void queryFlow(FlowNode* headFlow, const char* src_IP, const char* src_port_str, const char* dst_IP, const char* dst_port_str, const char* protocol, time_t startTime, time_t endTime) {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int src_port = (strcmp(src_port_str, "ALL") == 0) ? -1 : atoi(src_port_str);
    int dst_port = (strcmp(dst_port_str, "ALL") == 0) ? -1 : atoi(dst_port_str);

    FlowNode* current = headFlow;
    while (current != NULL) {
        bool srcIPMatch = false;
        bool dstIPMatch = false;

        char* srcIPWildcard = (char*)src_IP; // Cast to non-const pointer to use in comparison
	char* dstIPWildcard = (char*)dst_IP;

	// Updated IP matching logic without tokenization
	if (strcmp(src_IP, "ALL") != 0) {
	    srcIPMatch = true; // Assume match until proven otherwise
	    for (int i = 0; current->src_IP[i] != '\0' && srcIPWildcard[i] != '\0'; ++i) {
		if (srcIPWildcard[i] == '*') {
		    break; // Wildcard found, rest of the octets are assumed to match
		}
		if (current->src_IP[i] != srcIPWildcard[i]) {
		    srcIPMatch = false; // Exact match failed
		    break;
		}
	    }
	}

	if (strcmp(dst_IP, "ALL") != 0) {
	    dstIPMatch = true; // Assume match until proven otherwise
	    for (int i = 0; current->dst_IP[i] != '\0' && dstIPWildcard[i] != '\0'; ++i) {
		if (dstIPWildcard[i] == '*') {
		    break; // Wildcard found, rest of the octets are assumed to match
		}
		if (current->dst_IP[i] != dstIPWildcard[i]) {
		    dstIPMatch = false; // Exact match failed
		    break;
		}
	    }
	}
	
	

        bool srcPortMatch = (src_port == -1 || current->src_port == src_port);
        bool dstPortMatch = (dst_port == -1 || current->dst_port == dst_port);
        bool protocolMatch = (strcmp(protocol, "ALL") == 0 || strcmp(current->protocol, protocol) == 0);

        if (srcIPMatch && dstIPMatch && srcPortMatch && dstPortMatch && protocolMatch) {
            char src_country[100] = "Unknown";
            char dst_country[100] = "Unknown";
            int gai_error, mmdb_error;

            // Perform the country lookup for the source IP
            MMDB_lookup_result_s src_result = MMDB_lookup_string(&mmdb, current->src_IP, &gai_error, &mmdb_error);
            if (mmdb_error == MMDB_SUCCESS) {
                MMDB_entry_data_s entry_data;
                if (MMDB_get_value(&src_result.entry, &entry_data, "country", "names", "en", NULL) == MMDB_SUCCESS && entry_data.has_data) {
                    snprintf(src_country, sizeof(src_country), "%.*s", entry_data.data_size, entry_data.utf8_string);
                }
            }

            // Perform the country lookup for the destination IP
            MMDB_lookup_result_s dst_result = MMDB_lookup_string(&mmdb, current->dst_IP, &gai_error, &mmdb_error);
            if (mmdb_error == MMDB_SUCCESS) {
                MMDB_entry_data_s entry_data;
                if (MMDB_get_value(&dst_result.entry, &entry_data, "country", "names", "en", NULL) == MMDB_SUCCESS && entry_data.has_data) {
                    snprintf(dst_country, sizeof(dst_country), "%.*s", entry_data.data_size, entry_data.utf8_string);
                }
            }

            // Print the matching flow with the country information
            printf("Matching flow: %s:%d (%s) -> %s:%d (%s) [%s]\n", current->src_IP, current->src_port, src_country, current->dst_IP, current->dst_port, dst_country, current->protocol);

            DataNode* data = current->datas;
            while (data != NULL) {
                time_t dataTime = convertStringToTime(data->time->timestamp);
                if (dataTime >= startTime && dataTime <= endTime) {
                    printf("Timestamp: %s, Single Data Size: %d bytes\n", data->time->timestamp, data->single_data);
                }
                data = data->nextData;
            }
        }

        current = current->nextFlow;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double time_taken = (end.tv_sec - start.tv_sec) * 1e9;
    time_taken = (time_taken + (end.tv_nsec - start.tv_nsec)) * 1e-9;
    printf("The query operation took %.9f seconds.\n", time_taken);
}




void handleQuery(const char* input) {
    char src_IP[50], dst_IP[50], src_port_str[6], dst_port_str[6], protocol[10];
    char inputCopy[256];
    strncpy(inputCopy, input, sizeof(inputCopy));
     int parsed = sscanf(inputCopy, "%s %s %s %s %s", src_IP, src_port_str, dst_IP, dst_port_str, protocol);

    // 检查是否成功解析了所有的 5 个参数
    if (parsed != 5) {
        printf("Invalid format. Please enter 'src_ip src_port dst_ip dst_port protocol'.\n");
        return;
    }
    
   printf("Enter start time (YYYY-MM-DD-HH:MM:SS or 'start_time' for the beginning of the capture): ");
    char startTimeInput[50];
    
    scanf("%49s", startTimeInput);
    time_t startTime = 0;
    if (strcmp(startTimeInput, "start_time") == 0) {
        startTime = firstPacketTime;
    } else if (strcmp(startTimeInput, "end_time") == 0) {
        startTime = lastPacketTime;
    } else {
        startTime = convertStringToTime(startTimeInput);
    }

    // Check for a valid start time conversion
    if (startTime == -1) {
        printf("Invalid start time format entered.\n");
        return;
    }

    // Prompt the user for the end time
    printf("Enter end time (YYYY-MM-DD-HH:MM:SS or 'end_time' for the current time, '+/-valueUnit' to adjust start time): ");
    char endTimeInput[50];
    scanf("%49s", endTimeInput);
    time_t endTime = startTime; // Default to start time in case of immediate adjustment

    // Check for adjustments or specific end time
    if (endTimeInput[0] == '+' || endTimeInput[0] == '-') {
        endTime = adjustTime(startTime, endTimeInput);
    } else if (strcmp(endTimeInput, "end_time") == 0) {
        endTime = lastPacketTime;
    } else {
        endTime = convertStringToTime(endTimeInput);
    }

    // Check for a valid end time conversion and logical order
    if (endTime == -1 || endTime < startTime) {
        printf("Invalid end time format entered or end time is before start time.\n");
        return;
    }

    // 执行查询
    queryFlow(globalFlowsHead, src_IP, src_port_str, dst_IP, dst_port_str, protocol, startTime, endTime);
}



void freeDataNodes(DataNode* headData) {
    DataNode* current;
    while (headData != NULL) {
        current = headData;
        headData = headData->nextData;
        free(current);
    }
}

void freeFlowNodes(FlowNode* headFlow) {
    FlowNode* current;
    while (headFlow != NULL) {
        current = headFlow;
        headFlow = headFlow->nextFlow;
        freeDataNodes(current->datas); 
        free(current);
    }
}


void freeTimeNodes(TimeNode* headTime) {
    TimeNode* current;
    while (headTime != NULL) {
        current = headTime;
        headTime = headTime->nextTime;
        freeFlowNodes(current->flows); 
        free(current);
    }
}


double calculateGlobalFlowsSizeMB(FlowNode* headFlow) {
    double totalSize = 0;
    FlowNode* currentFlow = headFlow;

    while (currentFlow != NULL) {
        totalSize += sizeof(FlowNode); 
        DataNode* currentData = currentFlow->datas;

        while (currentData != NULL) {
            totalSize += sizeof(DataNode);  
            currentData = currentData->nextData;
        }

        currentFlow = currentFlow->nextFlow;
    }

    return totalSize / (1024.0 * 1024.0);  
}



double calculateDataStructureSizeMB(TimeNode* headTime) {
    double totalSize = 0;
    TimeNode* currentTime = headTime;
    while (currentTime != NULL) {
        totalSize += sizeof(TimeNode);
        FlowNode* currentFlow = currentTime->flows;
        while (currentFlow != NULL) {
            totalSize += sizeof(FlowNode);
            DataNode* currentData = currentFlow->datas;
            while (currentData != NULL) {
                totalSize += sizeof(DataNode);
                currentData = currentData->nextData;
            }
            currentFlow = currentFlow->nextFlow;
        }
        currentTime = currentTime->nextTime;
    }
    return totalSize / (1024.0 * 1024.0); 
}

int getFlowIndex(char** uniqueFlows, int flowCount, char* src_IP, int src_port, char* dst_IP, int dst_port, char* protocol) {
    char flowStr[1024];
    snprintf(flowStr, sizeof(flowStr), "%s:%d -> %s:%d [%s]", src_IP, src_port, dst_IP, dst_port, protocol);
    
    for (int i = 0; i < flowCount; i++) {
        if (strcmp(uniqueFlows[i], flowStr) == 0) {
            return i;
        }
    }
    return -1; 
}
char** getUniqueFlows(int* flowCount) {
    int capacity = 10;  
    char** flows = malloc(capacity * sizeof(char*));
    *flowCount = 0;

    FlowNode* currentFlow = globalFlowsHead;
    while (currentFlow != NULL) {
        char flowStr[1024]; 
        snprintf(flowStr, sizeof(flowStr), "%s:%d -> %s:%d [%s]",
                 currentFlow->src_IP, currentFlow->src_port,
                 currentFlow->dst_IP, currentFlow->dst_port,
                 currentFlow->protocol);


        bool exists = false;
        for (int i = 0; i < *flowCount; i++) {
            if (strcmp(flows[i], flowStr) == 0) {
                exists = true;
                break;
            }
        }


        if (!exists) {
            if (*flowCount >= capacity) {
                capacity *= 2;
                flows = realloc(flows, capacity * sizeof(char*));
            }
            flows[*flowCount] = strdup(flowStr);
            (*flowCount)++;
        }

        currentFlow = currentFlow->nextFlow;
    }

    return flows;
}


char** getUniqueTimestamps(int* timestampCount) {
    int count = 0;
    char** timestamps = NULL;

    if (headTime != NULL) {
        TimeNode* current = headTime;
        do {
            bool found = false;
            for (int i = 0; i < count; i++) {
                if (strcmp(timestamps[i], current->timestamp) == 0) {
                    found = true;
                    break;
                }
            }


            if (!found) {
                timestamps = realloc(timestamps, (count + 1) * sizeof(char*));
                timestamps[count] = strdup(current->timestamp);
                count++;
            }

            current = current->nextTime;
        } while (current != headTime);
    }

    *timestampCount = count;
    return timestamps;
}



char* createFlowString(FlowNode* flow) {
    char* flowStr = (char*)malloc(1024 * sizeof(char)); 
    if (flowStr == NULL) {
        fprintf(stderr, "Memory allocation failed for flow string.\n");
        exit(EXIT_FAILURE);
    }
    snprintf(flowStr, 1024, "%s:%d -> %s:%d [%s]",
             flow->src_IP, flow->src_port, flow->dst_IP, flow->dst_port, flow->protocol);
    return flowStr;
}


char** createUniqueFlowList(int* flowCount) {
    int capacity = 10;
    char** flows = (char**)malloc(capacity * sizeof(char*));
    if (flows == NULL) {
        fprintf(stderr, "Memory allocation failed for flows.\n");
        exit(EXIT_FAILURE);
    }
    *flowCount = 0;

    FlowNode* current = globalFlowsHead;
    while (current != NULL) {
        char* flowStr = createFlowString(current);


        bool found = false;
        for (int i = 0; i < *flowCount; i++) {
            if (strcmp(flows[i], flowStr) == 0) {
                found = true;
                break;
            }
        }


        if (!found) {
            if (*flowCount >= capacity) {
                capacity *= 2;
                flows = (char**)realloc(flows, capacity * sizeof(char*));
                if (flows == NULL) {
                    fprintf(stderr, "Memory reallocation failed for flows.\n");
                    exit(EXIT_FAILURE);
                }
            }
            flows[*flowCount] = flowStr;
            (*flowCount)++;
        } else {
            free(flowStr); 
        }

        current = current->nextFlow;
    }

    return flows;
}


void printDataStructure(TimeNode* headTime) {
    if (headTime == NULL) {
        printf("No data to display.\n");
        return;
    }
    size_t currentDataStructureSize = 0;
     
    TimeNode* timeNode = headTime;
    do {
        printf("\t%s", timeNode->timestamp); 
        timeNode = timeNode->nextTime;
    } while (timeNode != headTime);
    printf("\n");

    FlowNode* flowNode = globalFlowsHead;
    while (flowNode != NULL) {
       //printf("%s:%d -> %s:%d [%s] 出现次数: %d\n", flowNode->src_IP, flowNode->src_port, flowNode->dst_IP, flowNode->dst_port, flowNode->protocol, flowNode->flowCount);

        DataNode* dataNode = flowNode->datas;
        while (dataNode != NULL) {
            char dataStr[20]; // 假设数据不会超过这个长度
            if (dataNode->single_data == 0) {
                strcpy(dataStr, "X");
            } else {
                sprintf(dataStr, "%d", dataNode->data); // 将整数转换为字符串
            }
           // printf("\t%s", dataStr);

            currentDataStructureSize += dataNode->single_data;
            dataNode = dataNode->nextData;
        }
       // printf("\n");
        flowNode = flowNode->nextFlow; 
    }

    // 在所有节点遍历完毕后，打印总流量大小
     printf("Total traffic size in current data structure: %f MB\n", currentDataStructureSize / (1024.0 * 1024.0));
}





void queryAndSortFlows(int topN){
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int flowCount = 0;
    FlowNode* currentFlow = globalFlowsHead;

    // Step 2: Count the number of flows
    while (currentFlow != NULL) {
        flowCount++;
        currentFlow = currentFlow->nextFlow;
    }

    if (flowCount == 0) {
        printf("No flows to process.\n");
        return;
    }

    // Step 3: Allocate memory dynamically based on the flow count
    FlowSummary* summaries = (FlowSummary*)malloc(flowCount * sizeof(FlowSummary));
    if (summaries == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        return;
    }

    int summaryCount = 0;
    currentFlow = globalFlowsHead;

    // Step 4: Populate the dynamically allocated array
    while (currentFlow != NULL) {
        strcpy(summaries[summaryCount].src_IP, currentFlow->src_IP);
        strcpy(summaries[summaryCount].dst_IP, currentFlow->dst_IP);
        summaries[summaryCount].src_port = currentFlow->src_port;
        summaries[summaryCount].dst_port = currentFlow->dst_port;
        strcpy(summaries[summaryCount].protocol, currentFlow->protocol);
        summaries[summaryCount].totalData = currentFlow->totalData;  // Assume totalData is correctly updated elsewhere
        summaryCount++;
        currentFlow = currentFlow->nextFlow;
    }

    // Sort the summaries based on total data
    qsort(summaries, summaryCount, sizeof(FlowSummary), compareFlowSummary);

    // Print the top N flows
    for (int i = 0; i < summaryCount && i < topN; i++) {
        char src_country[100], dst_country[100]; // 存储国家名称

        // 查询源IP的国家
        int gai_error, mmdb_error;
        MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, summaries[i].src_IP, &gai_error, &mmdb_error);
        if (mmdb_error == MMDB_SUCCESS) {
            MMDB_entry_data_s entry_data;
            int status = MMDB_get_value(&result.entry, &entry_data, "country", "names", "en", NULL);
            if (status == MMDB_SUCCESS && entry_data.has_data) {
                snprintf(src_country, sizeof(src_country), "%.*s", entry_data.data_size, entry_data.utf8_string);
            } else {
                snprintf(src_country, sizeof(src_country), "Unknown");
            }
        }

        // 查询目的IP的国家
        result = MMDB_lookup_string(&mmdb, summaries[i].dst_IP, &gai_error, &mmdb_error);
        if (mmdb_error == MMDB_SUCCESS) {
            MMDB_entry_data_s entry_data;
            int status = MMDB_get_value(&result.entry, &entry_data, "country", "names", "en", NULL);
            if (status == MMDB_SUCCESS && entry_data.has_data) {
                snprintf(dst_country, sizeof(dst_country), "%.*s", entry_data.data_size, entry_data.utf8_string);
            } else {
                snprintf(dst_country, sizeof(dst_country), "Unknown");
            }
        }

        // 打印流信息和对应的国家
        printf("Flow #%d: %s:%d (%s) -> %s:%d (%s) [%s], Total Data: %d bytes \n",
               i + 1,
               summaries[i].src_IP, summaries[i].src_port, src_country,
               summaries[i].dst_IP, summaries[i].dst_port, dst_country,
               summaries[i].protocol, summaries[i].totalData );
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed_seconds = end.tv_sec - start.tv_sec + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("Sorting and querying took a total of %f seconds\n", elapsed_seconds);
}




int compareFlowSummary(const void* a, const void* b) {
    const FlowSummary* flowA = (const FlowSummary*)a;
    const FlowSummary* flowB = (const FlowSummary*)b;
    return flowB->totalData - flowA->totalData; 
}


int compareStatItems(const void* a, const void* b) {
    const StatItem* itemA = (const StatItem*)a;
    const StatItem* itemB = (const StatItem*)b;
    return itemB->count - itemA->count; 
}

int compareFlowCount(const void* a, const void* b) {
    FlowNode* flowA = *(FlowNode**)a;
    FlowNode* flowB = *(FlowNode**)b;
    return flowB->flowCount - flowA->flowCount;  
}


int compareFlowCountDiff(const void* a, const void* b) {
    FlowCountDiff* diffA = (FlowCountDiff*)a;
    FlowCountDiff* diffB = (FlowCountDiff*)b;
    return diffB->flowCountDifference - diffA->flowCountDifference;
}


void rankFlowsByFlowCount(int topN) {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int count = 0;
    FlowNode* current = globalFlowsHead;

    // 计算流的总数
    while (current) {
        count++;
        current = current->nextFlow;
    }

    // 为流节点指针分配数组
    FlowNode** flowArray = malloc(count * sizeof(FlowNode*));
    if (!flowArray) {
        perror("Memory allocation failed");
        return;
    }

    current = globalFlowsHead;
    for (int i = 0; i < count; i++) {
        flowArray[i] = current;
        current = current->nextFlow;
    }

    // 使用 qsort 排序
    qsort(flowArray, count, sizeof(FlowNode*), compareFlowCount);

    // 输出前 N 个流
    printf("Top %d Flows by Flow Count:\n", topN);
    for (int i = 0; i < topN && i < count; i++) {
        char src_country[100], dst_country[100]; // 存储国家名称

        int gai_error, mmdb_error; // 在函数内声明这些变量

        // 查询源IP的国家
        MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, flowArray[i]->src_IP, &gai_error, &mmdb_error);
        if (mmdb_error == MMDB_SUCCESS) {
            MMDB_entry_data_s entry_data;
            int status = MMDB_get_value(&result.entry, &entry_data, "country", "names", "en", NULL);
            if (status == MMDB_SUCCESS && entry_data.has_data) {
                snprintf(src_country, sizeof(src_country), "%.*s", entry_data.data_size, entry_data.utf8_string);
            } else {
                snprintf(src_country, sizeof(src_country), "Unknown");
            }
        }

        // 查询目的IP的国家
        result = MMDB_lookup_string(&mmdb, flowArray[i]->dst_IP, &gai_error, &mmdb_error);
        if (mmdb_error == MMDB_SUCCESS) {
            MMDB_entry_data_s entry_data;
            int status = MMDB_get_value(&result.entry, &entry_data, "country", "names", "en", NULL);
            if (status == MMDB_SUCCESS && entry_data.has_data) {
                snprintf(dst_country, sizeof(dst_country), "%.*s", entry_data.data_size, entry_data.utf8_string);
            } else {
                snprintf(dst_country, sizeof(dst_country), "Unknown");
            }
        }

        // 打印流信息和国家
        printf("Flow #%d: %s:%d (%s) -> %s:%d (%s) [%s], Flow Count: %d \n",
               i + 1,
               flowArray[i]->src_IP, flowArray[i]->src_port, src_country,
               flowArray[i]->dst_IP, flowArray[i]->dst_port, dst_country,
               flowArray[i]->protocol, flowArray[i]->flowCount );
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double time_taken = (end.tv_sec - start.tv_sec) * 1e9;
    time_taken = (time_taken + (end.tv_nsec - start.tv_nsec)) * 1e-9; // Convert to seconds

    printf("The ranking operation took %.9f seconds.\n", time_taken);

    free(flowArray);  // 释放数组内存
}

void rankFlowsByCountInRange(time_t startTime, time_t endTime, int topN) {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int flowCount = 0;
    FlowNode* current = globalFlowsHead;

    // 第一次遍历以计算流的总数
    while (current != NULL) {
        flowCount++;
        current = current->nextFlow;
    }

    // 根据流的数量动态分配FlowCountDiff数组
    FlowCountDiff* diffs = (FlowCountDiff*)malloc(flowCount * sizeof(FlowCountDiff));
    if (diffs == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        return; // 如果内存分配失败，提前返回
    }

    current = globalFlowsHead;
    int index = 0;

    // 第二次遍历以填充FlowCountDiff数组
    while (current != NULL) {
        // 寻找最接近startTime和endTime的DataNode
        DataNode* startData = NULL;
        DataNode* endData = NULL;

        for (DataNode* d = current->datas; d != NULL; d = d->nextData) {
            time_t dataTime = convertStringToTime(d->time->timestamp);
            if (dataTime <= startTime) {
                startData = d;
            }
            if (dataTime <= endTime) {
                endData = d;
            } else {
                break; // 数据已超出时间范围
            }
        }

        // 计算流计数差异
        int startCount = startData ? startData->flowCount : 0;
        int endCount = endData ? endData->flowCount : 0;
        diffs[index].flow = current;
        diffs[index].flowCountDifference = endCount - startCount;
        index++;

        current = current->nextFlow;
    }

    // 使用qsort根据flowCountDifference排序
    qsort(diffs, flowCount, sizeof(FlowCountDiff), compareFlowCountDiff);

    // 打印前N个结果
    for (int i = 0; i < topN && i < flowCount; i++) {
        char src_country[100] = "Unknown", dst_country[100] = "Unknown";  // Initialize country names
        int gai_error, mmdb_error;

        // Look up the country for the source IP
        MMDB_lookup_result_s src_result = MMDB_lookup_string(&mmdb, diffs[i].flow->src_IP, &gai_error, &mmdb_error);
        if (mmdb_error == MMDB_SUCCESS) {
            MMDB_entry_data_s entry_data;
            if (MMDB_get_value(&src_result.entry, &entry_data, "country", "names", "en", NULL) == MMDB_SUCCESS && entry_data.has_data) {
                snprintf(src_country, sizeof(src_country), "%.*s", entry_data.data_size, entry_data.utf8_string);
            }
        }

        // Look up the country for the destination IP
        MMDB_lookup_result_s dst_result = MMDB_lookup_string(&mmdb, diffs[i].flow->dst_IP, &gai_error, &mmdb_error);
        if (mmdb_error == MMDB_SUCCESS) {
            MMDB_entry_data_s entry_data;
            if (MMDB_get_value(&dst_result.entry, &entry_data, "country", "names", "en", NULL) == MMDB_SUCCESS && entry_data.has_data) {
                snprintf(dst_country, sizeof(dst_country), "%.*s", entry_data.data_size, entry_data.utf8_string);
            }
        }

        // Print the flow information along with the country names
        printf("Flow #%d: %s:%d (%s) -> %s:%d (%s) [%s], Count difference in the time range: %d\n",
               i + 1,
               diffs[i].flow->src_IP, diffs[i].flow->src_port, src_country,
               diffs[i].flow->dst_IP, diffs[i].flow->dst_port, dst_country,
               diffs[i].flow->protocol, diffs[i].flowCountDifference);
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    double time_taken = (end.tv_sec - start.tv_sec) * 1e9;
    time_taken = (time_taken + (end.tv_nsec - start.tv_nsec)) * 1e-9; // Convert to seconds

    printf("The ranking operation took %.9f seconds.\n", time_taken);

    free(diffs);
}




void rankAttribute(StatList *list, const char *attributeType, int topN) {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    qsort(list->items, list->size, sizeof(StatItem), compareStatItems);


    for (int i = 0; i < topN && i < list->size; i++) {
        if (strcmp(attributeType, "src_ip") == 0 || strcmp(attributeType, "dst_ip") == 0) {
            // 如果属性类型是src_ip或dst_ip，查询国家信息
            char country[100] = "Unknown"; // 默认国家名称
            int gai_error, mmdb_error;

            MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, list->items[i].value, &gai_error, &mmdb_error);
            if (mmdb_error == MMDB_SUCCESS) {
                MMDB_entry_data_s entry_data;
                int status = MMDB_get_value(&result.entry, &entry_data, "country", "names", "en", NULL);
                if (status == MMDB_SUCCESS && entry_data.has_data) {
                    snprintf(country, sizeof(country), "%.*s", entry_data.data_size, entry_data.utf8_string);
                }
            }
            // 打印IP地址及其对应国家
            printf("Top #%d :%s (%s): %d\n",i+1, list->items[i].value, country, list->items[i].count);
        } else {
            // 如果属性类型不是src_ip或dst_ip，正常打印
            printf("%s: %d\n", list->items[i].value, list->items[i].count);
        }
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    double time_taken = (end.tv_sec - start.tv_sec) * 1e9;
    time_taken = (time_taken + (end.tv_nsec - start.tv_nsec)) * 1e-9; // Convert to seconds

    printf("The ranking operation took %.9f seconds.\n", time_taken);
}

void rankAttributeWithinTimeRange(StatList *list, const char* attribute, time_t startTime, time_t endTime, int topN) {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    StatList tempList = {NULL, 0, 10};
    tempList.items = (StatItem*)calloc(tempList.capacity, sizeof(StatItem));
    if (tempList.items == NULL) {
        fprintf(stderr, "Memory allocation failed for temporary stat list.\n");
        return;
    }

    for (FlowNode* f = globalFlowsHead; f != NULL; f = f->nextFlow) {
        for (DataNode* d = f->datas; d != NULL; d = d->nextData) {
            time_t dataTime = convertStringToTime(d->time->timestamp);
            if (dataTime >= startTime && dataTime <= endTime) {
                const char* value = NULL;

                // 根据用户选择的属性获取值
                if (strcmp(attribute, "src_ip") == 0) {
                    value = f->src_IP;
                } else if (strcmp(attribute, "dst_ip") == 0) {
                    value = f->dst_IP;
                } else if (strcmp(attribute, "src_port") == 0) {
                    static char portStr[6]; // Static to reuse buffer, attention to thread safety
                    snprintf(portStr, sizeof(portStr), "%d", f->src_port);
                    value = portStr;
                } else if (strcmp(attribute, "dst_port") == 0) {
                    static char portStr[6];
                    snprintf(portStr, sizeof(portStr), "%d", f->dst_port);
                    value = portStr;
                } else if (strcmp(attribute, "protocol") == 0) {
                    value = f->protocol;
                }

                if (value) {
                    // 检查该值是否已在tempList中
                    bool found = false;
                    for (int i = 0; i < tempList.size; ++i) {
                        if (strcmp(tempList.items[i].value, value) == 0) {
                            tempList.items[i].count++;
                            found = true;
                            break;
                        }
                    }
                    // 如果未找到，则添加到tempList中
                    if (!found) {
                        if (tempList.size == tempList.capacity) {
                            tempList.capacity *= 2;
                            tempList.items = (StatItem*)realloc(tempList.items, tempList.capacity * sizeof(StatItem));
                        }
                        strncpy(tempList.items[tempList.size].value, value, sizeof(tempList.items[tempList.size].value) - 1);
                        tempList.items[tempList.size].value[sizeof(tempList.items[tempList.size].value) - 1] = '\0'; // 确保空字符终止
                        tempList.items[tempList.size].count = 1;
                        tempList.size++;
                    }
                }
            }
        }
    }

    qsort(tempList.items, tempList.size, sizeof(StatItem), compareStatItems);

    for (int i = 0; i < topN && i < tempList.size; i++) {
        char country[100] = "Unknown";  // Default country name
        int gai_error, mmdb_error;

        // Look up the country for IP addresses
        MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, tempList.items[i].value, &gai_error, &mmdb_error);

        if (mmdb_error == MMDB_SUCCESS) {
            MMDB_entry_data_s entry_data;
            int status = MMDB_get_value(&result.entry, &entry_data, "country", "names", "en", NULL);
            if (status == MMDB_SUCCESS && entry_data.has_data) {
                snprintf(country, sizeof(country), "%.*s", entry_data.data_size, entry_data.utf8_string);
            }
        }

        // Print the IP address along with its corresponding country and count
        printf("Top #%d : %s (%s): %d\n", i + 1, tempList.items[i].value, country, tempList.items[i].count);
    }
    
    free(tempList.items);

    clock_gettime(CLOCK_MONOTONIC, &end);
    double time_taken = (end.tv_sec - start.tv_sec) * 1e9;
    time_taken = (time_taken + (end.tv_nsec - start.tv_nsec)) * 1e-9;
    printf("The ranking operation took %.9f seconds.\n", time_taken);
}




void displayTopStats(StatList* list, int topN) {
    qsort(list->items, list->size, sizeof(StatItem), compareStatItems);

    for (int i = 0; i < topN && i < list->size; ++i) {
        printf("%s: %d\n", list->items[i].value, list->items[i].count);
    }
}


void freeGlobalFlows() {
    FlowNode* currentFlow = globalFlowsHead;
    while (currentFlow != NULL) {
        FlowNode* tempFlow = currentFlow;
        currentFlow = currentFlow->nextFlow;
        freeDataNodes(tempFlow->datas);
        free(tempFlow);
    }
}


time_t convertStringToTime(const char* timeStr) {
    struct tm tmTime = {0};
    if (sscanf(timeStr, "%d-%d-%d-%d:%d:%d",
               &tmTime.tm_year, &tmTime.tm_mon, &tmTime.tm_mday,
               &tmTime.tm_hour, &tmTime.tm_min, &tmTime.tm_sec) == 6) {
        tmTime.tm_year -= 1900;
        tmTime.tm_mon -= 1;     
        return mktime(&tmTime); 
    }
    return -1; 
}


bool isTimestampWithinRange(const char* timestampStr, const char* startStr, const char* endStr) {
    time_t timestamp = convertStringToTime(timestampStr);
    time_t startTime = convertStringToTime(startStr);
    time_t endTime = convertStringToTime(endStr);

    bool result = (timestamp >= startTime && timestamp <= endTime);

    return result;
}


int findSummaryIndex(FlowSummary* summaries, int count, char* src_IP, int src_port, char* dst_IP, int dst_port, char* protocol) {
    for (int i = 0; i < count; i++) {
        if (strcmp(summaries[i].src_IP, src_IP) == 0 && strcmp(summaries[i].dst_IP, dst_IP) == 0 &&
            summaries[i].src_port == src_port && summaries[i].dst_port == dst_port &&
            strcmp(summaries[i].protocol, protocol) == 0) {
            return i;
        }
    }
    return -1;
}

void queryAndSortFlowsWithTimeRange(time_t startTime, time_t endTime, int topN) {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int flowCount = 0;
    FlowNode* currentFlow = globalFlowsHead;

    // Count the number of flows
    while (currentFlow != NULL) {
        flowCount++;
        currentFlow = currentFlow->nextFlow;
    }

    if (flowCount == 0) {
        printf("No flows to process.\n");
        return;
    }

    // Dynamically allocate memory for FlowSummary based on the flow count
    FlowSummary* summaries = (FlowSummary*)malloc(flowCount * sizeof(FlowSummary));
    if (summaries == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        return;
    }

    int summaryCount = 0;
    currentFlow = globalFlowsHead;

    // Populate the dynamically allocated array
    while (currentFlow != NULL) {
        DataNode* startDataNode = NULL;
        DataNode* endDataNode = NULL;

        // Find the DataNode closest to the start and end times
        for (DataNode* d = currentFlow->datas; d != NULL; d = d->nextData) {
            time_t dataTime = convertStringToTime(d->time->timestamp);
            if (dataTime <= startTime) {
                startDataNode = d;
            }
            if (dataTime <= endTime) {
                endDataNode = d;
            } else {
                break; // Data is beyond the end time, stop searching
            }
        }

        // Calculate the data size within the time range
        int dataSizeWithinRange = 0;
        if (endDataNode != NULL) {
            dataSizeWithinRange = endDataNode->data;
            if (startDataNode != NULL) {
                dataSizeWithinRange -= startDataNode->data;
            }
        }

        if (dataSizeWithinRange > 0) {
            strcpy(summaries[summaryCount].src_IP, currentFlow->src_IP);
            strcpy(summaries[summaryCount].dst_IP, currentFlow->dst_IP);
            summaries[summaryCount].src_port = currentFlow->src_port;
            summaries[summaryCount].dst_port = currentFlow->dst_port;
            strcpy(summaries[summaryCount].protocol, currentFlow->protocol);
            summaries[summaryCount].totalData = dataSizeWithinRange;
            summaryCount++;
        }

        currentFlow = currentFlow->nextFlow;
    }
    qsort(summaries, summaryCount, sizeof(FlowSummary), compareFlowSummary);

     for (int i = 0; i < summaryCount && i < topN; i++) {
        char src_country[100], dst_country[100]; // 存储国家名称

        // 查询源IP的国家
        int gai_error, mmdb_error;
        MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, summaries[i].src_IP, &gai_error, &mmdb_error);
        if (mmdb_error == MMDB_SUCCESS) {
            MMDB_entry_data_s entry_data;
            int status = MMDB_get_value(&result.entry, &entry_data, "country", "names", "en", NULL);
            if (status == MMDB_SUCCESS && entry_data.has_data) {
                snprintf(src_country, sizeof(src_country), "%.*s", entry_data.data_size, entry_data.utf8_string);
            } else {
                snprintf(src_country, sizeof(src_country), "Unknown");
            }
        }

        // 查询目的IP的国家
        result = MMDB_lookup_string(&mmdb, summaries[i].dst_IP, &gai_error, &mmdb_error);
        if (mmdb_error == MMDB_SUCCESS) {
            MMDB_entry_data_s entry_data;
            int status = MMDB_get_value(&result.entry, &entry_data, "country", "names", "en", NULL);
            if (status == MMDB_SUCCESS && entry_data.has_data) {
                snprintf(dst_country, sizeof(dst_country), "%.*s", entry_data.data_size, entry_data.utf8_string);
            } else {
                snprintf(dst_country, sizeof(dst_country), "Unknown");
            }
        }

        // 打印流信息和对应的国家
        printf("Flow #%d: %s:%d (%s) -> %s:%d (%s) [%s], Total Data: %d bytes \n",
               i + 1,
               summaries[i].src_IP, summaries[i].src_port, src_country,
               summaries[i].dst_IP, summaries[i].dst_port, dst_country,
               summaries[i].protocol, summaries[i].totalData );
    }


    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed_seconds = end.tv_sec - start.tv_sec + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("排序和查询所需的总时间: %f 秒\n", elapsed_seconds);
}


void queryDataSizeWithinTimeRange(time_t startTime, time_t endTime) {
    double totalSizeMB = 0;

    for (FlowNode* f = globalFlowsHead; f != NULL; f = f->nextFlow) {
        for (DataNode* d = f->datas; d != NULL; d = d->nextData) {
            time_t dataTime = convertStringToTime(d->time->timestamp);
            if (dataTime >= startTime && dataTime <= endTime) {
                totalSizeMB += sizeof(DataNode); 
            }
        }
    }

    
    totalSizeMB /= (1024.0 * 1024.0);

    
    printf("Total data structure size within the specified time range: %f MB\n", totalSizeMB);
}


void* periodicDisplay(void* arg) {
    while (running) {
        sleep(intervalSeconds);
    }
    return NULL;
}


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    char dev[] = "enp5s0"; 
    //char dev[] = "enp0s3"; 
    pthread_t captureThread, displayThread;;
        
    initializeStatLists();
    const char *dbPath = "/home/topn/桌面/topN/GeoLite2-City_20240402/GeoLite2-City.mmdb";
    int status = MMDB_open(dbPath, MMDB_MODE_MMAP, &mmdb);
    if (status != MMDB_SUCCESS) {
        fprintf(stderr, "Can't open %s - %s\n", dbPath, MMDB_strerror(status));
        exit(2); // 或适当的错误处理
    }
    
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    
    if (pthread_create(&captureThread, NULL, capturePackets, handle) != 0) {
        fprintf(stderr, "Error creating capture thread\n");
        return 2;
    }
    
    if (pthread_create(&displayThread, NULL, periodicDisplay, NULL) != 0) {
        fprintf(stderr, "Error creating periodic display thread\n");
        return 2; 
    }


    
char command[100];
int newInterval;
	    printf("Enter new interval in seconds: ");
	    if (scanf("%d", &newInterval) == 1) {
		if (newInterval > 0) {
		    intervalSeconds = newInterval;
		    printf("Interval set to %d seconds.\n", intervalSeconds);
		} else {
		    printf("Invalid interval. Please enter a positive numbpthread_t displayThread;er.\n");
		}
	    }
while (running) {
    printf("Enter command (query, print, rank, timequery, setinterval, exit, ): ");
    if (scanf("%99s", command) == 1) {
        if (strcmp(command, "exit") == 0) {
            running = 0; 
        } else if (strcmp(command, "print") == 0) {
            printDataStructure(headTime); 
        } else if (strcmp(command, "query") == 0) {
            char input[100];
	    printf("Enter 'src_ip src_port dst_ip dst_port protocol': ");
	    int c;
    	    while ((c = getchar()) != '\n' && c != EOF) { }
	    // 使用 fgets 而不是 scanf 来获取整行输入，以便包含空格
	    fgets(input, sizeof(input), stdin);  // 注意：fgets 也会读取换行符
	    // 调用函数处理查询
	    handleQuery(input);
        } 
        // ------------------------------------------------------------------------------
        else if (strcmp(command, "rank") == 0) {
            int topN;
            char attribute[20];
            printf("Enter the attribute to rank by (src_ip, dst_ip, src_port, dst_port, protocol, flow, flowcount): ");
            scanf("%19s", attribute);
            
	    printf("Enter the number of top ranks you want to see: ");
	    scanf("%d", &topN);
	    
	    StatList* listToRank = NULL;
	    
		    if (strcmp(attribute, "flow") == 0) {
		queryAndSortFlows(topN);
		    } else  if (strcmp(attribute, "src_ip") == 0) {
		const char* attributeType = "src_ip";
		rankAttribute(&srcIPList, attributeType, topN);
	    } else if (strcmp(attribute, "dst_ip") == 0) {
	        const char* attributeType = "dst_ip";
		rankAttribute(&dstIPList, attributeType, topN);
	    } else if (strcmp(attribute, "src_port") == 0) {
	        const char* attributeType = "src_port";
		rankAttribute(&srcPortList, attributeType, topN);
	    } else if (strcmp(attribute, "dst_port") == 0) {
	        const char* attributeType = "dst_port";
		rankAttribute(&dstPortList, attributeType, topN);
	    } else if (strcmp(attribute, "protocol") == 0) {
	        const char* attributeType = "protocol";
		rankAttribute(&protocolList, attributeType, topN);
	    } else if (strcmp(attribute, "flowcount") == 0) {
		rankFlowsByFlowCount(topN);
	    } else {
		printf("Invalid attribute.\n");
	    }
	}
		//-----------------------------------------------------------------------------
	 else if (strcmp(command, "timequery") == 0) {
	    char startTimeInput[50], endTimeInput[50];
	    int topN;
	    char attribute[20];
	    printf("Enter the number of top ranks you want to see: ");
	    scanf("%d", &topN);
	    
	    printf("Enter the attribute to rank by (src_ip, dst_ip, src_port, dst_port, protocol, flow, flowcount): ");
    	    scanf("%19s", attribute);

	    printf("Enter start time: ");
	    scanf(" %49s", startTimeInput);

	    time_t startTime = 0;
	    if (strcmp(startTimeInput, "start_time") == 0) {
		startTime = firstPacketTime;
	    } else if (strcmp(startTimeInput, "end_time") == 0) {
		startTime = lastPacketTime;
	    } else {
		startTime = convertStringToTime(startTimeInput); 
	    }
	    printf("Enter end time: ");
	    scanf(" %49s", endTimeInput);
	    time_t endTime = startTime; 
	    

	    if (endTimeInput[0] == '+') { 
        	 endTime = adjustTime(startTime, endTimeInput);
       	    } else if (endTimeInput[0] == '-') {
   	         startTime = adjustTime(startTime, endTimeInput);
    	    } else if (strcmp(endTimeInput, "end_time") == 0) {
   	         endTime = lastPacketTime;
    	    } else {
        	 endTime = convertStringToTime(endTimeInput); 
    	    } 
    	    
    	    if (strcmp(attribute, "flow") == 0) {
		queryAndSortFlowsWithTimeRange(startTime, endTime, topN);
	        queryDataSizeWithinTimeRange(startTime, endTime);
	    } else  if (strcmp(attribute, "flowcount") == 0) {
		rankFlowsByCountInRange(startTime, endTime, topN);
	    } else  if (strcmp(attribute, "src_ip") == 0) {
		rankAttributeWithinTimeRange(&srcIPList, attribute, startTime, endTime, topN);
	    } else if (strcmp(attribute, "dst_ip") == 0) {
		rankAttributeWithinTimeRange(&dstIPList, attribute, startTime, endTime, topN);
	    } else if (strcmp(attribute, "src_port") == 0) {
		rankAttributeWithinTimeRange(&srcPortList, attribute, startTime, endTime, topN);
	    } else if (strcmp(attribute, "dst_port") == 0) {
		rankAttributeWithinTimeRange(&dstPortList, attribute, startTime, endTime, topN);
	    } else if (strcmp(attribute, "protocol") == 0) {
		rankAttributeWithinTimeRange(&protocolList, attribute, startTime, endTime, topN);
	    } else {
		printf("Invalid attribute.\n");
	    }
    	    
	    
	    
	}     
	
	//-----------------------------------------------------------------------------
	else if (strcmp(command, "setinterval") == 0) {
	    printf("Enter new interval in seconds: ");
	    if (scanf("%d", &newInterval) == 1) {
		if (newInterval > 0) {
		    intervalSeconds = newInterval;
		    printf("Interval set to %d seconds.\n", intervalSeconds);
		} else {
		    printf("Invalid interval. Please enter a positive number.\n");
		}
	    }
	}


    }
    }

    if (pthread_join(displayThread, NULL) != 0) {
        fprintf(stderr, "Error joining periodic display thread\n");
    }


    pthread_join(captureThread, NULL);


    pcap_close(handle);
    free(srcIPList.items);
    freeGlobalFlows(); 
    freeTimeNodes(headTime);
    MMDB_close(&mmdb);
    
    return 0;
}



