//bptflow.c

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
#include <time.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h> 

#define MAX_KEYS 4
#define HASH_TABLE_SIZE 100000


volatile sig_atomic_t print_flag = 0;
volatile sig_atomic_t print_common_flag = 0;
volatile sig_atomic_t print_rate_flag = 0;
volatile sig_atomic_t running = 1;



typedef struct FlowStats {
    char src_ip[16];
    char dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint64_t packet_size;   // Cumulative size of packets
    uint64_t packet_count;  // Total number of packets
} FlowStats;

typedef struct {
    union {
        char ip[INET_ADDRSTRLEN];
        uint16_t port;
        uint8_t protocol;
        uint64_t rate; // For packet rate
    };
    unsigned long count;
} CountStruct;

FlowStats hash_table[HASH_TABLE_SIZE] = {0};

typedef struct BPlusTreeNode {
    int keys[MAX_KEYS + 1];
    int numKeys;
    struct BPlusTreeNode *children[MAX_KEYS + 2];
    struct BPlusTreeNode *next;
    int isLeaf;
} BPlusTreeNode;

BPlusTreeNode *root = NULL;

BPlusTreeNode *createNode(int isLeaf) {
    BPlusTreeNode *node = (BPlusTreeNode *)malloc(sizeof(BPlusTreeNode));
    if (node == NULL) {
    perror("Failed to allocate memory for B+ Tree node");
    exit(EXIT_FAILURE);
}
    node->isLeaf = isLeaf;
    node->numKeys = 0;
    node->next = NULL;
    memset(node->children, 0, sizeof(node->children));
    return node;
}

unsigned int hash(FlowStats *stats) {
    unsigned int hash = 0;
    unsigned char *str;

    // Hash src_ip
    str = (unsigned char *)stats->src_ip;
    while (*str) {
        hash += *str++;
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }

    // Hash dst_ip
    str = (unsigned char *)stats->dst_ip;
    while (*str) {
        hash += *str++;
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }

    // Combine src_port, dst_port, and protocol
    hash += stats->src_port;
    hash += stats->dst_port;
    hash += (hash << 10);
    hash ^= (hash >> 6);
    hash += stats->protocol;
    hash += (hash << 10);
    hash ^= (hash >> 6);

    // Final mix
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash % HASH_TABLE_SIZE;
}


void track_packet(FlowStats *stats);
void *handle_user_queries(void *arg);
void print_most_common();
void print_highest_rate();
void insertNonFull(BPlusTreeNode *node, int key);
void splitChild(BPlusTreeNode *parent, int i, BPlusTreeNode *child);
void freeTree(BPlusTreeNode *root);
void sortAndPrint(CountStruct *array, int size);
int compare(const void *a, const void *b);
void displaySrcIPStats();
void displayDstIPStats();
void displaySrcPortStats();
void displayDstPortStats();
void displayProtocolStats();
void displayPacketSizeStats();
void displayPacketRateStats();

// 比较函数，根据 packet size 降序排序
int compareByPacketSize(const void *a, const void *b) {
    const FlowStats *statsA = (const FlowStats *)a;
    const FlowStats *statsB = (const FlowStats *)b;
    return (statsB->packet_size > statsA->packet_size) - (statsA->packet_size > statsB->packet_size);
}

// 比较函数，根据 packet rate 降序排序
int compareByPacketRate(const void *a, const void *b) {
    const FlowStats *statsA = (const FlowStats *)a;
    const FlowStats *statsB = (const FlowStats *)b;
    double rateA = (double)statsA->packet_size / (statsA->packet_count ? statsA->packet_count : 1);
    double rateB = (double)statsB->packet_size / (statsB->packet_count ? statsB->packet_count : 1);
    return (rateB > rateA) - (rateA > rateB);
}

// 假设存在 CountStruct 类型及相应的 count 数组
// 比较函数，根据 IP 出现次数降序排序
int compareByIPCount(const void *a, const void *b) {
    const CountStruct *ipA = (const CountStruct *)a;
    const CountStruct *ipB = (const CountStruct *)b;
    return (ipB->count > ipA->count) - (ipA->count > ipB->count);
}

void rankFlows(const char *sortBy) {
    clock_t start, end; // 用于存储时间的变量
    double cpu_time_used;

    start = clock(); // 获取排序开始前的时间

    // 根据 packet size 或 packet rate 排序
    if (strcmp(sortBy, "packet size") == 0) {
        qsort(hash_table, HASH_TABLE_SIZE, sizeof(FlowStats), compareByPacketSize);
    } else if (strcmp(sortBy, "packet rate") == 0) {
        qsort(hash_table, HASH_TABLE_SIZE, sizeof(FlowStats), compareByPacketRate);
    } 

    end = clock(); // 获取排序完成后的时间
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC; // 计算排序所需的时间（秒）

    // 打印排序后的结果
    for (int i = 0; i < HASH_TABLE_SIZE; ++i) {
        if (hash_table[i].packet_count > 0) { // 确保有数据要打印
            printf("IP: %s -> %s, Port: %u -> %u, Protocol: %u, Packet Size: %lu, Packet Count: %lu, Packet Rate: %f\n",
                   hash_table[i].src_ip, hash_table[i].dst_ip, hash_table[i].src_port,
                   hash_table[i].dst_port, hash_table[i].protocol, hash_table[i].packet_size,
                   hash_table[i].packet_count, (double)hash_table[i].packet_size / hash_table[i].packet_count);
        }
    }

    printf("Ranking by %s took %f seconds.\n", sortBy, cpu_time_used); // 打印排序操作的执行时间
}



void handlePrintCommonSignal(int sig) {
    print_common_flag = 1;
}

void handleExitSignal(int sig) {
    running = 0; // Set the flag to false to exit the loop
}

// Signal handler for printing highest rate flows
void handlePrintRateSignal(int sig) {
    print_rate_flag = 1;
}

void handleSignal(int sig) {
    printf("Received signal %d, cleaning up...\n", sig);
    // Clean up resources, such as calling freeTree(root)
    if (root != NULL) {
        freeTree(root);
        root = NULL; // Prevent use after free
    }
    exit(sig);
}
void insert(BPlusTreeNode **root, int key) {
    BPlusTreeNode *r = *root;
    if (r->numKeys == MAX_KEYS) {
        BPlusTreeNode *s = createNode(0);
        *root = s;
        s->children[0] = r;
        splitChild(s, 0, r);
        insertNonFull(s, key);
    } else {
        insertNonFull(r, key);
    }
}

void insertNonFull(BPlusTreeNode *node, int key) {
    int i = node->numKeys - 1;

    // If this is a leaf node, insert the key into the node
    if (node->isLeaf) {
        // Move keys that are greater than key to one position ahead of their current position
        while (i >= 0 && node->keys[i] > key) {
            node->keys[i + 1] = node->keys[i];
            i--;
        }
        node->keys[i + 1] = key;
        node->numKeys++;
    } else {
        // Find the child which is going to have the new key
        while (i >= 0 && node->keys[i] > key) {
            i--;
        }
        i++; // Move to the correct child
        // If the found child is full, split it
        if (node->children[i] != NULL && node->children[i]->numKeys == MAX_KEYS) {
            splitChild(node, i, node->children[i]);
            // After splitting, the key at index i in this node will be the median key from the split
            // Decide which of the two halves will have the new key
            if (key > node->keys[i]) {
                i++;
            }
        }
        // Insert the key in the non-full child
        if (node->children[i] != NULL) {
            insertNonFull(node->children[i], key);
        }
    }
}

void splitChild(BPlusTreeNode *parent, int i, BPlusTreeNode *child) {
    // Create a new node to store keys of [t, 2t-1] from y
    BPlusTreeNode *newChild = createNode(child->isLeaf);
    newChild->numKeys = MAX_KEYS / 2;

    // Copy the last (MAX_KEYS/2) keys from y to z
    for (int j = 0; j < newChild->numKeys; j++) {
        newChild->keys[j] = child->keys[j + MAX_KEYS / 2 + 1];
    }

    // If y is not a leaf, copy the last (MAX_KEYS/2) + 1 children from y to z
    if (!child->isLeaf) {
        for (int j = 0; j <= MAX_KEYS / 2; j++) {
            newChild->children[j] = child->children[j + MAX_KEYS / 2 + 1];
        }
    }

    child->numKeys = MAX_KEYS / 2; // Reduce the number of keys in y

    // Since this node is going to have a new child, move its existing children one space to the right
    for (int j = parent->numKeys; j > i; j--) {
        parent->children[j + 1] = parent->children[j];
    }
    // Link the new child to this node
    parent->children[i + 1] = newChild;

    // A key of y will move to this node. Move all greater keys one space to the right
    for (int j = parent->numKeys - 1; j >= i; j--) {
        parent->keys[j + 1] = parent->keys[j];
    }

    // Copy the middle key of y to this node
    parent->keys[i] = child->keys[MAX_KEYS / 2];
    parent->numKeys++; // Increment count of keys in this node
}


void printTree(BPlusTreeNode *root, int level) {
    if (root == NULL) return;

    printf("Level %d, Keys:", level);
    for (int i = 0; i < root->numKeys; i++) {
        printf(" %d", root->keys[i]);
    }
    printf("\n");

    if (!root->isLeaf) {
        for (int i = 0; i <= root->numKeys; i++) {
            printTree(root->children[i], level + 1);
        }
    }
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethhdr *eth_header = (struct ethhdr *)packet;
    
    if (ntohs(eth_header->h_proto) == ETH_P_IP) {
        struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
        
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->saddr), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->daddr), dst_ip, INET_ADDRSTRLEN);

        unsigned short src_port = 0, dst_port = 0;
        unsigned int protocol = ip_header->protocol;

        if (protocol == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + ip_header->ihl * 4 + sizeof(struct ethhdr));
            src_port = ntohs(tcp_header->source);
            dst_port = ntohs(tcp_header->dest);
        } else if (protocol == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *)(packet + ip_header->ihl * 4 + sizeof(struct ethhdr));
            src_port = ntohs(udp_header->source);
            dst_port = ntohs(udp_header->dest);
        } else if (protocol == IPPROTO_ICMP) {
            // For ICMP, ports are not applicable, so we can set them to zero or some placeholder
            src_port = 0;
            dst_port = 0;
            // Additional ICMP packet handling could be implemented here
        }
        // Add cases for other protocols as needed

        FlowStats new_stats;
        strcpy(new_stats.src_ip, src_ip);
        strcpy(new_stats.dst_ip, dst_ip);
        new_stats.src_port = src_port;
        new_stats.dst_port = dst_port;
        new_stats.protocol = protocol;
        new_stats.packet_size = header->len; // Use the capture length here
        new_stats.packet_count = 1;

        track_packet(&new_stats);
    }
    
    if (print_common_flag) {
        print_most_common();
        print_common_flag = 0;
    }

    if (print_rate_flag) {
        print_highest_rate();
        print_rate_flag = 0;
    }
}



void freeTree(BPlusTreeNode *root) {
    if (root == NULL) return;

    if (!root->isLeaf) {
        for (int i = 0; i <= root->numKeys; i++) {
            freeTree(root->children[i]);
        }
    }

    free(root);
}

void track_packet(FlowStats *stats) {
    unsigned int index = hash(stats) % HASH_TABLE_SIZE;
    // Collision handling is omitted for brevity

    FlowStats *entry = &hash_table[index];
    if (entry->packet_count == 0) {
        // Initialize new flow stats entry
        memcpy(entry, stats, sizeof(FlowStats));
    } else {
        // Update existing flow stats
        entry->packet_count += 1;
        entry->packet_size += stats->packet_size;
    }
}


void print_most_common() {
    uint64_t max_count = 0;
    FlowStats *most_common = NULL;

    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        if (hash_table[i].packet_count > max_count) {
            max_count = hash_table[i].packet_count;
            most_common = &hash_table[i];
        }
    }

    if (most_common) {
        printf("Most common flow: Src IP %s, Dst IP %s, Src Port %u, Dst Port %u, Protocol %u, Packet Count %lu\n",
               most_common->src_ip, most_common->dst_ip, most_common->src_port,
               most_common->dst_port, most_common->protocol, (unsigned long)most_common->packet_count);
    }
}

void print_highest_rate() {
    uint64_t max_rate = 0;
    FlowStats *highest_rate_flow = NULL;

    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        uint64_t rate = hash_table[i].packet_count == 0 ? 0 : hash_table[i].packet_size / hash_table[i].packet_count;
        if (rate > max_rate) {
            max_rate = rate;
            highest_rate_flow = &hash_table[i];
        }
    }

    if (highest_rate_flow) {
        printf("Highest rate flow: Src IP %s, Dst IP %s, Src Port %u, Dst Port %u, Protocol %u, Average Packet Size %lu\n",
               highest_rate_flow->src_ip, highest_rate_flow->dst_ip, highest_rate_flow->src_port,
               highest_rate_flow->dst_port, highest_rate_flow->protocol, (unsigned long)max_rate);
    }
}

void *handle_user_queries(void *arg) {
    char query[256];

    while (running) {
        printf("-----------------------------------------------------------------------\n");
        printf("Enter query (e.g., 'rank packet size', 'rank packet rate'): ");
        if (fgets(query, sizeof(query), stdin) == NULL) {
            continue; // 如果读取失败，则继续下一次循环
        }

        // 移除末尾的换行符
        size_t len = strlen(query);
        if (len > 0 && query[len - 1] == '\n') {
            query[--len] = '\0';
        }

        // 根据用户输入的查询调用 rankFlows
        if (strcmp(query, "rank packet size") == 0) {
            rankFlows("packet size");
        } else if (strcmp(query, "rank packet rate") == 0) {
            rankFlows("packet rate");
        } else {
            printf("Invalid query. Please enter 'rank packet size' or 'rank packet rate'.\n");
        }
    }

    return NULL;
}



// 命令行查詢處理函數
void handleUserQuery() {
    // Your code for handling user input
    char query[256];
    while (running) {
        printf("-----------------------------------------------------------------------");
        printf("Enter query (e.g., 'src IP','dst IP', 'src port'...etc): ");
        scanf("%255s", query);

        if (strcmp(query, "src IP") == 0) {
            displaySrcIPStats();
        }
        // Handle other queries similarly
    }
}
// 比較函數，用於 qsort
int compare(const void *a, const void *b) {
    CountStruct *countA = (CountStruct *)a;
    CountStruct *countB = (CountStruct *)b;
    return (countB->count - countA->count); // 降序
}

// 排序並打印結果
void sortAndPrint(CountStruct *array, int size) {
    for (int i = 0; i < size; i++) {
        printf("%s: %lu\n", array[i].ip, array[i].count);
    }
}

int compareCountDesc(const void *a, const void *b) {
    const CountStruct *statsA = (const CountStruct *)a;
    const CountStruct *statsB = (const CountStruct *)b;
    // For descending order, flip the operands
    return (statsB->count - statsA->count);
}

void displaySrcIPStats() {
    // Array to hold counts for each unique source IP
    CountStruct srcIPCounts[HASH_TABLE_SIZE];
    int srcIPCount = 0;

    // Populate srcIPCounts with counts of each unique source IP
    for (int i = 0; i < HASH_TABLE_SIZE; ++i) {
        FlowStats *entry = &hash_table[i];
        if (entry->packet_count == 0) continue; // Skip empty entries

        // Check if this IP is already in srcIPCounts
        int found = 0;
        for (int j = 0; j < srcIPCount; ++j) {
            if (strcmp(srcIPCounts[j].ip, entry->src_ip) == 0) {
                srcIPCounts[j].count += entry->packet_count;
                found = 1;
                break;
            }
        }

        // If this is a new IP, add it to srcIPCounts
        if (!found) {
            strcpy(srcIPCounts[srcIPCount].ip, entry->src_ip);
            srcIPCounts[srcIPCount].count = entry->packet_count;
            srcIPCount++;
        }
    }

    // Sort the array of counts
    qsort(srcIPCounts, srcIPCount, sizeof(CountStruct), compareCountDesc);

    // Display the sorted array
    for (int i = 0; i < srcIPCount; ++i) {
        printf("%s: %lu\n", srcIPCounts[i].ip, srcIPCounts[i].count);
    }
}


// Function to display Destination IP statistics
void displayDstIPStats() {
    CountStruct dstIPCounts[HASH_TABLE_SIZE];
    int dstIPCount = 0;

    // Populate dstIPCounts with counts of each unique destination IP
    for (int i = 0; i < HASH_TABLE_SIZE; ++i) {
        FlowStats *entry = &hash_table[i];
        if (entry->packet_count == 0) continue; // Skip empty entries

        // Check if this IP is already in dstIPCounts
        int found = 0;
        for (int j = 0; j < dstIPCount; ++j) {
            if (strcmp(dstIPCounts[j].ip, entry->dst_ip) == 0) {
                dstIPCounts[j].count += entry->packet_count;
                found = 1;
                break;
            }
        }

        // If this is a new IP, add it to dstIPCounts
        if (!found) {
            strcpy(dstIPCounts[dstIPCount].ip, entry->dst_ip);
            dstIPCounts[dstIPCount].count = entry->packet_count;
            dstIPCount++;
        }
    }

    // Sort the array of counts
    qsort(dstIPCounts, dstIPCount, sizeof(CountStruct), compareCountDesc);

    // Display the sorted array
    for (int i = 0; i < dstIPCount; ++i) {
        printf("%s: %lu\n", dstIPCounts[i].ip, dstIPCounts[i].count);
    }
}


void displaySrcPortStats() {
    CountStruct srcPortCounts[HASH_TABLE_SIZE];
    int srcPortCount = 0;

    // Populate srcPortCounts with counts of each unique source port
    for (int i = 0; i < HASH_TABLE_SIZE; ++i) {
        FlowStats *entry = &hash_table[i];
        if (entry->packet_count == 0) continue; // Skip empty entries

        // Update srcPortCounts with this entry's source port
        int found = 0;
        for (int j = 0; j < srcPortCount; ++j) {
            if (srcPortCounts[j].port == entry->src_port) {
                srcPortCounts[j].count += entry->packet_count;
                found = 1;
                break;
            }
        }

        // If this is a new port, add it to srcPortCounts
        if (!found) {
            srcPortCounts[srcPortCount].port = entry->src_port;
            srcPortCounts[srcPortCount].count = entry->packet_count;
            srcPortCount++;
        }
    }

    // Sort the array of counts
    qsort(srcPortCounts, srcPortCount, sizeof(CountStruct), compareCountDesc);

    // Display the sorted array
    for (int i = 0; i < srcPortCount; ++i) {
        printf("%u: %lu\n", srcPortCounts[i].port, srcPortCounts[i].count);
    }
}

void displayDstPortStats() {
    CountStruct dstPortCounts[HASH_TABLE_SIZE];
    int dstPortCount = 0;

    // Populate dstPortCounts with counts of each unique destination port
    for (int i = 0; i < HASH_TABLE_SIZE; ++i) {
        FlowStats *entry = &hash_table[i];
        if (entry->packet_count == 0) continue;

        // Update dstPortCounts with this entry's destination port
        int found = 0;
        for (int j = 0; j < dstPortCount; ++j) {
            if (dstPortCounts[j].port == entry->dst_port) {
                dstPortCounts[j].count += entry->packet_count;
                found = 1;
                break;
            }
        }

        // If this is a new port, add it to dstPortCounts
        if (!found) {
            dstPortCounts[dstPortCount].port = entry->dst_port;
            dstPortCounts[dstPortCount].count = entry->packet_count;
            dstPortCount++;
        }
    }

    // Sort the array of counts
    qsort(dstPortCounts, dstPortCount, sizeof(CountStruct), compareCountDesc);

    // Display the sorted array
    for (int i = 0; i < dstPortCount; ++i) {
        printf("%u: %lu\n", dstPortCounts[i].port, dstPortCounts[i].count);
    }
}

// Function to display Protocol statistics
void displayProtocolStats() {
    CountStruct protocolCounts[HASH_TABLE_SIZE];
    int protocolCount = 0;

    // Populate protocolCounts with counts of each unique protocol
    for (int i = 0; i < HASH_TABLE_SIZE; ++i) {
        FlowStats *entry = &hash_table[i];
        if (entry->packet_count == 0) continue;

        // Update protocolCounts with this entry's protocol
        int found = 0;
        for (int j = 0; j < protocolCount; ++j) {
            if (protocolCounts[j].protocol == entry->protocol) {
                protocolCounts[j].count += entry->packet_count;
                found = 1;
                break;
            }
        }

        // If this is a new protocol, add it to protocolCounts
        if (!found) {
            protocolCounts[protocolCount].protocol = entry->protocol;
            protocolCounts[protocolCount].count = entry->packet_count;
            protocolCount++;
        }
    }

    // Sort the array of counts
    qsort(protocolCounts, protocolCount, sizeof(CountStruct), compareCountDesc);

    // Display the sorted array
    for (int i = 0; i < protocolCount; ++i) {
        printf("%u: %lu\n", protocolCounts[i].protocol, protocolCounts[i].count);
    }
}

// Function to display Packet Size statistics
void displayPacketSizeStats() {
    // Sort hash_table by packet size using the correct comparison function
    qsort(hash_table, HASH_TABLE_SIZE, sizeof(FlowStats), compareByPacketSize);

    // Print the sorted results along with IP, port, and protocol
    for (int i = 0; i < HASH_TABLE_SIZE; ++i) {
        if (hash_table[i].packet_count > 0) { // Ensure there is data to print
            printf("IP: %s -> %s, Port: %u -> %u, Protocol: %u, Packet Size: %lu\n",
                   hash_table[i].src_ip,
                   hash_table[i].dst_ip,
                   hash_table[i].src_port,
                   hash_table[i].dst_port,
                   hash_table[i].protocol,
                   hash_table[i].packet_size);
        }
    }
}


// Function to display Packet Rate statistics
void displayPacketRateStats() {
    // Sort hash_table by packet rate using the correct comparison function
    qsort(hash_table, HASH_TABLE_SIZE, sizeof(FlowStats), compareByPacketRate);

    // Print the sorted results along with IP, port, and protocol
    for (int i = 0; i < HASH_TABLE_SIZE; ++i) {
        if (hash_table[i].packet_count > 0) { // Ensure there is data to print
            printf("IP: %s -> %s, Port: %u -> %u, Protocol: %u, Packet Rate: %f packets/s\n",
                   hash_table[i].src_ip,
                   hash_table[i].dst_ip,
                   hash_table[i].src_port,
                   hash_table[i].dst_port,
                   hash_table[i].protocol,
                   (double)hash_table[i].packet_size / hash_table[i].packet_count);
        }
    }
}



int main() {
    pcap_if_t *alldevsp, *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    char query[100];


    signal(SIGINT, handleSignal);
    signal(SIGTERM, handleExitSignal);


    struct sigaction sa_common, sa_rate;
    memset(&sa_common, 0, sizeof(sa_common));
    sa_common.sa_handler = &handlePrintCommonSignal;
    sigaction(SIGUSR2, &sa_common, NULL);

    memset(&sa_rate, 0, sizeof(sa_rate));
    sa_rate.sa_handler = &handlePrintRateSignal;
    sigaction(SIGTERM, &sa_rate, NULL);
    
        
    if (root == NULL) {
    root = createNode(1); // Initialize root as a leaf node
}

    // 使用 pcap_findalldevs 获取所有网络设备
    if (pcap_findalldevs(&alldevsp, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return(2);
    }

    // 选择第一个网络设备
    device = alldevsp;
    if (device == NULL) {
        fprintf(stderr, "No devices found.\n");
        return(2);
    }
    printf("Using device: %s\n", device->name);

    // 以下为打开设备和捕获数据包的代码...
        handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device->name, errbuf);
        pcap_freealldevs(alldevsp); // Release the device list
        return(2);
    }

    // Declare the thread for handling user queries
    pthread_t query_thread;
    if (pthread_create(&query_thread, NULL, handle_user_queries, NULL) != 0) {
        fprintf(stderr, "Error creating query thread\n");
        return(1);
    }
    
    
    // 進行流量擷取
    while (running) {
        pcap_dispatch(handle, -1, got_packet, NULL);

        if (print_common_flag) {
            print_most_common();
            print_common_flag = 0; // Reset the flag after printing
        }

        if (print_rate_flag) {
            print_highest_rate();
            print_rate_flag = 0; // Reset the flag after printing
        }
    }
    while (1) {
        printf("Enter query: ");
        scanf("%99s", query);

        // 根据输入调用相应的函数
        if (strcmp(query, "src IP") == 0) {
            displaySrcIPStats();
        } else if (strcmp(query, "dst IP") == 0) {
            displayDstIPStats();
        } else if (strcmp(query, "src port") == 0) {
            displaySrcPortStats();
        } else if (strcmp(query, "dst port") == 0) {
            displayDstPortStats();
        } else if (strcmp(query, "protocol") == 0) {
            displayProtocolStats();
        } else if (strcmp(query, "packet size") == 0) {
            displayPacketSizeStats();
        } else if (strcmp(query, "packet rate") == 0) {
            displayPacketRateStats();
        } else {
            printf("Invalid query.\n");
        }
    }
    handleUserQuery();
    
    //print_most_common_src_ip();
    print_most_common();
    print_highest_rate();
    pthread_join(query_thread, NULL);

    // Cleanup
    pthread_join(query_thread, NULL);
    pcap_freealldevs(alldevsp);
    pcap_close(handle); 
    return(0);
    
}

