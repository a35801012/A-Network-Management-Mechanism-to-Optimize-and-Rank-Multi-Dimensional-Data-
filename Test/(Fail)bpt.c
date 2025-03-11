//2


#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <string.h>
#include <time.h>
#include <signal.h> 
#include <stdbool.h> // 添加对bool类型的支持

#define MAX_KEYS 4
#define MIN_KEYS (MAX_KEYS / 2)
#define MAX_CHILDREN (MAX_KEYS + 1)

volatile sig_atomic_t stop_capture = 0; // 全局变量，用于停止捕获

typedef struct PacketInfo {
    int key; // 使用时间戳作为键值
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    unsigned int protocol;
    int src_port;
    int dst_port;
} PacketInfo;

typedef struct BPlusTreeNode {
    int numKeys;
    int keys[MAX_KEYS];
    PacketInfo* packetInfos[MAX_KEYS];
    struct BPlusTreeNode* children[MAX_CHILDREN];
    bool isLeaf;
} BPlusTreeNode;

BPlusTreeNode* root = NULL;

// B+树的节点创建、分裂和插入操作的函数声明
BPlusTreeNode* createNode(bool isLeaf) {
    BPlusTreeNode* node = (BPlusTreeNode*)malloc(sizeof(BPlusTreeNode));
    if (node == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }   


    node->isLeaf = isLeaf;
    node->numKeys = 0;
    for (int i = 0; i < MAX_KEYS; i++) {
        node->packetInfos[i] = NULL;
    }
    for (int i = 0; i < MAX_CHILDREN; i++) {
        node->children[i] = NULL;
    }
    return node;
}

void insertPacketInfo(BPlusTreeNode* node, PacketInfo* pInfo);
void splitChild(BPlusTreeNode* parent, int childIndex, BPlusTreeNode* child);
void insertNonFull(BPlusTreeNode* node, int key, PacketInfo* packetInfo);
void insert(int key, PacketInfo* packetInfo);
void printBPlusTree(BPlusTreeNode* node, int level);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void freeBPlusTree(BPlusTreeNode* node);

void handle_signal(int signal) {
    stop_capture = 1;
    if (root != NULL) {
        printBPlusTree(root, 0); // 打印B+树的内容
        freeBPlusTree(root); // 释放B+树
        root = NULL;
    }
    exit(0); // 安全退出程序
}


void printBPlusTree(BPlusTreeNode* node, int level) {
    if (node == NULL) return;

    printf("Level %d, Num keys: %d, Keys: ", level, node->numKeys);
    for (int i = 0; i < node->numKeys; ++i) {
        // 假设这些键是IP地址，这里需要将它们转换为人类可读的形式
        // 这只是一个示例，具体实现取决于您的键代表什么
        unsigned int ip = node->keys[i]; // 假设键是IP地址
        printf("%u.%u.%u.%u ", ip >> 24, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
    }
    printf("\n");

    // 如果节点是内部节点，递归打印子树
    if (!node->isLeaf) {
        for (int i = 0; i <= node->numKeys; ++i) {
            printBPlusTree(node->children[i], level + 1);
        }
    }
}


void splitChild(BPlusTreeNode* parent, int childIndex, BPlusTreeNode* child) {
    BPlusTreeNode* newChild = createNode(child->isLeaf);
    newChild->numKeys = MIN_KEYS;

    for (int i = 0; i < MIN_KEYS; ++i) {
        newChild->keys[i] = child->keys[i + MIN_KEYS + 1];
        newChild->packetInfos[i] = child->packetInfos[i + MIN_KEYS + 1];
    }

    if (!child->isLeaf) {
        for (int i = 0; i <= MIN_KEYS; ++i) {
            newChild->children[i] = child->children[i + MIN_KEYS + 1];
        }
    }

    child->numKeys = MIN_KEYS;

    for (int i = parent->numKeys; i >= childIndex + 1; --i) {
        parent->children[i + 1] = parent->children[i];
    }
    parent->children[childIndex + 1] = newChild;

    for (int i = parent->numKeys - 1; i >= childIndex; --i) {
        parent->keys[i + 1] = parent->keys[i];
        parent->packetInfos[i + 1] = parent->packetInfos[i];
    }

    parent->keys[childIndex] = child->keys[MIN_KEYS];
    parent->packetInfos[childIndex] = child->packetInfos[MIN_KEYS];
    parent->numKeys++;
}

void insertNonFull(BPlusTreeNode* node, int key, PacketInfo* packetInfo) {
    int i = node->numKeys - 1;

    if (node->isLeaf) {
        while (i >= 0 && node->keys[i] > key) {
            node->keys[i + 1] = node->keys[i];
            node->packetInfos[i + 1] = node->packetInfos[i];
            i--;
        }
        node->keys[i + 1] = key;
        node->packetInfos[i + 1] = packetInfo;
        node->numKeys++;
    } else {
        while (i >= 0 && node->keys[i] > key) {
            i--;
        }
        if (node->children[i + 1]->numKeys == MAX_KEYS) {
            splitChild(node, i + 1, node->children[i + 1]);
            if (key > node->keys[i + 1]) {
                i++;
            }
        }
        insertNonFull(node->children[i + 1], key, packetInfo);
    }
}

void insert(int key, PacketInfo* packetInfo) {
    if (!root) {
        root = createNode(true);  // 创建一个新的根节点，它是一个叶子节点
        root->keys[0] = key;
        root->packetInfos[0] = packetInfo;
        root->numKeys = 1;  // 更新根节点的键数
    } else {
        BPlusTreeNode* oldRoot = root;
        if (oldRoot->numKeys == MAX_KEYS) {  // 根节点已满
            BPlusTreeNode* newRoot = createNode(false);  // 创建一个新的根节点，它是一个内部节点
            root = newRoot;
            newRoot->children[0] = oldRoot;
            splitChild(newRoot, 0, oldRoot);  // 分裂旧的根节点
            insertPacketInfo(newRoot, packetInfo);  // 将新的封包信息插入到新的根节点
        } else {
            insertPacketInfo(oldRoot, packetInfo);  // 根节点未满，直接在旧的根节点中插入新的封包信息
        }
    }
}

void insertPacketInfo(BPlusTreeNode* node, PacketInfo* pInfo) {
    int key = pInfo->key;
    int i = node->numKeys - 1;

    if (node->isLeaf) {
        // 在叶子节点中，找到插入新键的位置
        while (i >= 0 && node->keys[i] > key) {
            node->keys[i + 1] = node->keys[i];
            node->packetInfos[i + 1] = node->packetInfos[i];
            i--;
        }
        node->keys[i + 1] = key;
        node->packetInfos[i + 1] = pInfo;
        node->numKeys++;
    } else {
        // 在内部节点中，找到应该插入新键的子节点
        while (i >= 0 && node->keys[i] > key) {
            i--;
        }
        i++;

        // 如果子节点已满，先分裂子节点
        if (node->children[i]->numKeys == MAX_KEYS) {
            splitChild(node, i, node->children[i]);
            if (key > node->keys[i]) {
                i++;
            }
        }
        insertPacketInfo(node->children[i], pInfo);
    }
}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->daddr), dst_ip, INET_ADDRSTRLEN);

    PacketInfo* pInfo = (PacketInfo*)malloc(sizeof(PacketInfo));
    pInfo->key = header->ts.tv_sec;
    strcpy(pInfo->src_ip, src_ip);
    strcpy(pInfo->dst_ip, dst_ip);
    pInfo->protocol = ip_header->protocol;
    
    if (stop_capture) {
        pcap_breakloop((pcap_t*)args);  // 停止捕获
        return;
    }
    
    if (ip_header->protocol == IPPROTO_TCP) {
        struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct ethhdr) + ip_header->ihl * 4);
        pInfo->src_port = ntohs(tcp_header->source);
        pInfo->dst_port = ntohs(tcp_header->dest);
    } else if (ip_header->protocol == IPPROTO_UDP) {
        struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct ethhdr) + ip_header->ihl * 4);
        pInfo->src_port = ntohs(udp_header->source);
        pInfo->dst_port = ntohs(udp_header->dest);
    } else {
        pInfo->src_port = 0;
        pInfo->dst_port = 0;
    }

    if (!root) {
        root = createNode(true);
    }
    insertPacketInfo(root, pInfo);
}

void freePacketInfo(PacketInfo* pInfo) {
    if (pInfo != NULL) {
        free(pInfo);
    }
}

// 递归释放B+树节点和它们包含的PacketInfo结构
void freeBPlusTree(BPlusTreeNode* node) {
    if (node == NULL) return;

    if (node->isLeaf) {
        for (int i = 0; i < node->numKeys; i++) {
            free(node->packetInfos[i]);  // 释放 PacketInfo 结构
        }
    } else {
        for (int i = 0; i <= node->numKeys; i++) {
            freeBPlusTree(node->children[i]);
        }
    }
    free(node);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *device;
    pcap_t *handle;
    char filter_exp[] = "ip";
    struct bpf_program fp;
    bpf_u_int32 net;
    
    signal(SIGINT, handle_signal);
    
    // 使用pcap_findalldevs获取设备列表
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Couldn't find devices: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    // 选择设备列表中的第一个设备
    device = alldevs;
    if (device == NULL) {
        fprintf(stderr, "No devices found.\n");
        exit(EXIT_FAILURE);
    }

    // 使用选定的设备打开会话
    handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device->name, errbuf);
        exit(EXIT_FAILURE);
    }

    // 编译并应用过滤器
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    // 捕获封包
    pcap_loop(handle, 0, got_packet, NULL);  // 只捕获10个封包

    
    printf("捕获停止，进入查询模式。\n");
    if (root != NULL) {
        printBPlusTree(root, 0);
        freeBPlusTree(root);
    }

    // 清理和关闭
    
    freeBPlusTree(root);
    pcap_freecode(&fp);
    pcap_close(handle);
    pcap_freealldevs(alldevs); // 释放设备列表

    return 0;
}
