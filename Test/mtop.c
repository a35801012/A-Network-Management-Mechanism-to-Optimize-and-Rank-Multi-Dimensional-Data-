#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//2

typedef struct DataNode {
    int data;
    struct FlowNode* flow;
    struct TimeNode* time;
    struct DataNode* nextData; 
} DataNode;

typedef struct FlowNode {
    char IP[50];
    int src_port; 
    int dst_port; 
    int protocol;  
    DataNode* datas; 
    struct FlowNode* nextFlow; 
} FlowNode;

typedef struct TimeNode {
    char IP[50];
    struct TimeNode* nextTime; 
} TimeNode;


// 函数声明
FlowNode* findFlow(FlowNode* head, const char* IP);
void updateFlowAttribute(FlowNode* flow, const char* attribute, int newValue);
TimeNode* findOrAddTime(TimeNode** headTime, char* IP);
void insertData(FlowNode* flow, TimeNode* time, int data);

FlowNode* findOrAddFlow(FlowNode** headFlow, char* IP) {
    FlowNode* current = *headFlow;
    FlowNode* last = NULL;
    while (current != NULL) {
        if (strcmp(current->IP, IP) == 0) {
            return current; 
        }
        last = current;
        current = current->nextFlow;
    }
    FlowNode* newFlow = (FlowNode*)malloc(sizeof(FlowNode));
    strcpy(newFlow->IP, IP);
    newFlow->datas = NULL;
    newFlow->nextFlow = NULL;
    if (last == NULL) { 
        *headFlow = newFlow;
    } else {
        last->nextFlow = newFlow;
    }
    return newFlow;
}

TimeNode* findOrAddTime(TimeNode** headTime, char* IP) {
    TimeNode* current = *headTime;
    TimeNode* last = NULL;
    while (current != NULL) {
        if (strcmp(current->IP, IP) == 0) {
            return current; 
        }
        last = current;
        current = current->nextTime;
    }
    
    TimeNode* newTime = (TimeNode*)malloc(sizeof(TimeNode));
    strcpy(newTime->IP, IP);
    newTime->nextTime = NULL;
    if (last == NULL) { 
        *headTime = newTime;
    } else {
        last->nextTime = newTime;
    }
    return newTime;
}

void insertData(FlowNode* flow, TimeNode* time, int data) {
    DataNode* newData = (DataNode*)malloc(sizeof(DataNode));
    newData->data = data;
    newData->flow = flow;
    newData->time = time;
    newData->nextData = flow->datas;
    flow->datas = newData; 
}

FlowNode* findFlow(FlowNode* head, const char* IP) {
    while (head != NULL) {
        if (strcmp(head->IP, IP) == 0) {
            return head;
        }
        head = head->nextFlow;
    }
    return NULL; 
}


void updateFlowAttribute(FlowNode* flow, const char* attribute, int newValue) {
    if (strcmp(attribute, "src_port") == 0) {
        flow->src_port = newValue;
    } else if (strcmp(attribute, "dst_port") == 0) {
        flow->dst_port = newValue;
    } else if (strcmp(attribute, "protocol") == 0) {
        flow->protocol = newValue;
    } else {
        printf("未知屬性。\n");
    }
}


void queryFlow(FlowNode* head, const char* IP) {
    FlowNode* current = head;
    while (current != NULL) {
        if (strcmp(current->IP, IP) == 0) {
            printf("IP: %s\n", current->IP);
            printf("SourcePort: %d\n", current->src_port);
            printf("DestinationPort: %d\n", current->dst_port);
            printf("Protocol: %d\n", current->protocol);

            DataNode* data = current->datas;
            while (data != NULL) {
                printf("時間: %s,　封包資訊: %d\n", data->time->IP, data->data);
                data = data->nextData;
            }
            return;
        }
        current = current->nextFlow;
    }
    printf("沒有找到該流量: %s\n", IP);
}


void freeData(DataNode* data) {
    while (data != NULL) {
        DataNode* tempdata = data;
        data = data->nextData;
        free(tempdata);
    }
}

void freeTimeList(TimeNode* headTime) {
    while (headTime != NULL) {
        TimeNode* tempTime = headTime;
        headTime = headTime->nextTime;
        free(tempTime);  
    }
}


void freeFlowList(FlowNode* headFlow) {
    while (headFlow != NULL) {
        freeData(headFlow->datas); 
        FlowNode* tempFlow = headFlow;
        headFlow = headFlow->nextFlow;
        free(tempFlow); 
    }
}

double calculateDataStructureSizeMB(FlowNode* headFlow, TimeNode* headTime) {
    double totalSize = 0;

    FlowNode* currentFlow = headFlow;
    while (currentFlow != NULL) {
        totalSize += sizeof(FlowNode);
        DataNode* data = currentFlow->datas;
        while (data != NULL) {
            totalSize += sizeof(DataNode);
            data = data->nextData;
        }
        currentFlow = currentFlow->nextFlow;
    }


    TimeNode* currentTime = headTime;
    while (currentTime != NULL) {
        totalSize += sizeof(TimeNode);
        currentTime = currentTime->nextTime;
    }
    return totalSize / (1024.0 * 1024.0);
}


void printDataStructure(TimeNode* headTime) {
    TimeNode* current_time;
    FlowNode* current_flow;
    DataNode* current_data;

    // 打印時間結構
    printf("(時間結構)：\n");
    for (current_time = headTime; current_time != NULL; current_time = current_time->nextTime) {
        printf("[%s] -> ", current_time->timestamp);
    }
    printf("[結束]\n");

    // 對於每個時間結點，遍歷並打印對應的流量節點和數據節點
    for (current_time = headTime; current_time != NULL; current_time = current_time->nextTime) {
        // 打印直接連接到時間節點下方的箭頭
        printf("    |    ");
        printf("\n    V    \n");

        // 遍歷與此時間結點相關的所有流量結點
        for (current_flow = current_time->flows; current_flow != NULL; current_flow = current_flow->nextFlow) {
            printf("[%s:%d -> %s:%d] -> ", current_flow->src_IP, current_flow->src_port, current_flow->dst_IP, current_flow->dst_port);
            // 遍歷與此流量結點相關的所有數據節點
            for (current_data = current_flow->datas; current_data != NULL; current_data = current_data->nextData) {
                if (current_data->time == current_time) {
                    printf("[%d] -> ", current_data->data);
                }
            }
            // 如果此流量節點沒有更多數據節點，打印 [x]
            printf("[結束]\n");
        }
        printf("\n");  // 在每個時間節點後打印換行，為下一個時間節點做準備
    }
}


int main() {
    FlowNode* headFlow = NULL;
    TimeNode* headTime = NULL;

    char FlowIP[50];
    char Timestamp[50];
    int data;
    char mode;
    char inputType;

    do {
        printf("選擇模式：\n");
        printf("1. 輸入模式\n");
        printf("2. 查詢模式\n");
        printf("3. 退出\n");
        scanf(" %c", &mode); 

        if (mode == '1') {
            printf("選擇輸入類型：\n");
            printf("a. 更新現有資料\n");
            printf("b. 新增資料\n");
            scanf(" %c", &inputType);

            if (inputType == 'a') {
                printf("請輸入流量資訊: ");
                scanf("%49s", FlowIP);
                FlowNode* flow = findFlow(headFlow, FlowIP);
                if (flow) {
                    printf("請輸入要更新的屬性 (src_port, dst_port, protocol): ");
                    char attribute[50];
                    scanf("%49s", attribute);
                    int newValue;
                    printf("請輸入新值: ");
                    scanf("%d", &newValue);
                    updateFlowAttribute(flow, attribute, newValue);
                } else {
                    printf("流量不存在。\n");
                }
            } else if (inputType == 'b') {
                printf("請輸入流量資訊: ");
                scanf("%49s", FlowIP);
                printf("請輸入時間: ");
                scanf("%49s", Timestamp);
                printf("請輸入封包資訊: ");
                scanf("%d", &data);
                FlowNode* flow = findOrAddFlow(&headFlow, FlowIP);
                TimeNode* time = findOrAddTime(&headTime, Timestamp);
                insertData(flow, time, data);
            } else {
                printf("無效輸入。\n");
            }
        } else if (mode == '2') {
    char queryIP[50];
    printf("輸入要查詢的流量資訊: ");
    scanf("%49s", queryIP);

    while (getchar() != '\n');

    queryFlow(headFlow, queryIP);
    
    printDataStructure(headFlow, headTime);
} else if (mode == '3') {
        double dataSizeMB = calculateDataStructureSizeMB(headFlow, headTime);
    	printf("資料結構大小: %.4f MB\n", dataSizeMB);
        }

        while (getchar() != '\n');

    } while (mode != '3');

    while (getchar() != '\n');
    
    freeFlowList(headFlow);
    freeTimeList(headTime);

    return 0;
}





