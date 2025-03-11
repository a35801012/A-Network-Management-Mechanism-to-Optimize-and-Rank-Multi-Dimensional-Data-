//bpt.c

#include <stdio.h>
#include <stdlib.h>

#define MAX_KEYS 4  // 节点中最大键的数量

typedef struct BPlusTreeNode {
    int keys[MAX_KEYS];
    int numKeys;
    struct BPlusTreeNode *children[MAX_KEYS + 1];
    struct BPlusTreeNode *next;
    int isLeaf;
} BPlusTreeNode;

// 函数原型声明
BPlusTreeNode *createNode(int isLeaf);
BPlusTreeNode *findLeafNode(BPlusTreeNode *root, int key);
void insertInLeafNode(BPlusTreeNode *leaf, int key);
BPlusTreeNode *splitAndInsertInLeafNode(BPlusTreeNode *leaf, int key);
void insertInParentNode(BPlusTreeNode **root, BPlusTreeNode *leaf, int key, BPlusTreeNode *newLeaf);
void insert(BPlusTreeNode **root, int key);
void printTree(BPlusTreeNode *root, int level);
BPlusTreeNode *findParent(BPlusTreeNode *root, BPlusTreeNode *child);



BPlusTreeNode *createNode(int isLeaf) {
    BPlusTreeNode *node = (BPlusTreeNode *)malloc(sizeof(BPlusTreeNode));
    node->numKeys = 0;
    node->isLeaf = isLeaf;
    node->next = NULL;
    for (int i = 0; i < MAX_KEYS + 1; i++) {
        node->children[i] = NULL;
    }
    return node;
}

BPlusTreeNode *findLeafNode(BPlusTreeNode *root, int key) {
    BPlusTreeNode *current = root;
    while (!current->isLeaf) {
        int i = 0;
        while (i < current->numKeys && key >= current->keys[i]) {
            i++;
        }
        current = current->children[i];
    }
    return current;
}

void insertInLeafNode(BPlusTreeNode *leaf, int key) {
    int i = leaf->numKeys - 1;
    while (i >= 0 && leaf->keys[i] > key) {
        leaf->keys[i + 1] = leaf->keys[i];
        i--;
    }
    leaf->keys[i + 1] = key;
    leaf->numKeys++;
}

BPlusTreeNode *splitAndInsertInLeafNode(BPlusTreeNode *leaf, int key) {
    BPlusTreeNode *newLeaf = createNode(1);
    int tempKeys[MAX_KEYS + 1];
    int i, j;

    for (i = 0; i < MAX_KEYS; i++) {
        tempKeys[i] = leaf->keys[i];
    }
    i = MAX_KEYS - 1;
    while (i >= 0 && tempKeys[i] > key) {
        tempKeys[i + 1] = tempKeys[i];
        i--;
    }
    tempKeys[i + 1] = key;

    leaf->numKeys = (MAX_KEYS + 1) / 2;
    for (i = 0; i < leaf->numKeys; i++) {
        leaf->keys[i] = tempKeys[i];
    }

    newLeaf->numKeys = MAX_KEYS + 1 - leaf->numKeys;
    for (i = 0, j = leaf->numKeys; i < newLeaf->numKeys; i++, j++) {
        newLeaf->keys[i] = tempKeys[j];
    }

    newLeaf->next = leaf->next;
    leaf->next = newLeaf;

    return newLeaf;
}

void insertInParentNode(BPlusTreeNode **root, BPlusTreeNode *leaf, int key, BPlusTreeNode *newLeaf) {
    if (leaf == *root) {
        BPlusTreeNode *newRoot = createNode(0);
        newRoot->keys[0] = key;
        newRoot->children[0] = leaf;
        newRoot->children[1] = newLeaf;
        newRoot->numKeys = 1;
        *root = newRoot;
        return;
    }

    BPlusTreeNode *parent = findParent(*root, leaf);
    int i = parent->numKeys - 1;

    if (parent->numKeys < MAX_KEYS) {
        while (i >= 0 && parent->keys[i] > key) {
            parent->keys[i + 1] = parent->keys[i];
            parent->children[i + 2] = parent->children[i + 1];
            i--;
        }
        parent->keys[i + 1] = key;
        parent->children[i + 2] = newLeaf;
        parent->numKeys++;
    } else {
        // 需要分裂父节点的逻辑
    }
}

void insert(BPlusTreeNode **root, int key) {
    BPlusTreeNode *oldRoot = *root;

    if (oldRoot == NULL) {
        *root = createNode(1);
        (*root)->keys[0] = key;
        (*root)->numKeys = 1;
    } else {
        BPlusTreeNode *leaf = findLeafNode(oldRoot, key);

        if (leaf->numKeys < MAX_KEYS) {
            insertInLeafNode(leaf, key);
        } else {
            BPlusTreeNode *newLeaf = splitAndInsertInLeafNode(leaf, key);
            insertInParentNode(root, leaf, newLeaf->keys[0], newLeaf);
        }
    }
}

void printTree(BPlusTreeNode *root, int level) {
    if (root == NULL) return;

    printf("Level %d: ", level);
    for (int i = 0; i < root->numKeys; i++) {
        printf("%d ", root->keys[i]);
    }
    printf("\n");

    if (!root->isLeaf) {
        for (int i = 0; i <= root->numKeys; i++) {
            printTree(root->children[i], level + 1);
        }
    }
}

BPlusTreeNode *findParent(BPlusTreeNode *root, BPlusTreeNode *child) {
    if (root == NULL || root->isLeaf || root == child) {
        return NULL;
    }

    for (int i = 0; i <= root->numKeys; i++) {
        if (root->children[i] == child) {
            return root;
        }

        BPlusTreeNode *potentialParent = findParent(root->children[i], child);
        if (potentialParent != NULL) {
            return potentialParent;
        }
    }

    return NULL;
}

int main() {
    BPlusTreeNode *root = NULL;
    int choice, key;

    while (1) {
        printf("\n1. Insert\n2. Search\n3. Display Tree\n4. Exit\nEnter your choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                printf("Enter key to insert: ");
                scanf("%d", &key);
                insert(&root, key);
                printTree(root, 0);
                break;
            case 2:
                printf("Enter key to search: ");
                scanf("%d", &key);
                BPlusTreeNode *leaf = findLeafNode(root, key);
                int found = 0;
                for (int i = 0; i < leaf->numKeys; i++) {
                    if (leaf->keys[i] == key) {
                        found = 1;
                        break;
                    }
                }
                if (found) {
                    printf("Key %d found.\n", key);
                } else {
                    printf("Key %d not found.\n", key);
                }
                printTree(root, 0);
                break;
            case 3:
                printTree(root, 0);
                break;
            case 4:
                return 0;
            default:
                printf("Invalid choice.\n");
        }
    }

    return 0;
}
