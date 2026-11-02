#include "merkle_tree.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#if defined(__APPLE__)
#include <CommonCrypto/CommonDigest.h>
#define SHA256_DIGEST_LENGTH CC_SHA256_DIGEST_LENGTH
#define SHA256(data, len, hash) CC_SHA256(data, len, hash)
#else
#include <openssl/sha.h>
#endif

#define MAX_HASH_LEN 65
#define HASH_SIZE SHA256_DIGEST_LENGTH
#define MAX_HASH_HEX_LENGTH (HASH_SIZE * 2 + 1)

typedef struct Node {
    unsigned char hash[HASH_SIZE];
    struct Node *left;
    struct Node *right;
    struct Node *parent;
} Node;

struct MerkleTree {
    Node *root;
    Node **leaves;
    int leaf_count;
    int capacity;
};

struct MerkleProof {
    unsigned char **siblings;
    int *directions;
    int count;
};

void *sha256_hash(const void *input, size_t length, unsigned char *output) {
    SHA256((const unsigned char *)input, length, output);
}

char* hash_to_string(const unsigned char *hash) {
    char *output = malloc(MAX_HASH_HEX_LENGTH);
    for(int i = 0; i < HASH_SIZE; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[MAX_HASH_HEX_LENGTH - 1] = 0;
    return output;
}

Node* create_node(const unsigned char *hash) {
    Node *node = malloc(sizeof(Node));
    memcpy(node->hash, hash, HASH_SIZE);
    node->left = NULL;
    node->right = NULL;
    node->parent = NULL;
    return node;
}

MerkleTree* create_merkle_tree() {
    MerkleTree *tree = malloc(sizeof(MerkleTree));
    tree->root = NULL;
    tree->leaves = NULL;
    tree->leaf_count = 0;
    tree->capacity = 0;
    return tree;
}

void add_element(MerkleTree *tree, const char *data) {
    unsigned char hash[HASH_SIZE];
    sha256_hash(data, strlen(data), hash);
    Node *new_node = create_node(hash);

    if (tree->leaf_count == tree->capacity) {
        tree->capacity = tree->capacity == 0 ? 1 : tree->capacity * 2;
        tree->leaves = realloc(tree->leaves, tree->capacity * sizeof(Node*));
    }
    tree->leaves[tree->leaf_count++] = new_node;

    // Rebuild the tree
    int n = tree->leaf_count;
    Node **current_level = tree->leaves;
    while (n > 1) {
        int next_level_size = (n + 1) / 2;
        Node **next_level = malloc(next_level_size * sizeof(Node*));

        for (int i = 0; i < n - 1; i += 2) {
            Node *left = current_level[i];
            Node *right = current_level[i + 1];

            unsigned char combined[HASH_SIZE * 2];
            memcpy(combined, left->hash, HASH_SIZE);
            memcpy(combined + HASH_SIZE, right->hash, HASH_SIZE);

            unsigned char parent_hash[HASH_SIZE];
            sha256_hash(combined, HASH_SIZE * 2, parent_hash);
            Node *parent = create_node(parent_hash);

            parent->left = left;
            parent->right = right;
            left->parent = parent;
            right->parent = parent;

            next_level[i / 2] = parent;
        }

        // If there's an odd number of nodes, promote the last node to the next level
        if (n % 2 != 0) {
            next_level[next_level_size - 1] = current_level[n - 1];
        }

        if (current_level != tree->leaves) {
            free(current_level);
        }
        current_level = next_level;
        n = next_level_size;
    }

    tree->root = current_level[0];
    if (current_level != tree->leaves) {
        free(current_level);
    }
}

bool find_element(MerkleTree *tree, const char *data) {
    unsigned char hash[HASH_SIZE];
    sha256_hash(data, strlen(data), hash);
    for (int i = 0; i < tree->leaf_count; i++) {
        if (memcmp(tree->leaves[i]->hash, hash, HASH_SIZE) == 0) {
            return true;
        }
    }
    return false;
}

void remove_element(MerkleTree *tree, const char *data) {
    unsigned char hash[HASH_SIZE];
    sha256_hash(data, strlen(data), hash);
    for (int i = 0; i < tree->leaf_count; i++) {
        if (memcmp(tree->leaves[i]->hash, hash, HASH_SIZE) == 0) {
            free(tree->leaves[i]);
            for (int j = i; j < tree->leaf_count - 1; j++) {
                tree->leaves[j] = tree->leaves[j + 1];
            }
            tree->leaf_count--;
            // Rebuild the tree
            MerkleTree *new_tree = create_merkle_tree();
            for (int k = 0; k < tree->leaf_count; k++) {
                add_element(new_tree, hash_to_string(tree->leaves[k]->hash));
            }
            free_merkle_tree(tree);
            *tree = *new_tree;
            free(new_tree);
            return;
        }
    }
}


MerkleProof *generate_proof(MerkleTree *tree, const char *data) {

    if (tree == NULL || data == NULL || tree->leaf_count == 0) {
        return NULL;
    }

    // Hash the data we want to prove
    unsigned char target_hash[HASH_SIZE];
    sha256_hash(data, strlen(data), target_hash);

    // Find the leaf containing the requested hash
    int index = -1;

    for (int i = 0; i < tree->leaf_count; i++) {
        if (memcmp(tree->leaves[i]->hash,
                   target_hash, HASH_SIZE) == 0) {
            index = i;
            break;
        }
    }

    // Element does not exist
    if (index == -1) {
        return NULL;
    }

    // Calculate the maximum number of proof levels
    int max_levels = 0;
    int temp = tree->leaf_count;

    while (temp > 1) {
        temp = (temp + 1) / 2;
        max_levels++;
    }

    // Allocate the proof structure
    MerkleProof *proof = calloc(1, sizeof(MerkleProof));

    if (proof == NULL) {
        return NULL;
    }

    if (max_levels > 0) {
        proof->siblings = calloc(max_levels, sizeof(unsigned char *));
        proof->directions = calloc(max_levels, sizeof(int));

        if (proof->siblings == NULL || proof->directions == NULL) {
            free(proof->siblings);
            free(proof->directions);
            free(proof);
            return NULL;
        }
    }

    // Copy all leaf hashes into the current level
    int n = tree->leaf_count;

    unsigned char *current_level = malloc(n * HASH_SIZE);

    if (current_level == NULL) {
        free_merkle_proof(proof);
        return NULL;
    }

    for (int i = 0; i < n; i++) {
        memcpy(current_level + i * HASH_SIZE,
               tree->leaves[i]->hash, HASH_SIZE);
    }

    // Build the proof level by level
    while (n > 1) {

        int sibling_index;

        if (index % 2 == 0) {
            sibling_index = index + 1;
        } else {
            sibling_index = index - 1;
        }

        // Store the sibling if one exists
        if (sibling_index < n) {

            proof->siblings[proof->count] = malloc(HASH_SIZE);

            if (proof->siblings[proof->count] == NULL) {
                free(current_level);
                free_merkle_proof(proof);
                return NULL;
            }

            memcpy(proof->siblings[proof->count],
                   current_level + sibling_index * HASH_SIZE,
                   HASH_SIZE);

            // 1 = current hash is on the left
            // 0 = current hash is on the right
            proof->directions[proof->count] =
                (index % 2 == 0) ? 1 : 0;

            proof->count++;
        }

        // Calculate the next level
        int next_size = (n + 1) / 2;

        unsigned char *next_level =
            malloc(next_size * HASH_SIZE);

        if (next_level == NULL) {
            free(current_level);
            free_merkle_proof(proof);
            return NULL;
        }

        for (int i = 0; i < n; i += 2) {

            if (i + 1 < n) {

                unsigned char combined[HASH_SIZE * 2];

                memcpy(combined,
                       current_level + i * HASH_SIZE,
                       HASH_SIZE);

                memcpy(combined + HASH_SIZE,
                       current_level + (i + 1) * HASH_SIZE,
                       HASH_SIZE);

                sha256_hash(combined, HASH_SIZE * 2,
                            next_level + (i / 2) * HASH_SIZE);

            } else {

                // Promote an unpaired node to the next level
                memcpy(next_level + (i / 2) * HASH_SIZE,
                       current_level + i * HASH_SIZE,
                       HASH_SIZE);
            }
        }

        free(current_level);

        current_level = next_level;
        n = next_size;

        // Move to the parent position
        index = index / 2;
    }

    free(current_level);

    return proof;
}


bool verify_proof(const unsigned char *root_hash, const char *data, MerkleProof *proof) {
    unsigned char current_hash[HASH_SIZE];
    sha256_hash(data, strlen(data), current_hash);

    for (int i = 0; i < proof->count; i++) {
        unsigned char combined[HASH_SIZE * 2];
        if (proof->directions[i] == 1) {
            memcpy(combined, current_hash, HASH_SIZE);
            memcpy(combined + HASH_SIZE, proof->siblings[i], HASH_SIZE);
        } else {
            memcpy(combined, proof->siblings[i], HASH_SIZE);
            memcpy(combined + HASH_SIZE, current_hash, HASH_SIZE);
        }
        sha256_hash(combined, HASH_SIZE * 2, current_hash);
    }

    return memcmp(current_hash, root_hash, HASH_SIZE) == 0;
}

void print_node(Node *node, int depth) {
    if (node == NULL) return;

    for (int i = 0; i < depth; i++) printf("  ");
    char *hash_str = hash_to_string(node->hash);
    printf("%s\n", hash_str);
    free(hash_str);

    print_node(node->left, depth + 1);
    print_node(node->right, depth + 1);
}

void print_tree(MerkleTree *tree) {
    print_node(tree->root, 0);
}

void print_leaf_hashes(MerkleTree *tree) {
    for (int i = 0; i < tree->leaf_count; i++) {
        char *hash_str = hash_to_string(tree->leaves[i]->hash);
        printf("%s\n", hash_str);
        free(hash_str);
    }
}

void free_node(Node *node) {
    if (node == NULL) return;
    free_node(node->left);
    free_node(node->right);
    free(node);
}

void free_merkle_tree(MerkleTree *tree) {
    free_node(tree->root);
    free(tree->leaves);
    free(tree);
}

void free_merkle_proof(MerkleProof *proof) {
    for (int i = 0; i < proof->count; i++) {
        free(proof->siblings[i]);
    }
    free(proof->siblings);
    free(proof->directions);
    free(proof);
}

const unsigned char* get_root_hash(MerkleTree *tree) {
    if (tree && tree->root) {
        return tree->root->hash;
    }
    return NULL;
}

int get_proof_count(MerkleProof *proof) {
    if (proof) {
        return proof->count;
    }
    return 0;
}

const unsigned char* get_proof_sibling(MerkleProof *proof, int index) {
    if (proof && index >= 0 && index < proof->count) {
        return proof->siblings[index];
    }
    return NULL;
}
