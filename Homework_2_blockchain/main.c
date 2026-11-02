
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "merkle_tree.c"

#define MAX_NAME_LENGTH 256

int main() {

    MerkleTree *tree = create_merkle_tree();

    if (tree == NULL) {
        printf("Error creating Merkle Tree.\n");
        return 1;
    }

    FILE *file = fopen("students_2026.txt", "r");

    if (file == NULL) {
        printf("Error opening students.txt\n");
        free_merkle_tree(tree);
        return 1;
    }

    char name[MAX_NAME_LENGTH];
    int count = 0;

    // Read all student names
    while (fgets(name, sizeof(name), file)) {

        name[strcspn(name, "\r\n")] = '\0';

        if (strlen(name) == 0) {
            continue;
        }

        add_element(tree, name);
        count++;
    }

    fclose(file);

    printf("Number of students: %d\n", count);

    // Display all leaf hashes
    printf("\nStudent hashes:\n");
    print_leaf_hashes(tree);

    // Display the Merkle Root
    const unsigned char *root = get_root_hash(tree);

    if (root != NULL) {
        char *root_string = hash_to_string(root);

        printf("\nMerkle Root:\n%s\n", root_string);

        free(root_string);
    }

    const char *my_name = "\"Vasiescu Adriana\"";

    // Generate proof
    MerkleProof *proof = generate_proof(tree, my_name);

    if (proof == NULL) {
        printf("\nStudent not found in the tree!\n");
        free_merkle_tree(tree);
        return 1;
    }

    printf("\nMerkle Proof for: %s\n", my_name);

    printf("Number of siblings: %d\n",
           get_proof_count(proof));

    for (int i = 0; i < get_proof_count(proof); i++) {

        char *sibling = hash_to_string(
            get_proof_sibling(proof, i)
        );

        printf("Sibling %d: %s\n", i + 1, sibling);

        //printf("Direction: %s\n", proof->directions[i] == 1 ? "RIGHT" : "LEFT");

        free(sibling);
    }

    // Verify the proof
    bool valid = verify_proof(root, my_name, proof);

    printf("\nProof verification: %s\n",
           valid ? "SUCCESS" : "FAILED");

    free_merkle_proof(proof);
    free_merkle_tree(tree);

    return 0;
}

