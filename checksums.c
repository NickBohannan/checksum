#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#define BUFFER_SIZE 1024

// List of digest types
const char *digest_names[] = {
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha3-224",
    "sha3-256",
    "sha3-384",
    "sha3-512",
    "blake2s256",
    "blake2b512",
    // Add more digest names here as needed
    NULL // Null-terminated list
};

void calculate_checksum(const char *filename, const char *digest_name) {
    FILE *file;
    EVP_MD_CTX *mdctx;
    const EVP_MD *digest_type;
    unsigned char buffer[BUFFER_SIZE];
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    if (!(file = fopen(filename, "rb"))) {
        perror("Failed to open file");
        exit(1);
    }

    OpenSSL_add_all_digests(); // Initialize OpenSSL's digest algorithms

    // Get the digest type by name
    digest_type = EVP_get_digestbyname(digest_name);
    if (!digest_type) {
        fprintf(stderr, "Digest type not found: %s\n", digest_name);
        exit(1);
    }

    mdctx = EVP_MD_CTX_new();

    EVP_DigestInit(mdctx, digest_type);
    while (1) {
        size_t bytes_read = fread(buffer, 1, BUFFER_SIZE, file);
        if (bytes_read == 0) break;
        EVP_DigestUpdate(mdctx, buffer, bytes_read);
    }
    EVP_DigestFinal(mdctx, hash, &hash_len);

    printf("%s: ", digest_name);
    for (unsigned int i = 0; i < hash_len; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    EVP_MD_CTX_free(mdctx);
    fclose(file);
}

void calculate_checksums(const char *filename) {
    int i = 0;
    const char *digest_name;

    while ((digest_name = digest_names[i])) {
        calculate_checksum(filename, digest_name);
        i++;
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    calculate_checksums(argv[1]);
    return 0;
}

