// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <errno.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ─────────────────────────────────────────────────-

// Write an object to the store.
//
// Object format on disk:
//   "<type> <size>\0<data>"
//   where <type> is "blob", "tree", or "commit"
//   and <size> is the decimal string of the data length
//
// Steps:
//   1. Build the full object: header ("blob 16\0") + data
//   2. Compute SHA-256 hash of the FULL object (header + data)
//   3. Check if object already exists (deduplication) — if so, just return success
//   4. Create shard directory (.pes/objects/XX/) if it doesn't exist
//   5. Write to a temporary file in the same shard directory
//   6. fsync() the temporary file to ensure data reaches disk
//   7. rename() the temp file to the final path (atomic on POSIX)
//   8. Open and fsync() the shard directory to persist the rename
//   9. Store the computed hash in *id_out

// HINTS - Useful syscalls and functions for this phase:
//   - sprintf / snprintf : formatting the header string
//   - compute_hash       : hashing the combined header + data
//   - object_exists      : checking for deduplication
//   - mkdir              : creating the shard directory (use mode 0755)
//   - open, write, close : creating and writing to the temp file
//                          (Use O_CREAT | O_WRONLY | O_TRUNC, mode 0644)
//   - fsync              : flushing the file descriptor to disk
//   - rename             : atomically moving the temp file to the final path
//

//
// Returns 0 on success, -1 on error.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    if (!data || !id_out) return -1;

    const char *type_str = NULL;
    switch (type) {
        case OBJ_BLOB:   type_str = "blob"; break;
        case OBJ_TREE:   type_str = "tree"; break;
        case OBJ_COMMIT: type_str = "commit"; break;
        default: return -1;
    }

    // 1) Build header "<type> <size>\0"
    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu%c", type_str, len, '\0');
    if (header_len < 0 || (size_t)header_len >= sizeof(header)) {
        return -1;
    }

    // 2) Build full object buffer = header + data
    size_t full_len = (size_t)header_len + len;
    unsigned char *full = (unsigned char *)malloc(full_len);
    if (!full) return -1;

    memcpy(full, header, (size_t)header_len);
    memcpy(full + (size_t)header_len, data, len);

    // 2) Compute hash of FULL object (header + data)
    ObjectID id;
    compute_hash(full, full_len, &id);

    // 3) Dedup: if already exists, return success
    if (object_exists(&id)) {
        *id_out = id;
        free(full);
        return 0;
    }

    // Convert hash to hex for shard path
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(&id, hex);

    // 4) Create shard directory (.pes/objects/XX/)
    char shard_dir[512];
    snprintf(shard_dir, sizeof(shard_dir), "%s/%.2s", OBJECTS_DIR, hex);

    if (mkdir(shard_dir, 0755) != 0) {
        if (errno != EEXIST) {
            free(full);
            return -1;
        }
    }

    // Final object path
    char final_path[512];
    object_path(&id, final_path, sizeof(final_path));

    // 5) Write to a temporary file in the same shard directory
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s/.tmp.%d", shard_dir, (int)getpid());

    int fd = open(tmp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        free(full);
        return -1;
    }

    // Write all bytes (handle partial writes)
    size_t off = 0;
    while (off < full_len) {
        ssize_t n = write(fd, full + off, full_len - off);
        if (n < 0) {
            close(fd);
            unlink(tmp_path);
            free(full);
            return -1;
        }
        off += (size_t)n;
    }

    // 6) fsync temp file
    if (fsync(fd) != 0) {
        close(fd);
        unlink(tmp_path);
        free(full);
        return -1;
    }

    if (close(fd) != 0) {
        unlink(tmp_path);
        free(full);
        return -1;
    }

    // 7) rename temp -> final (atomic)
    if (rename(tmp_path, final_path) != 0) {
        unlink(tmp_path);
        free(full);
        return -1;
    }

    // 8) fsync shard directory to persist rename
    int dfd = open(shard_dir, O_RDONLY);
    if (dfd >= 0) {
        (void)fsync(dfd);
        close(dfd);
    }

    // 9) Return the computed hash
    *id_out = id;
    free(full);
    return 0;
}

// Read an object from the store.
//
// Steps:
//   1. Build the file path from the hash using object_path()
//   2. Open and read the entire file
//   3. Parse the header to extract the type string and size
//   4. Verify integrity: recompute the SHA-256 of the file contents
//      and compare to the expected hash (from *id). Return -1 if mismatch.
//   5. Set *type_out to the parsed ObjectType
//   6. Allocate a buffer, copy the data portion (after the \0), set *data_out and *len_out
//
// HINTS - Useful syscalls and functions for this phase:
//   - object_path        : getting the target file path
//   - fopen, fread, fseek: reading the file into memory
//   - memchr             : safely finding the '\0' separating header and data
//   - strncmp            : parsing the type string ("blob", "tree", "commit")
//   - compute_hash       : re-hashing the read data for integrity verification
//   - memcmp             : comparing the computed hash against the requested hash
//   - malloc, memcpy     : allocating and returning the extracted data
//
// The caller is responsible for calling free(*data_out).
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    if (!id || !type_out || !data_out || !len_out) return -1;

    char path[512];
    object_path(id, path, sizeof(path));

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    // Read whole file
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    long flen_long = ftell(f);
    if (flen_long < 0) {
        fclose(f);
        return -1;
    }
    size_t flen = (size_t)flen_long;
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }

    unsigned char *buf = (unsigned char *)malloc(flen);
    if (!buf) {
        fclose(f);
        return -1;
    }

    size_t nread = fread(buf, 1, flen, f);
    fclose(f);
    if (nread != flen) {
        free(buf);
        return -1;
    }

    // 4) Integrity check: recompute hash of entire file
    ObjectID computed;
    compute_hash(buf, flen, &computed);
    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) {
        free(buf);
        return -1;
    }

    // 3) Parse header: "<type> <size>\0"
    unsigned char *nul = (unsigned char *)memchr(buf, '\0', flen);
    if (!nul) {
        free(buf);
        return -1;
    }

    size_t header_len = (size_t)(nul - buf); // not including '\0'
    char header[128];
    if (header_len >= sizeof(header)) {
        free(buf);
        return -1;
    }
    memcpy(header, buf, header_len);
    header[header_len] = '\0';

    char type_str[16];
    unsigned long long declared_size = 0;
    if (sscanf(header, "%15s %llu", type_str, &declared_size) != 2) {
        free(buf);
        return -1;
    }

    ObjectType parsed_type;
    if (strcmp(type_str, "blob") == 0) parsed_type = OBJ_BLOB;
    else if (strcmp(type_str, "tree") == 0) parsed_type = OBJ_TREE;
    else if (strcmp(type_str, "commit") == 0) parsed_type = OBJ_COMMIT;
    else {
        free(buf);
        return -1;
    }

    // 6) Extract payload
    size_t payload_len = flen - (header_len + 1); // +1 for '\0'
    if (declared_size != payload_len) {
        free(buf);
        return -1;
    }

    void *payload = malloc(payload_len);
    if (!payload) {
        free(buf);
        return -1;
    }
    memcpy(payload, nul + 1, payload_len);

    *type_out = parsed_type;
    *data_out = payload;
    *len_out = payload_len;

    free(buf);
    return 0;
}