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

// ─── PROVIDED ───────────────────────────────────────────────────────────────

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
// Returns 0 on success, -1 on error.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    // IMPORTANT: allow data == NULL only when len == 0
    if (!id_out) return -1;
    if (len > 0 && !data) return -1;

    const char *type_str = NULL;
    switch (type) {
        case OBJ_BLOB:   type_str = "blob"; break;
        case OBJ_TREE:   type_str = "tree"; break;
        case OBJ_COMMIT: type_str = "commit"; break;
        default: return -1;
    }

    // 1. Build header "<type> <size>\0"
    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);
    if (header_len < 0 || (size_t)header_len + 1 > sizeof(header)) return -1;
    header_len += 1; // include '\0'

    // 2. Build full object = header + data
    size_t full_len = (size_t)header_len + len;
    uint8_t *full = (uint8_t *)malloc(full_len > 0 ? full_len : 1);
    if (!full) return -1;

    memcpy(full, header, (size_t)header_len);
    if (len > 0) memcpy(full + header_len, data, len);

    // 3. Compute hash of full object
    ObjectID id;
    compute_hash(full, full_len, &id);

    // 4. Dedup
    if (object_exists(&id)) {
        *id_out = id;
        free(full);
        return 0;
    }

    // Paths
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(&id, hex);

    char shard_dir[512];
    if (snprintf(shard_dir, sizeof(shard_dir), "%s/%.2s", OBJECTS_DIR, hex) >= (int)sizeof(shard_dir)) {
        free(full);
        return -1;
    }

    char final_path[512];
    object_path(&id, final_path, sizeof(final_path));

    // 5. Ensure shard directory exists
    if (mkdir(shard_dir, 0755) != 0 && errno != EEXIST) {
        free(full);
        return -1;
    }

    // 6. Temp path in same directory
    char tmp_path[512];
    if (snprintf(tmp_path, sizeof(tmp_path), "%s/.tmp.%d", shard_dir, (int)getpid()) >= (int)sizeof(tmp_path)) {
        free(full);
        return -1;
    }

    int fd = open(tmp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        free(full);
        return -1;
    }

    // 7. Write full object
    size_t off = 0;
    while (off < full_len) {
        ssize_t n = write(fd, full + off, full_len - off);
        if (n <= 0) {
            close(fd);
            unlink(tmp_path);
            free(full);
            return -1;
        }
        off += (size_t)n;
    }

    // 8. fsync file
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

    // 9. Atomic rename
    if (rename(tmp_path, final_path) != 0) {
        unlink(tmp_path);
        free(full);
        return -1;
    }

    // 10. fsync shard dir (best effort)
    int dfd = open(shard_dir, O_RDONLY | O_DIRECTORY);
    if (dfd >= 0) {
        (void)fsync(dfd);
        close(dfd);
    }

    *id_out = id;
    free(full);
    return 0;
}

// Read an object from the store.
//
// Returns 0 on success, -1 on error.
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    if (!id || !type_out || !data_out || !len_out) return -1;

    char path[512];
    object_path(id, path, sizeof(path));

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long flong = ftell(f);
    if (flong < 0) { fclose(f); return -1; }
    size_t flen = (size_t)flong;
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }

    uint8_t *buf = (uint8_t *)malloc(flen > 0 ? flen : 1);
    if (!buf) { fclose(f); return -1; }

    if (flen > 0 && fread(buf, 1, flen, f) != flen) {
        fclose(f);
        free(buf);
        return -1;
    }
    fclose(f);

    // Verify hash integrity of entire stored object
    ObjectID actual;
    compute_hash(buf, flen, &actual);
    if (memcmp(actual.hash, id->hash, HASH_SIZE) != 0) {
        free(buf);
        return -1;
    }

    // Parse "<type> <size>\0"
    uint8_t *nul = memchr(buf, '\0', flen);
    if (!nul) { free(buf); return -1; }

    size_t header_len = (size_t)(nul - buf);
    if (header_len >= 128) { free(buf); return -1; }

    char header[128];
    memcpy(header, buf, header_len);
    header[header_len] = '\0';

    char tstr[16];
    unsigned long long declared_size = 0;
    if (sscanf(header, "%15s %llu", tstr, &declared_size) != 2) {
        free(buf);
        return -1;
    }

    ObjectType t;
    if (strcmp(tstr, "blob") == 0) t = OBJ_BLOB;
    else if (strcmp(tstr, "tree") == 0) t = OBJ_TREE;
    else if (strcmp(tstr, "commit") == 0) t = OBJ_COMMIT;
    else { free(buf); return -1; }

    size_t payload_len = flen - (header_len + 1);
    if (payload_len != (size_t)declared_size) {
        free(buf);
        return -1;
    }

    void *payload = malloc(payload_len > 0 ? payload_len : 1);
    if (!payload) { free(buf); return -1; }
    if (payload_len > 0) memcpy(payload, nul + 1, payload_len);

    *type_out = t;
    *data_out = payload;
    *len_out = payload_len;

    free(buf);
    return 0;
}