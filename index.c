// index.c — Staging area implementation
//
// Text format of .pes/index (one entry per line, sorted by path):
//
//   <mode-octal> <64-char-hex-hash> <mtime-seconds> <size> <path>
//
// Example:
//   100644 a1b2c3d4e5f6...  1699900000 42 README.md
//   100644 f7e8d9c0b1a2...  1699900100 128 src/main.c
//
// This is intentionally a simple text format. No magic numbers, no
// binary parsing. The focus is on the staging area CONCEPT (tracking
// what will go into the next commit) and ATOMIC WRITES (temp+rename).
//
// PROVIDED functions: index_find, index_remove, index_status
// TODO functions:     index_load, index_save, index_add

#include "index.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>

int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);

// ─── PROVIDED ───────────────────────────────────────────────────────────────

// Find an index entry by path (linear scan).
IndexEntry* index_find(Index *index, const char *path) {
    for (int i = 0; i < index->count; i++) {
        if (strcmp(index->entries[i].path, path) == 0)
            return &index->entries[i];
    }
    return NULL;
}

// Remove a file from the index.
// Returns 0 on success, -1 if path not in index.
int index_remove(Index *index, const char *path) {
    for (int i = 0; i < index->count; i++) {
        if (strcmp(index->entries[i].path, path) == 0) {
            int remaining = index->count - i - 1;
            if (remaining > 0)
                memmove(&index->entries[i], &index->entries[i + 1],
                        remaining * sizeof(IndexEntry));
            index->count--;
            return index_save(index);
        }
    }
    fprintf(stderr, "error: '%s' is not in the index\n", path);
    return -1;
}

// Print the status of the working directory.
int index_status(const Index *index) {
    printf("Staged changes:\n");
    int staged_count = 0;
    for (int i = 0; i < index->count; i++) {
        printf("  staged:     %s\n", index->entries[i].path);
        staged_count++;
    }
    if (staged_count == 0) printf("  (nothing to show)\n");
    printf("\n");

    printf("Unstaged changes:\n");
    int unstaged_count = 0;
    for (int i = 0; i < index->count; i++) {
        struct stat st;
        if (stat(index->entries[i].path, &st) != 0) {
            printf("  deleted:    %s\n", index->entries[i].path);
            unstaged_count++;
        } else {
            if (st.st_mtime != (time_t)index->entries[i].mtime_sec || st.st_size != (off_t)index->entries[i].size) {
                printf("  modified:   %s\n", index->entries[i].path);
                unstaged_count++;
            }
        }
    }
    if (unstaged_count == 0) printf("  (nothing to show)\n");
    printf("\n");

    printf("Untracked files:\n");
    int untracked_count = 0;
    DIR *dir = opendir(".");
    if (dir) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
            if (strcmp(ent->d_name, ".pes") == 0) continue;
            if (strcmp(ent->d_name, "pes") == 0) continue;
            if (strstr(ent->d_name, ".o") != NULL) continue;

            int is_tracked = 0;
            for (int i = 0; i < index->count; i++) {
                if (strcmp(index->entries[i].path, ent->d_name) == 0) {
                    is_tracked = 1;
                    break;
                }
            }

            if (!is_tracked) {
                struct stat st;
                if (stat(ent->d_name, &st) == 0 && S_ISREG(st.st_mode)) {
                    printf("  untracked:  %s\n", ent->d_name);
                    untracked_count++;
                }
            }
        }
        closedir(dir);
    }
    if (untracked_count == 0) printf("  (nothing to show)\n");
    printf("\n");

    return 0;
}

// ─── TODO: Implement these ───────────────────────────────────────────────────

// Load the index from .pes/index.
int index_load(Index *index) {
    if (!index) return -1;
    memset(index, 0, sizeof(*index));   // hard reset to avoid garbage count

    FILE *f = fopen(INDEX_FILE, "r");
    if (!f) return 0; // missing file => empty index

    while (index->count < MAX_INDEX_ENTRIES) {
        IndexEntry e;
        memset(&e, 0, sizeof(e));

        char hash_hex[HASH_HEX_SIZE + 1] = {0};
        unsigned long long mtime = 0;
        unsigned int size = 0;

        int rc = fscanf(f, "%o %64s %llu %u %511s",
                        &e.mode, hash_hex, &mtime, &size, e.path);

        if (rc == EOF) break;
        if (rc != 5) { fclose(f); return -1; }
        if (hex_to_hash(hash_hex, &e.hash) != 0) { fclose(f); return -1; }

        e.mtime_sec = (uint64_t)mtime;
        e.size = (uint32_t)size;
        index->entries[index->count++] = e;
    }

    fclose(f);
    return 0;
}

static int compare_index_entries(const void *a, const void *b) {
    const IndexEntry *ea = (const IndexEntry *)a;
    const IndexEntry *eb = (const IndexEntry *)b;
    return strcmp(ea->path, eb->path);
}

int index_save(const Index *index) {
    if (!index) return -1;
    if (index->count < 0 || index->count > MAX_INDEX_ENTRIES) return -1;

    // Ensure .pes exists
    if (access(PES_DIR, F_OK) != 0) {
        if (mkdir(PES_DIR, 0755) != 0 && errno != EEXIST) return -1;
    }

    // IMPORTANT: avoid "Index tmp = *index;" (stack overflow risk)
    // Sort in-place. Callers pass mutable Index anyway.
    Index *mutable_index = (Index *)index;
    qsort(mutable_index->entries, (size_t)mutable_index->count,
          sizeof(IndexEntry), compare_index_entries);

    char tmp_path[512];
    if (snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", INDEX_FILE) >= (int)sizeof(tmp_path)) {
        return -1;
    }

    FILE *f = fopen(tmp_path, "w");
    if (!f) return -1;

    for (int i = 0; i < mutable_index->count; i++) {
        char hex[HASH_HEX_SIZE + 1];
        hash_to_hex(&mutable_index->entries[i].hash, hex);

        if (fprintf(f, "%o %s %llu %u %s\n",
                    mutable_index->entries[i].mode,
                    hex,
                    (unsigned long long)mutable_index->entries[i].mtime_sec,
                    mutable_index->entries[i].size,
                    mutable_index->entries[i].path) < 0) {
            fclose(f);
            unlink(tmp_path);
            return -1;
        }
    }

    if (fflush(f) != 0) { fclose(f); unlink(tmp_path); return -1; }

    int fd = fileno(f);
    if (fd < 0 || fsync(fd) != 0) { fclose(f); unlink(tmp_path); return -1; }

    if (fclose(f) != 0) { unlink(tmp_path); return -1; }

    if (rename(tmp_path, INDEX_FILE) != 0) { unlink(tmp_path); return -1; }

    return 0;
}

// Stage a file for the next commit.
int index_add(Index *index, const char *path) {
    if (!index || !path) return -1;
    if (index->count < 0 || index->count > MAX_INDEX_ENTRIES) return -1;

    struct stat st;
    if (stat(path, &st) != 0) return -1;
    if (!S_ISREG(st.st_mode)) return -1;

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long end = ftell(f);
    if (end < 0) { fclose(f); return -1; }
    size_t size = (size_t)end;
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }

    void *buf = malloc(size ? size : 1);
    if (!buf) { fclose(f); return -1; }

    size_t n = fread(buf, 1, size, f);
    fclose(f);
    if (n != size) { free(buf); return -1; }

    ObjectID blob_id;
    if (object_write(OBJ_BLOB, buf, size, &blob_id) != 0) {
        free(buf);
        return -1;
    }
    free(buf);

    IndexEntry *e = index_find(index, path);
    if (!e) {
        if (index->count >= MAX_INDEX_ENTRIES) return -1;
        e = &index->entries[index->count++];
        memset(e, 0, sizeof(*e));
        snprintf(e->path, sizeof(e->path), "%s", path);
    }

    e->mode = (st.st_mode & S_IXUSR) ? 0100755 : 0100644;
    e->hash = blob_id;
    e->mtime_sec = (uint64_t)st.st_mtime;
    e->size = (uint32_t)st.st_size;

    return index_save(index);
}