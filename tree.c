// tree.c — Tree object serialization and construction
//
// PROVIDED functions: get_file_mode, tree_parse, tree_serialize
// TODO functions:     tree_from_index
//
// Binary tree format (per entry, concatenated with no separators):
//   "<mode-as-ascii-octal> <name>\0<32-byte-binary-hash>"
//
// Example single entry (conceptual):
//   "100644 hello.txt\0" followed by 32 raw bytes of SHA-256

#include "tree.h"
#include "index.h"
#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

// ─── Mode Constants ─────────────────────────────────────────────────────────

#define MODE_FILE      0100644
#define MODE_EXEC      0100755
#define MODE_DIR       0040000

// Forward declaration (implemented in object.c)
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);

// ─── PROVIDED ───────────────────────────────────────────────────────────────

// Determine the object mode for a filesystem path.
uint32_t get_file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;

    if (S_ISDIR(st.st_mode))  return MODE_DIR;
    if (st.st_mode & S_IXUSR) return MODE_EXEC;
    return MODE_FILE;
}

// Parse binary tree data into a Tree struct safely.
// Returns 0 on success, -1 on parse error.
int tree_parse(const void *data, size_t len, Tree *tree_out) {
    tree_out->count = 0;
    const uint8_t *ptr = (const uint8_t *)data;
    const uint8_t *end = ptr + len;

    while (ptr < end && tree_out->count < MAX_TREE_ENTRIES) {
        TreeEntry *entry = &tree_out->entries[tree_out->count];

        // 1. Safely find the space character for the mode
        const uint8_t *space = memchr(ptr, ' ', end - ptr);
        if (!space) return -1; // Malformed data

        // Parse mode into an isolated buffer
        char mode_str[16] = {0};
        size_t mode_len = (size_t)(space - ptr);
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = (uint32_t)strtol(mode_str, NULL, 8);

        ptr = space + 1; // Skip space

        // 2. Safely find the null terminator for the name
        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1; // Malformed data

        size_t name_len = (size_t)(null_byte - ptr);
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0'; // Ensure null-terminated

        ptr = null_byte + 1; // Skip null byte

        // 3. Read the 32-byte binary hash
        if ((size_t)(end - ptr) < HASH_SIZE) return -1; 
        memcpy(entry->hash.hash, ptr, HASH_SIZE);
        ptr += HASH_SIZE;

        tree_out->count++;
    }
    return 0;
}

// Helper for qsort to ensure consistent tree hashing
static int compare_tree_entries(const void *a, const void *b) {
    return strcmp(((const TreeEntry *)a)->name, ((const TreeEntry *)b)->name);
}

// Serialize a Tree struct into binary format for storage.
// Caller must free(*data_out).
// Returns 0 on success, -1 on error.
int tree_serialize(const Tree *tree, void **data_out, size_t *len_out) {
    if (!tree || !data_out || !len_out) return -1;
    if (tree->count < 0 || tree->count > MAX_TREE_ENTRIES) return -1;

    // Estimate max size: (6 bytes mode + 1 byte space + 256 bytes name + 1 byte null + 32 bytes hash) per entry
    size_t max_size = (size_t)tree->count * 296; 
    uint8_t *buffer = malloc(max_size > 0 ? max_size : 1);
    if (!buffer) return -1;

    // Create a mutable copy to sort entries (Git requirement)
    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, (size_t)sorted_tree.count, sizeof(TreeEntry), compare_tree_entries);

    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];
        
        // Write mode and name (%o writes octal correctly for Git standards)
        int written = sprintf((char *)buffer + offset, "%o %s", entry->mode, entry->name);
        if (written < 0) { free(buffer); return -1; }
        offset += (size_t)written + 1; // +1 to step over the null terminator written by sprintf
        
        // Write binary hash
        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }

    *data_out = buffer;
    *len_out = offset;
    return 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Build a tree hierarchy from the current index and write all tree
// objects to the object store.
//
// HINTS - Useful functions and concepts for this phase:
//   - index_load      : load the staged files into memory
//   - strchr          : find the first '/' in a path to separate directories from files
//   - strncmp         : compare prefixes to group files belonging to the same subdirectory
//   - Recursion       : you will likely want to create a recursive helper function 
//                       (e.g., `write_tree_level(entries, count, depth)`) to handle nested dirs.
//   - tree_serialize  : convert your populated Tree struct into a binary buffer
//   - object_write    : save that binary buffer to the store as OBJ_TREE
//
// Returns 0 on success, -1 on error.

typedef struct {
    char dir[512];   // "" for root, else "src" or "src/lib"
    Tree tree;       // entries directly under this directory
} DirNode;

static int dir_find(DirNode *dirs, int dir_count, const char *dir) {
    for (int i = 0; i < dir_count; i++) {
        if (strcmp(dirs[i].dir, dir) == 0) return i;
    }
    return -1;
}

static int dir_ensure(DirNode *dirs, int *dir_count, const char *dir) {
    int idx = dir_find(dirs, *dir_count, dir);
    if (idx >= 0) return idx;

    if (*dir_count >= 2048) return -1;
    idx = *dir_count;
    snprintf(dirs[idx].dir, sizeof(dirs[idx].dir), "%s", dir);
    dirs[idx].tree.count = 0;
    (*dir_count)++;
    return idx;
}

static void split_path_dir_base(const char *path, char *out_dir, size_t dsz,
                                char *out_base, size_t bsz) {
    const char *slash = strrchr(path, '/');
    if (!slash) {
        snprintf(out_dir, dsz, "%s", "");
        snprintf(out_base, bsz, "%s", path);
        return;
    }

    size_t dlen = (size_t)(slash - path);
    if (dlen >= dsz) dlen = dsz - 1;
    memcpy(out_dir, path, dlen);
    out_dir[dlen] = '\0';

    snprintf(out_base, bsz, "%s", slash + 1);
}

static void split_dir_parent_base(const char *dir, char *out_parent, size_t psz,
                                  char *out_base, size_t bsz) {
    const char *slash = strrchr(dir, '/');
    if (!slash) {
        snprintf(out_parent, psz, "%s", "");
        snprintf(out_base, bsz, "%s", dir);
        return;
    }

    size_t plen = (size_t)(slash - dir);
    if (plen >= psz) plen = psz - 1;
    memcpy(out_parent, dir, plen);
    out_parent[plen] = '\0';

    snprintf(out_base, bsz, "%s", slash + 1);
}

static int tree_add_entry(Tree *t, uint32_t mode, const ObjectID *id, const char *name) {
    if (t->count < 0 || t->count >= MAX_TREE_ENTRIES) return -1;
    TreeEntry *e = &t->entries[t->count++];
    e->mode = mode;
    e->hash = *id;
    snprintf(e->name, sizeof(e->name), "%s", name);
    return 0;
}

static int dir_depth(const char *dir) {
    if (dir[0] == '\0') return 0;
    int d = 1;
    for (const char *p = dir; *p; p++) if (*p == '/') d++;
    return d;
}

int tree_from_index(ObjectID *id_out) {
    if (!id_out) return -1;

    Index idx;
    if (index_load(&idx) != 0) return -1;

    // If nothing staged, write an empty root tree.
    if (idx.count == 0) {
        Tree empty;
        empty.count = 0;
        void *raw = NULL;
        size_t raw_len = 0;
        if (tree_serialize(&empty, &raw, &raw_len) != 0) return -1;
        int rc = object_write(OBJ_TREE, raw, raw_len, id_out);
        free(raw);
        return rc;
    }

    DirNode dirs[2048];
    ObjectID dir_ids[2048];
    int dir_count = 0;

    // Ensure root node exists
    if (dir_ensure(dirs, &dir_count, "") < 0) return -1;

    // 1) Add all file entries to their direct directory node, and ensure parent directory nodes exist.
    for (int i = 0; i < idx.count; i++) {
        char dir[512], base[256];
        split_path_dir_base(idx.entries[i].path, dir, sizeof(dir), base, sizeof(base));

        int d_idx = dir_ensure(dirs, &dir_count, dir);
        if (d_idx < 0) return -1;

        if (tree_add_entry(&dirs[d_idx].tree, idx.entries[i].mode, &idx.entries[i].hash, base) != 0) {
            return -1;
        }

        // Ensure all ancestors exist
        char walk[512];
        snprintf(walk, sizeof(walk), "%s", dir);
        while (walk[0] != '\0') {
            char parent[512], name[256];
            split_dir_parent_base(walk, parent, sizeof(parent), name, sizeof(name));
            if (dir_ensure(dirs, &dir_count, parent) < 0) return -1;
            snprintf(walk, sizeof(walk), "%s", parent);
        }
    }

    // 2) Sort dirs by depth descending (children first), so child tree IDs are available for parent entries.
    for (int i = 0; i < dir_count; i++) {
        for (int j = i + 1; j < dir_count; j++) {
            int di = dir_depth(dirs[i].dir);
            int dj = dir_depth(dirs[j].dir);
            if (dj > di || (dj == di && strcmp(dirs[j].dir, dirs[i].dir) < 0)) {
                DirNode tmp = dirs[i];
                dirs[i] = dirs[j];
                dirs[j] = tmp;
            }
        }
    }

    // 3) Write each tree; for non-root, add a MODE_DIR entry into parent.
    for (int i = 0; i < dir_count; i++) {
        void *raw = NULL;
        size_t raw_len = 0;
        if (tree_serialize(&dirs[i].tree, &raw, &raw_len) != 0) return -1;

        if (object_write(OBJ_TREE, raw, raw_len, &dir_ids[i]) != 0) {
            free(raw);
            return -1;
        }
        free(raw);

        if (dirs[i].dir[0] != '\0') {
            char parent[512], base[256];
            split_dir_parent_base(dirs[i].dir, parent, sizeof(parent), base, sizeof(base));

            int p_idx = dir_find(dirs, dir_count, parent);
            if (p_idx < 0) return -1;

            if (tree_add_entry(&dirs[p_idx].tree, MODE_DIR, &dir_ids[i], base) != 0) {
                return -1;
            }
        }
    }

    // 4) Return root tree ID
    int root_idx = dir_find(dirs, dir_count, "");
    if (root_idx < 0) return -1;
    *id_out = dir_ids[root_idx];
    return 0;
}