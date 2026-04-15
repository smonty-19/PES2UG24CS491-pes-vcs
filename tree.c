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

// Forward declarations (implemented in object.c)
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
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);

        ptr = space + 1; // Skip space

        // 2. Safely find the null terminator for the name
        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1; // Malformed data

        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0'; // Ensure null-terminated

        ptr = null_byte + 1; // Skip null byte

        // 3. Read the 32-byte binary hash
        if (ptr + HASH_SIZE > end) return -1;
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
    // Estimate max size: (6 bytes mode + 1 byte space + 256 bytes name + 1 byte null + 32 bytes hash) per entry
    size_t max_size = tree->count * 296;
    uint8_t *buffer = malloc(max_size);
    if (!buffer) return -1;

    // Create a mutable copy to sort entries (Git requirement)
    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, sorted_tree.count, sizeof(TreeEntry), compare_tree_entries);

    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];

        // Write mode and name (%o writes octal correctly for Git standards)
        int written = sprintf((char *)buffer + offset, "%o %s", entry->mode, entry->name);
        offset += (size_t)written + 1; // +1 to step over the null terminator written by sprintf

        // Write binary hash
        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }

    *data_out = buffer;
    *len_out = offset;
    return 0;
}

// ─── TODO: Implement these ─────────────────────────────────────────────────-

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
    char dir[512];   // directory path relative to repo root; "" means root
    Tree tree;       // entries in that directory
} DirTree;

static int find_dir(DirTree *dirs, int dir_count, const char *dir) {
    for (int i = 0; i < dir_count; i++) {
        if (strcmp(dirs[i].dir, dir) == 0) return i;
    }
    return -1;
}

static int ensure_dir(DirTree *dirs, int *dir_count_io, const char *dir) {
    int idx = find_dir(dirs, *dir_count_io, dir);
    if (idx >= 0) return idx;

    if (*dir_count_io >= 2048) return -1;
    idx = *dir_count_io;
    snprintf(dirs[idx].dir, sizeof(dirs[idx].dir), "%s", dir);
    dirs[idx].tree.count = 0;
    (*dir_count_io)++;
    return idx;
}

// Split "a/b/c.txt" -> dir="a/b", name="c.txt"
// Split "README.md" -> dir="",    name="README.md"
static void split_path(const char *path,
                       char *out_dir, size_t out_dir_sz,
                       char *out_name, size_t out_name_sz) {
    const char *slash = strrchr(path, '/');
    if (!slash) {
        snprintf(out_dir, out_dir_sz, "%s", "");
        snprintf(out_name, out_name_sz, "%s", path);
        return;
    }

    size_t dir_len = (size_t)(slash - path);
    if (dir_len >= out_dir_sz) dir_len = out_dir_sz - 1;
    memcpy(out_dir, path, dir_len);
    out_dir[dir_len] = '\0';

    snprintf(out_name, out_name_sz, "%s", slash + 1);
}

// Split dir "a/b/c" -> parent="a/b", base="c"
// Split dir "src"   -> parent="",    base="src"
static void split_dir_parent(const char *dir,
                             char *out_parent, size_t out_parent_sz,
                             char *out_base, size_t out_base_sz) {
    const char *slash = strrchr(dir, '/');
    if (!slash) {
        snprintf(out_parent, out_parent_sz, "%s", "");
        snprintf(out_base, out_base_sz, "%s", dir);
        return;
    }

    size_t parent_len = (size_t)(slash - dir);
    if (parent_len >= out_parent_sz) parent_len = out_parent_sz - 1;
    memcpy(out_parent, dir, parent_len);
    out_parent[parent_len] = '\0';

    snprintf(out_base, out_base_sz, "%s", slash + 1);
}

static int add_tree_entry(Tree *t, uint32_t mode, const ObjectID *hash, const char *name) {
    if (t->count >= MAX_TREE_ENTRIES) return -1;
    TreeEntry *e = &t->entries[t->count++];
    e->mode = mode;
    e->hash = *hash;
    snprintf(e->name, sizeof(e->name), "%s", name);
    return 0;
}

static int depth_of_dir(const char *dir) {
    int d = 0;
    for (const char *p = dir; *p; p++) if (*p == '/') d++;
    return d;
}

int tree_from_index(ObjectID *id_out) {
    if (!id_out) return -1;

    Index index;
    if (index_load(&index) != 0) return -1;

    DirTree dirs[2048];
    int dir_count = 0;

    // root always exists
    if (ensure_dir(dirs, &dir_count, "") < 0) return -1;

    // 1) Add each file to the Tree for its directory, and ensure parent dirs exist
    for (int i = 0; i < index.count; i++) {
        const IndexEntry *ie = &index.entries[i];

        char dir[512], name[256];
        split_path(ie->path, dir, sizeof(dir), name, sizeof(name));

        int d_idx = ensure_dir(dirs, &dir_count, dir);
        if (d_idx < 0) return -1;

        // Leaf entries use the mode stored in the index entry
        if (add_tree_entry(&dirs[d_idx].tree, ie->mode, &ie->hash, name) != 0) return -1;

        // Ensure all parents for this directory exist
        char walk[512];
        snprintf(walk, sizeof(walk), "%s", dir);
        while (walk[0] != '\0') {
            char parent[512], base[256];
            split_dir_parent(walk, parent, sizeof(parent), base, sizeof(base));
            if (ensure_dir(dirs, &dir_count, parent) < 0) return -1;
            snprintf(walk, sizeof(walk), "%s", parent);
        }
    }

    // 2) Sort directories deepest-first so we can write children before parents
    for (int i = 0; i < dir_count; i++) {
        for (int j = i + 1; j < dir_count; j++) {
            int di = depth_of_dir(dirs[i].dir);
            int dj = depth_of_dir(dirs[j].dir);

            // deeper first; tie-breaker for determinism
            if (dj > di || (dj == di && strcmp(dirs[j].dir, dirs[i].dir) < 0)) {
                DirTree tmp = dirs[i];
                dirs[i] = dirs[j];
                dirs[j] = tmp;
            }
        }
    }

    // 3) Write each directory tree object; then add it to its parent as a MODE_DIR entry
    ObjectID dir_ids[2048];

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
            split_dir_parent(dirs[i].dir, parent, sizeof(parent), base, sizeof(base));

            int p_idx = find_dir(dirs, dir_count, parent);
            if (p_idx < 0) return -1;

            if (add_tree_entry(&dirs[p_idx].tree, MODE_DIR, &dir_ids[i], base) != 0) return -1;
        }
    }

    // 4) Return the root tree hash
    for (int i = 0; i < dir_count; i++) {
        if (strcmp(dirs[i].dir, "") == 0) {
            *id_out = dir_ids[i];
            return 0;
        }
    }

    return -1;
}