#define _GNU_SOURCE
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

typedef struct block_meta {
    size_t size;
    int is_free;
    struct block_meta *next;
    uint32_t magic;
} block_meta;

#define META_SIZE sizeof(block_meta)

static block_meta *global_base = NULL;

static size_t page_align(size_t size) {
    size_t page = sysconf(_SC_PAGESIZE);
    return (size + page - 1) & ~(page - 1);
}

static block_meta *request_region(size_t size) {
    size_t total = page_align(size + META_SIZE);

    void *mem = mmap(
        NULL,
        total,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANON,
        -1,
        0
    );

    if (mem == MAP_FAILED)
        return NULL;

    block_meta *block = (block_meta *)mem;
    block->size = total - META_SIZE;
    block->is_free = 0;
    block->next = NULL;
    block->magic = 0xCAFEBABE;

    return block;
}

static block_meta *find_free_block(size_t size) {
    block_meta *current = global_base;
    while (current) {
        if (current->is_free && current->size >= size)
            return current;
        current = current->next;
    }
    return NULL;
}

void *_malloc(size_t size) {
    if (size == 0)
        return NULL;

    block_meta *block;

    if (!global_base) {
        block = request_region(size);
        if (!block) return NULL;
        global_base = block;
    } else {
        block = find_free_block(size);
        if (!block) {
            block = request_region(size);
            if (!block) return NULL;

            block_meta *current = global_base;
            while (current->next)
                current = current->next;
            current->next = block;
        } else {
            block->is_free = 0;
            block->magic = 0xCAFEBABE;
        }
    }

    return (block + 1);
}

void my_free(void *ptr) {
    if (!ptr)
        return;

    block_meta *block = ((block_meta *)ptr) - 1;
    assert(block->magic == 0xCAFEBABE);

    block->is_free = 1;
    block->magic = 0xFEEDFACE;

    // return large blocks directly to OS 
    if (block->size >= sysconf(_SC_PAGESIZE)) {
        munmap(block, block->size + META_SIZE);
    }
}

void *_calloc(size_t n, size_t size) {
    size_t total = n * size;
    void *ptr = _malloc(total);
    if (ptr)
        memset(ptr, 0, total);
    return ptr;
}

void *_realloc(void *ptr, size_t size) {
    if (!ptr)
        return _malloc(size);

    block_meta *block = ((block_meta *)ptr) - 1;
    if (block->size >= size)
        return ptr;

    void *new_ptr = _malloc(size);
    if (!new_ptr)
        return NULL;

    memcpy(new_ptr, ptr, block->size);
    my_free(ptr);
    return new_ptr;
}
