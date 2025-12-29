#define _DEFAULT_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>

// [metadata] [payload] [metadata] [payload] [metadata] [payload] ... (heap grows) <-- before coalescing
// [header] [payload] [footer] [header] [payload] [footer] ... <-- now

typedef struct block_meta {
    size_t size;
    struct block_meta *next;
    int is_free;  
    uint32_t magic;
} block_meta;

#define META_SIZE sizeof(block_meta)
#define FOOTER_SIZE sizeof(size_t)

static block_meta *global_base = NULL;

static block_meta *find_free_block(block_meta **last, size_t size) {
    block_meta *current = global_base;
    while(current && !(current->is_free && current->size >= size))
    {
        *last = current;
        current = current->next;
    }
    return current;
}

static block_meta *request_space(block_meta *last, size_t size) {
    block_meta *block = sbrk(0);
    void *request = sbrk(size + META_SIZE + FOOTER_SIZE);
    if (request == (void*)-1)  return NULL;
    assert (block == request);
    if (last) last->next = block;
    block->size = size;
    block->next = NULL;
    block->is_free = 0;
    block->magic = 0xCAFEBABE;
    size_t *footer = (size_t *)((char *) (block + 1) + size);
    *footer = size;
    return block;
}

static block_meta *get_block_ptr(void *ptr) {
    return (block_meta *)ptr -1 ;
}

static block_meta *next_block(block_meta *block) {
    return block->next;
}

static block_meta *prev_block(block_meta *block) {
    size_t prev_size = *(size_t *)((char *)block - FOOTER_SIZE);
    return (block_meta *)((char *)block - prev_size - META_SIZE - FOOTER_SIZE);
}


// malloc
void *_malloc(size_t size) {
    if (size==0) {
        return NULL;
    }
    block_meta *block;
    if (!global_base){
        // first allocation
        block = request_space(NULL, size);
        if (!block) return NULL;
        global_base = block;
    }
    else {
        block_meta *last = global_base;
        block = find_free_block(&last, size);
        if (!block) {
            // no reusable block found
            block = request_space(last, size);
            if (!block) return NULL;
        }
        else {
            // sufficient space -- reuse block 
            assert(block->is_free == 1);
            block->is_free = 0;
            block->magic = 0xDEADBEEF;
        }
    }
    return (block + 1);
}

void is_free(void *ptr) {
    if (!ptr) return;
    block_meta *block = get_block_ptr(ptr);
    // assert(block->is_free==0);
    // assert(block->magic==0xCAFEBABE || block->magic==0xDEADBEEF);
    block->is_free = 1;
    block->magic = 0xFEEDFACE;
    
    block_meta *next = next_block(block);
    if (next && next->free) {
        block->size += META_SIZE + FOOTER_SIZE + next->size;
        block->next = next->next;
        size_t  *footer = (size_t *)((char *)(block + 1) + block->size);
        *footer = block->size;
    }
    if (block != global_base) {
        block_meta *prev = prev_block(block);
        if (prev->free) {
            prev->free += META_SIZE + FOOTER_SIZE + block->size;
            
        }
    }
}

void *_calloc(size_t nmemb, size_t size) {
    size_t total = nmemb*size;
    void *ptr = _malloc(total);
    if (!ptr) return NULL;
    memset(ptr, 0, total);
    return ptr;
}

void *_realloc(void *ptr, size_t size)
{
    if (!ptr) {
        return _malloc(size);
    }
    block_meta *block = get_block_ptr(ptr);
    if (block->size >= size) return ptr;
    void *new_ptr = _malloc(size);
    if(!new_ptr) return NULL;

    memcpy(new_ptr, ptr, block->size);
    is_free(ptr);
    return new_ptr;
}

void dump_heap(void) {
    block_meta *cur = global_base;
    fprintf(stderr, "----- HEAP DUMP -----\n");
    while (cur) {
        fprintf(stderr,
            "block=%p payload=%p size=%zu free=%d magic=0x%x next=%p\n",
            (void *)cur,
            (void *)(cur + 1),
            cur->size,
            cur->is_free,
            cur->magic,
            (void *)cur->next
        );
        cur = cur->next;
    }
    fprintf(stderr, "---------------------\n");
}



