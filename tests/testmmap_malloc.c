#include <stdio.h>
#include <string.h>

void *_malloc(size_t);
void my_free(void *);
void *_calloc(size_t, size_t);
void *_realloc(void *, size_t);

int main() {
    char *a = _malloc(3000);
    strcpy(a, "hello mmap allocator");

    char *b = _malloc(5000);
    b = _realloc(b, 9000);

    my_free(a);
    my_free(b);

    printf("done\n");
    return 0;
}
