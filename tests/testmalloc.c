#include <stdio.h>
#include <stdint.h>

#define malloc   _malloc
#define free     is_free
#define calloc   _calloc
#define realloc  _realloc

#include "mallocreuse.c"

int main(void) {
    printf("=== custom malloc test start ===\n");

    int *a = malloc(10 * sizeof(int));
    printf("a = %p\n", (void *)a);

    int *b = malloc(20 * sizeof(int));
    printf("b = %p\n", (void *)b);

    free(a);
    printf("freed a\n");

    int *c = malloc(5 * sizeof(int));
    printf("c = %p (should reuse a's block if large enough)\n", (void *)c);

    dump_heap();

    b = realloc(b, 40 * sizeof(int));
    printf("b realloced = %p\n", (void *)b);

    free(b);
    free(c);

    dump_heap();

    printf("=== custom malloc test end ===\n");
    return 0;
}
