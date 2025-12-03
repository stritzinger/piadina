#include <stdio.h>
#include <stdlib.h>

#include "piadina_config.h"

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    puts("Piadina launcher stub running.");
    printf("Project version: %s\n", PACKAGE_VERSION);
    return EXIT_SUCCESS;
}
