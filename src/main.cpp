#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "parser.h"

int main(int argc, char **argv) {
    if (argc != 5) {
        return 0;
    }

    char *in = argv[1];
    char *out = argv[2];
    char *sc = argv[3];
    char *sw = argv[4];

    if (access(in, F_OK | R_OK) != 0) {
        printf("file does not exist or can not be read.\n");
        return 0;
    }

    int type = -1;

    if (sw[0] == '-') {
        switch (sw[1]) {
            case ('e'):
                type = EXTEND_CODE;
                break;
            case ('n'):
                type = NEW_SECTION;
                break;
            case ('c'):
                type = CODE_CAVE;
                break;
        }
    }

    if (type < 0) {
        printf("invalid injection method.\n");
        return 0;
    }

    FILE *fp = fopen(sc, "rb");

    if (fp == NULL) {
        printf("file does not exist or can not be read.\n");
        return 0;
    }

    IMAGE image = IMAGE(in);

    fseek(fp, 0, SEEK_END);
    uint32_t size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    uint8_t *shellcode = (uint8_t *)malloc(size);

    fread(shellcode, 1, size, fp);

    if (image.inject(out, shellcode, size, type) == true) {
        printf("injection successful.\n");
    } else {
        printf("injection failed.\n");
    }

    free(shellcode);
    return 0;
}
