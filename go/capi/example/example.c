/* cc example.c -I.. -L.. -lgfmx -o example && LD_LIBRARY_PATH=.. ./example cert.der */
#include <stdio.h>
#include <stdlib.h>
#include "libgfmx.h"

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s cert.der\n", argv[0]); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror(argv[1]); return 2; }
    static unsigned char buf[1 << 20];
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    char fp[64];
    int rc = gfmx_fingerprint(buf, n, fp, sizeof fp);
    if (rc != 0) { fprintf(stderr, "not a parseable certificate (%d)\n", rc); return 1; }
    printf("%s\n", fp);
    char *js = gfmx_json(buf, n);
    printf("%s\n", js);
    gfmx_free(js);
    printf("libgfmx %s\n", gfmx_version());
    return 0;
}
