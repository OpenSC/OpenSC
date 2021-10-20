/*
 * fuzzer.c: Standalone main for fuzz target
 *
 * Copyright (C) 2021 Red Hat, Inc.
 *
 * Author: Veronika Hanulikova <vhanulik@redhat.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput (const unsigned char *data, size_t size);

int main (int argc, char **argv)
{
    printf("Testing one input:\n");
    FILE *fd = NULL;
    size_t len = 0;
    unsigned char *buffer = NULL;

    if (argc < 2) {
        fprintf(stderr, "No arguments, passing NULL\n");
        len = 0;
    } else {
        fd = fopen(argv[1], "r");
        fseek(fd, 0, SEEK_END);
        len = ftell(fd);
        rewind(fd);
        buffer = (unsigned char*) malloc(len);
        if (fread(buffer, 1, len, fd) != len) {
            fprintf(stderr, "fread failed\n");
        }
        fclose(fd);
    }

    LLVMFuzzerTestOneInput(buffer, len);
    if (buffer)
        free(buffer);
    printf("Done!\n");
    return 0;
}
