/*
 * fuzzer_tool.c: Implementation of general tool-fuzzing functions
 *
 * Copyright (C) 2022 Red Hat, Inc.
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

#include "fuzzer_tool.h"
#define MAX_ARGC 10000

const uint8_t *get_word(const uint8_t *data, size_t size)
{
	/* Words are separated by one zero byte,
	   return pointer to the next word if there is one */
	const uint8_t *ptr = data;
	if (!data || size == 0 || *data == 0)
		return NULL;
	
	ptr = memchr(data, 0, size - 1);
	return ptr ? ++ptr : NULL;
}

char *extract_word(const uint8_t **data, size_t *size)
{
	/* Find word and return its copy (needs to be freed) */
	char *result = NULL;
	const uint8_t *ptr = NULL;

	if (*size < 2)
		return NULL;

	ptr = get_word(*data, *size);
	if (!ptr)
		return NULL;
	result = strdup((const char *)*data);
	*size -=(ptr - *data);
	*data = ptr;

	return result;
}

int get_fuzzed_argv(const char *app_name, const uint8_t *data, size_t size,
                    char ***argv_out, int *argc_out, const uint8_t **reader_data, size_t *reader_data_size)
{
	const uint8_t *ptr = data, *help_ptr = data;
	size_t ptr_size = size;
	char **argv = NULL;
	int argc = 1;

	/* Count arguments until double zero bytes occurs*/
	while(*ptr != 0) {
		ptr = get_word(help_ptr, ptr_size);
		if (!ptr)
			return -1;
		argc++;
		ptr_size -= (ptr - help_ptr);
		help_ptr = ptr;
	}

	if (argc > MAX_ARGC)
		return -1;

	argv = malloc((argc + 1) * sizeof(char*));
	if (!argv)
		return -1;

	/* Copy arguments into argv */
	ptr = data;
	ptr_size = size;
	argv[0] = strdup(app_name);
	for (int i = 1; i < argc; i++) {
		argv[i] = extract_word(&ptr, &ptr_size);
	}
	argv[argc] = NULL;

	*argc_out = argc;
	*argv_out = argv;
	*reader_data = ptr + 1; /* there are two zero bytes at the end of argv */
	*reader_data_size = ptr_size - 1;
	return 0;
}

uint16_t get_buffer(const uint8_t **buf, size_t buf_len, const uint8_t **out, size_t *out_len, size_t max_size)
{
	/* Split buf into two parts according to length stored in first two bytes */
	uint16_t len = 0;

	if (!buf || !(*buf) || buf_len < sizeof(uint16_t))
		return 0;

	/* Get length of the result buffer*/
	len = *((uint16_t *) *buf) % max_size;
	(*buf) += 2;
	buf_len -= 2;
	if (buf_len <= len) {
		*out = *buf;
		*out_len = buf_len;
		return 0;
	}

	/* Set out buffer to new reader data*/
	*out = *buf + len;
	*out_len = buf_len - len;
	return len;
}

int create_input_file(char **filename_out, const uint8_t **data, size_t *size)
{
	const uint8_t *ptr = *data;
	size_t file_size = 0, backup_size = *size;
	int fd = 0;
	size_t r = 0;
	char *filename = NULL;
	
	/* Split data into file content and rest*/
	file_size = get_buffer(&ptr, *size, data, size, 6000);
	if (file_size == 0)
		return 1;

	filename = strdup("/tmp/input.XXXXXX");
	fd = mkstemp(filename);
	if (fd < 0) {
		*data = ptr - 2;
		*size = backup_size;
		free(filename);
		return 1;
	}

	r = write(fd, ptr, file_size);
	close(fd);

	if (r != file_size) {
		*data = ptr - 2;
		*size = backup_size;
		remove_file(filename);
		return 1;
	}

	*filename_out = filename;
	return 0;
}

void remove_file(char *filename)
{
	if (filename) {
		unlink(filename);
		free(filename);
	}
}

void free_arguments(int argc, char **argv)
{
	for (int i = 0; i < argc; i++) {
		free(argv[i]);
	}
	free(argv);
}
