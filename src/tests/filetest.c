#include "sc-test.h"
#include "opensc.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	int i;
	struct sc_file file;
	
	i = sc_test_init(&argc, argv);
	if (i < 0)
		return 1;
	memset(&file, 0, sizeof(file));
	
	return 0;
}
