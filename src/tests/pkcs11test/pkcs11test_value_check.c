#include "pkcs11test_value_check.h"

/* Checkers for values */
int
check_num_value(CK_ULONG expected, CK_ULONG actual, enum ck_type type)
{
	char *str1 = "UNKNOWN", *str2 = "UNKNOWN";
	if (expected != actual) {
		if (type != INT) {
			/* Print strings */
			lookup_enum(type, expected, &str1);
			lookup_enum(type, actual, &str2);
			error_log("\t\t\t\tExpected %s, but got %s", str1, str2);
		} else {
			error_log("\t\t\t\tExpected %lu, but got %lu", expected, actual);
		}
	} else {
		if (type != INT) {
			/* Print strings */
			lookup_enum(type, actual, &str1);
			error_log("\t\t\t\tReceived %s is correct", str1);
		} else {
			error_log("\t\t\t\tReceived %lu is correct", actual);
		}
	}
	return PKCS11TEST_SUCCESS;
}

int
check_memory(CK_BYTE_PTR expected, CK_BYTE_PTR actual, size_t length)
{
	if (memcmp(expected, actual, length) != 0) {
		error_log("\t\t\t\tMemory values differ");
	} else {
		log("\t\t\t\tMemory value is correct");
	}
	return PKCS11TEST_SUCCESS;
}

int
check_CK_BYTE(CK_BYTE expected, CK_BYTE actual)
{
	if (expected != actual) {
		error_log("\t\t\t\tByte values differ: expected %02x, but got %02x", expected, actual);
	} else {
		log("\t\t\t\tByte value is correct");
	}
	return PKCS11TEST_SUCCESS;
}
