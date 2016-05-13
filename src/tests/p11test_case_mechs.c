#include "p11test_case_mechs.h"

void supported_mechanisms_test(void **state) {
	token_info_t *info = (token_info_t *) *state;
	CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;

	CK_RV rv;
	CK_ULONG mechanism_count, i;
	CK_MECHANISM_TYPE_PTR mechanism_list;
	CK_MECHANISM_INFO_PTR mechanism_info;

	rv = function_pointer->C_GetMechanismList(info->slot_id, NULL_PTR, &mechanism_count);
	assert_int_not_equal(mechanism_count,0);
	if ((rv == CKR_OK) && (mechanism_count > 0)) {
		mechanism_list = (CK_MECHANISM_TYPE_PTR) malloc(mechanism_count * sizeof(CK_MECHANISM_TYPE));
		rv = function_pointer->C_GetMechanismList(info->slot_id, mechanism_list, &mechanism_count);
		if (rv != CKR_OK) {
			free(mechanism_list);
			function_pointer->C_Finalize(NULL_PTR);
			fail_msg("Could not get mechanism list!\n");
		}
		assert_non_null(mechanism_list);

		mechanism_info = (CK_MECHANISM_INFO_PTR) malloc(mechanism_count * sizeof(CK_MECHANISM_INFO));

		for (i=0; i< mechanism_count; i++) {
			CK_MECHANISM_TYPE mechanism_type = mechanism_list[i];
			rv = function_pointer->C_GetMechanismInfo(info->slot_id,
				mechanism_type, &mechanism_info[i]);

			if(rv != CKR_OK){
				continue;
			}
		}

		printf("[    MECHANISM    ] [ KEY SIZE ] [  FLAGS   ]\n");
		printf("[                 ] [ MIN][ MAX] [          ]\n");
		for (i = 0; i < mechanism_count; i++) {
			printf("[%-17s] [%4lu][%4lu] [%10s]", get_mechanism_name(mechanism_list[i]),
				mechanism_info[i].ulMinKeySize, mechanism_info[i].ulMaxKeySize,
				get_mechanism_flag_name(mechanism_info[i].flags));
			for (CK_FLAGS j = 1; j <= CKF_EC_COMPRESS; j = j<<1)
				if ((mechanism_info[i].flags & j) != 0)
					printf(" %s", get_mechanism_flag_name(j));
			printf("\n");
		}
		free(mechanism_list);
		free(mechanism_info);
	}
}

