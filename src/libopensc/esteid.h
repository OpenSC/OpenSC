#ifndef _OPENSC_ESTEID_H
#define _OPENSC_ESTEID_H

#define SC_ESTEID_AUTH	1
#define SC_ESTEID_SIGN	2


/* personal data file record numbers */

#define SC_ESTEID_PD_SURNAME      	1
#define SC_ESTEID_PD_GIVEN_NAMES1 	2
#define SC_ESTEID_PD_GIVEN_NAMES2 	3
#define SC_ESTEID_PD_SEX    		4
#define SC_ESTEID_PD_CITIZENSHIP  	5
#define SC_ESTEID_PD_DATE_OF_BIRTH   	6
#define SC_ESTEID_PD_PERSONAL_ID  	7
#define SC_ESTEID_PD_DOCUMENT_NR  	8
#define SC_ESTEID_PD_EXPIRY_DATE  	9
#define SC_ESTEID_PD_PLACE_OF_BIRTH  	10
#define SC_ESTEID_PD_ISSUING_DATE 	11
#define SC_ESTEID_PD_PERMIT_TYPE  	12
#define SC_ESTEID_PD_REMARK1      	13
#define SC_ESTEID_PD_REMARK2      	14
#define SC_ESTEID_PD_REMARK3      	15
#define SC_ESTEID_PD_REMARK4      	16

/* i love constants  */
#define SC_ESTEID_KEYREF_FILE_RECLEN    21

int select_esteid_df(sc_card_t * card);
#endif
