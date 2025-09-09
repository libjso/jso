AM_CFLAGS = -Wall -std=c11 -I$(top_srcdir)/src

check_PROGRAMS = jso_parser_test jso_pointer_test jso_schema_draft_04_test jso_schema_draft_06_test \
	jso_schema_draft_07_test

TESTS = jso_parser_test jso_schema_draft_04_test jso_schema_draft_06_test jso_schema_draft_07_test

jso_parser_test_LDADD = -lcmocka ../../src/libjso.a
jso_pointer_test_LDADD = -lcmocka ../../src/libjso.a
jso_schema_draft_04_test_LDADD = -lcmocka ../../src/libjso.a
jso_schema_draft_06_test_LDADD = -lcmocka ../../src/libjso.a
jso_schema_draft_07_test_LDADD = -lcmocka ../../src/libjso.a
