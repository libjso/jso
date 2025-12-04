AM_CFLAGS = -Wall -std=c11

noinst_LIBRARIES = libjso.a
libjso_a_SOURCES = jso.c jso_dbg.c jso_value.c jso_array.c jso_object.c jso_dg_dtoa.c \
	jso_number.c  jso_builder.c jso_encoder.c jso_error.c jso_ht.c jso_re.c \
	jso_scanner.c jso_parser.tab.c parser/jso_parser.c parser/jso_parser_hooks_decode.c \
	parser/jso_parser_hooks_decode_schema.c parser/jso_parser_hooks_validate.c \
	io/jso_io.c io/jso_io_file.c io/jso_io_memory.c io/jso_io_string.c \
	pointer/jso_pointer_error.c pointer/jso_pointer.c \
	schema/jso_schema_array.c schema/jso_schema_data.c schema/jso_schema_error.c  \
	schema/jso_schema_keyword.c schema/jso_schema_keyword_array.c \
	schema/jso_schema_keyword_freer.c schema/jso_schema_keyword_object.c \
	schema/jso_schema_keyword_regexp.c schema/jso_schema_keyword_scalar.c \
	schema/jso_schema_keyword_single.c schema/jso_schema_keyword_types.c \
	schema/jso_schema_keyword_union.c  schema/jso_schema_validation.c \
	schema/jso_schema_reference.c \
	schema/jso_schema_validation_array.c schema/jso_schema_validation_common.c \
	schema/jso_schema_validation_composition.c \
	schema/jso_schema_validation_error.c schema/jso_schema_validation_object.c \
	schema/jso_schema_validation_result.c schema/jso_schema_validation_scalar.c \
	schema/jso_schema_validation_stack.c schema/jso_schema_validation_stream.c \
	schema/jso_schema_validation_string.c schema/jso_schema_validation_value.c \
	schema/jso_schema_value.c schema/jso_schema_value_freer.c \
	schema/jso_schema_value_init.c schema/jso_schema_value_parser.c \
	schema/jso_schema_version.c schema/jso_schema.c schema/jso_schema_uri.c

bin_PROGRAMS = jso
jso_SOURCES =  main.c jso_cli.c
jso_LDADD = libjso.a

include_HEADERS = jso.h jso_types.h jso_dbg.h jso_value.h jso_array.h jso_object.h jso_dg_dtoa.h \
	jso_bitset.h jso_builder.h jso_number.h jso_error.h jso_encoder.h jso_ht.h jso_mm.h \
	jso_parser.h jso_parser.tab.h jso_parser_hooks.h parser/jso_parser_hooks_decode.h \
	parser/jso_parser_hooks_decode_schema.h parser/jso_parser_hooks_validate.h \
	jso_scanner.h jso_string.h jso_io.h io/jso_io_file.h io/jso_io_memory.h io/jso_io_string.h \
	jso_pointer.h pointer/jso_pointer_error.h \
	jso_schema.h schema/jso_schema_array.h schema/jso_schema_data.h schema/jso_schema_error.h  \
	schema/jso_schema_keyword.h schema/jso_schema_keyword_array.h \
	schema/jso_schema_keyword_freer.h schema/jso_schema_keyword_object.h \
	schema/jso_schema_keyword_regexp.h schema/jso_schema_keyword_scalar.h \
	schema/jso_schema_keyword_single.h schema/jso_schema_keyword_types.h \
	schema/jso_schema_keyword_union.h schema/jso_schema_value.h  \
	schema/jso_schema_reference.h \
	schema/jso_schema_validation_array.h schema/jso_schema_validation_common.h \
	schema/jso_schema_validation_composition.h \
	schema/jso_schema_validation_error.h schema/jso_schema_validation_object.h \
	schema/jso_schema_validation_result.h schema/jso_schema_validation_scalar.h \
	schema/jso_schema_validation_stack.h schema/jso_schema_validation_stream.h \
	schema/jso_schema_validation_string.h schema/jso_schema_validation_value.h \
	schema/jso_schema_version.h schema/jso_schema_uri.h jso_tokens.h jso_re.h jso_cli.h


jso_scanner.c: jso_scanner.re jso_scanner.h jso_parser.tab.h
	$(RE2C) -t jso_scanner_defs.h --no-generation-date -bci jso_scanner.re > jso_scanner.c

jso_parser.tab.c jso_parser.tab.h: jso_parser.y jso_parser.h
	$(YACC) --file-prefix=jso_parser -l -d jso_parser.y
