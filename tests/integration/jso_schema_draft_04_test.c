/*
 * Copyright (c) 2024-2025 Jakub Zelenka. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

#include "../../src/jso_schema.h"

#define JSO_SCHEMA_DRAFT_TEST_VERSION_VALUE JSO_SCHEMA_VERSION_VALUE_DRAFT_04
#define JSO_SCHEMA_DRAFT_TEST_VERSION_IDENTIFIER JSO_SCHEMA_VERSION_IDENTIFIER_DRAFT_04

#include "jso_schema_draft_test.h"

/* A test for a simple integer type with exclusive min and max range. */
static void test_jso_schema_integer_range_exclusive(void **state)
{
	(void) state; /* unused */

	jso_schema_validation_result result;
	jso_builder builder;
	jso_builder_init(&builder);

	// build schema
	jso_schema_test_start_schema_object(&builder);
	jso_builder_object_add_cstr(&builder, "type", "integer");
	jso_builder_object_add_int(&builder, "minimum", 4);
	jso_builder_object_add_int(&builder, "maximum", 100);
	jso_builder_object_add_bool(&builder, "exclusiveMinimum", true);
	jso_builder_object_add_bool(&builder, "exclusiveMaximum", true);
	jso_builder_object_end(&builder);

	jso_schema schema;
	jso_schema_init(&schema);
	assert_jso_schema_result_success(jso_schema_parse(&schema, jso_builder_get_value(&builder)));
	jso_builder_clear_all(&builder);

	jso_value instance;

	JSO_VALUE_SET_INT(instance, 0);
	assert_jso_schema_validation_failure(jso_schema_validate(&schema, &instance));
	jso_value_clear(&instance);

	JSO_VALUE_SET_INT(instance, 4);
	assert_jso_schema_validation_failure(jso_schema_validate(&schema, &instance));
	jso_value_clear(&instance);

	JSO_VALUE_SET_INT(instance, 5);
	assert_jso_schema_validation_success(jso_schema_validate(&schema, &instance));
	jso_value_clear(&instance);

	JSO_VALUE_SET_INT(instance, 10);
	assert_jso_schema_validation_success(jso_schema_validate(&schema, &instance));
	jso_value_clear(&instance);

	JSO_VALUE_SET_INT(instance, 99);
	assert_jso_schema_validation_success(jso_schema_validate(&schema, &instance));
	jso_value_clear(&instance);

	JSO_VALUE_SET_INT(instance, 100);
	assert_jso_schema_validation_failure(jso_schema_validate(&schema, &instance));
	jso_value_clear(&instance);

	JSO_VALUE_SET_INT(instance, -1);
	assert_jso_schema_validation_failure(jso_schema_validate(&schema, &instance));
	jso_value_clear(&instance);

	JSO_VALUE_SET_DOUBLE(instance, -10);
	assert_jso_schema_validation_failure(jso_schema_validate(&schema, &instance));
	jso_value_clear(&instance);

	jso_schema_clear(&schema);
}

/* A test for a simple number type with exclusive min and max range. */
static void test_jso_schema_number_range_exclusive(void **state)
{
	(void) state; /* unused */

	jso_schema_validation_result result;
	jso_builder builder;
	jso_builder_init(&builder);

	// build schema
	jso_schema_test_start_schema_object(&builder);
	jso_builder_object_add_cstr(&builder, "type", "number");
	jso_builder_object_add_int(&builder, "minimum", 4);
	jso_builder_object_add_int(&builder, "maximum", 100);
	jso_builder_object_add_bool(&builder, "exclusiveMinimum", true);
	jso_builder_object_add_bool(&builder, "exclusiveMaximum", true);

	jso_builder_object_end(&builder);

	jso_schema schema;
	jso_schema_init(&schema);
	assert_jso_schema_result_success(jso_schema_parse(&schema, jso_builder_get_value(&builder)));
	jso_builder_clear_all(&builder);

	jso_value instance;

	JSO_VALUE_SET_INT(instance, 0);
	assert_jso_schema_validation_failure(jso_schema_validate(&schema, &instance));
	jso_value_clear(&instance);

	JSO_VALUE_SET_INT(instance, 4);
	assert_jso_schema_validation_failure(jso_schema_validate(&schema, &instance));
	jso_value_clear(&instance);

	JSO_VALUE_SET_INT(instance, 5);
	assert_jso_schema_validation_success(jso_schema_validate(&schema, &instance));
	jso_value_clear(&instance);

	JSO_VALUE_SET_INT(instance, 10);
	assert_jso_schema_validation_success(jso_schema_validate(&schema, &instance));
	jso_value_clear(&instance);

	JSO_VALUE_SET_INT(instance, 99);
	assert_jso_schema_validation_success(jso_schema_validate(&schema, &instance));
	jso_value_clear(&instance);

	JSO_VALUE_SET_INT(instance, 100);
	assert_jso_schema_validation_failure(jso_schema_validate(&schema, &instance));
	jso_value_clear(&instance);

	JSO_VALUE_SET_INT(instance, -1);
	assert_jso_schema_validation_failure(jso_schema_validate(&schema, &instance));
	jso_value_clear(&instance);

	JSO_VALUE_SET_DOUBLE(instance, -10);
	assert_jso_schema_validation_failure(jso_schema_validate(&schema, &instance));
	jso_value_clear(&instance);

	jso_schema_clear(&schema);
}

/* A test for an object type with empty required properties - schema failure. */
static void test_jso_schema_object_required_props_empty(void **state)
{
	(void) state; /* unused */

	jso_builder builder;
	jso_builder_init(&builder);

	// build schema
	jso_schema_test_start_schema_object(&builder);
	jso_builder_object_add_cstr(&builder, "type", "object");
	// properties
	jso_builder_object_add_object_start(&builder, "properties");
	// name property
	jso_builder_object_add_object_start(&builder, "name");
	jso_builder_object_add_cstr(&builder, "type", "string");
	jso_builder_object_end(&builder);
	// email property
	jso_builder_object_add_object_start(&builder, "email");
	jso_builder_object_add_cstr(&builder, "type", "string");
	jso_builder_object_end(&builder);
	// address property
	jso_builder_object_add_object_start(&builder, "address");
	jso_builder_object_add_cstr(&builder, "type", "string");
	jso_builder_object_end(&builder);
	// telephone property
	jso_builder_object_add_object_start(&builder, "telephone");
	jso_builder_object_add_cstr(&builder, "type", "string");
	jso_builder_object_end(&builder);
	// end properties
	jso_builder_object_end(&builder);
	// required
	jso_builder_object_add_array_start(&builder, "required");
	jso_builder_array_end(&builder);
	// end root
	jso_builder_object_end(&builder);

	jso_schema schema;
	jso_schema_init(&schema);
	assert_int_equal(JSO_FAILURE, jso_schema_parse(&schema, jso_builder_get_value(&builder)));
	assert_int_equal(JSO_SCHEMA_ERROR_VALUE_DATA_DEPS, JSO_SCHEMA_ERROR_TYPE(&schema));
	jso_builder_clear_all(&builder);
	jso_schema_clear(&schema);
}

/* A test for an array type with items. */
static void test_jso_schema_array_items(void **state)
{
	(void) state; /* unused */

	jso_schema_validation_result result;
	jso_builder builder;
	jso_builder_init(&builder);

	// build schema
	jso_schema_test_start_schema_object(&builder);
	jso_builder_object_add_cstr(&builder, "type", "array");
	jso_builder_object_add_object_start(&builder, "items");
	jso_builder_object_add_cstr(&builder, "type", "number");
	jso_builder_object_end(&builder);
	jso_builder_object_end(&builder);

	jso_schema schema;
	jso_schema_init(&schema);
	assert_jso_schema_result_success(jso_schema_parse(&schema, jso_builder_get_value(&builder)));
	jso_builder_clear_all(&builder);

	// valid empty array
	jso_builder_array_start(&builder);
	assert_jso_schema_validation_success(
			jso_schema_validate(&schema, jso_builder_get_value(&builder)));
	jso_builder_clear_all(&builder);

	// valid with number items
	jso_builder_array_start(&builder);
	jso_builder_array_add_int(&builder, 0);
	jso_builder_array_add_int(&builder, 1);
	jso_builder_array_add_int(&builder, 2);
	jso_builder_array_add_int(&builder, 3);
	jso_builder_array_add_int(&builder, 4);
	assert_jso_schema_validation_success(
			jso_schema_validate(&schema, jso_builder_get_value(&builder)));
	jso_builder_clear_all(&builder);

	// invalid with one string item between number items
	jso_builder_array_start(&builder);
	jso_builder_array_add_int(&builder, 0);
	jso_builder_array_add_int(&builder, 1);
	jso_builder_array_add_cstr(&builder, "2");
	jso_builder_array_add_int(&builder, 3);
	jso_builder_array_add_int(&builder, 4);
	assert_jso_schema_validation_failure(
			jso_schema_validate(&schema, jso_builder_get_value(&builder)));
	jso_builder_clear_all(&builder);

	// invalid with empty object
	jso_builder_object_start(&builder);
	assert_jso_schema_validation_failure(
			jso_schema_validate(&schema, jso_builder_get_value(&builder)));
	jso_builder_clear_all(&builder);

	jso_schema_clear(&schema);
}

/* A test for an array tuple - items with different types. */
static void test_jso_schema_array_tuple(void **state)
{
	(void) state; /* unused */

	jso_schema_validation_result result;
	jso_builder builder;
	jso_builder_init(&builder);

	// build schema
	jso_schema_test_start_schema_object(&builder);
	jso_builder_object_add_cstr(&builder, "type", "array");
	jso_builder_object_add_array_start(&builder, "items");
	// first item number
	jso_builder_array_add_object_start(&builder);
	jso_builder_object_add_cstr(&builder, "type", "number");
	jso_builder_object_end(&builder);
	// second item string
	jso_builder_array_add_object_start(&builder);
	jso_builder_object_add_cstr(&builder, "type", "string");
	jso_builder_object_end(&builder);
	// third item boolean
	jso_builder_array_add_object_start(&builder);
	jso_builder_object_add_cstr(&builder, "type", "boolean");
	jso_builder_object_end(&builder);
	// end
	jso_builder_array_end(&builder);
	jso_builder_object_end(&builder);

	jso_schema schema;
	jso_schema_init(&schema);
	assert_jso_schema_result_success(jso_schema_parse(&schema, jso_builder_get_value(&builder)));
	jso_builder_clear_all(&builder);

	// valid empty array
	jso_builder_array_start(&builder);
	assert_jso_schema_validation_success(
			jso_schema_validate(&schema, jso_builder_get_value(&builder)));
	jso_builder_clear_all(&builder);

	// valid with all items
	jso_builder_array_start(&builder);
	jso_builder_array_add_int(&builder, 3);
	jso_builder_array_add_cstr(&builder, "street");
	jso_builder_array_add_bool(&builder, true);
	assert_jso_schema_validation_success(
			jso_schema_validate(&schema, jso_builder_get_value(&builder)));
	jso_builder_clear_all(&builder);

	// valid with not all items
	jso_builder_array_start(&builder);
	jso_builder_array_add_int(&builder, 3);
	jso_builder_array_add_cstr(&builder, "street");
	assert_jso_schema_validation_success(
			jso_schema_validate(&schema, jso_builder_get_value(&builder)));
	jso_builder_clear_all(&builder);

	// invalid with more items
	jso_builder_array_start(&builder);
	jso_builder_array_add_int(&builder, 3);
	jso_builder_array_add_cstr(&builder, "street");
	jso_builder_array_add_bool(&builder, true);
	jso_builder_array_add_cstr(&builder, "street");
	assert_jso_schema_validation_success(
			jso_schema_validate(&schema, jso_builder_get_value(&builder)));
	jso_builder_clear_all(&builder);

	// invalid with last item type incorrect
	jso_builder_array_start(&builder);
	jso_builder_array_add_int(&builder, 3);
	jso_builder_array_add_cstr(&builder, "street");
	jso_builder_array_add_cstr(&builder, "street2");
	jso_builder_array_add_bool(&builder, true);
	assert_jso_schema_validation_failure(
			jso_schema_validate(&schema, jso_builder_get_value(&builder)));
	jso_builder_clear_all(&builder);

	// invalid with first item type incorrect
	jso_builder_array_start(&builder);
	jso_builder_array_add_cstr(&builder, "street");
	jso_builder_array_add_cstr(&builder, "street2");
	jso_builder_array_add_bool(&builder, true);
	assert_jso_schema_validation_failure(
			jso_schema_validate(&schema, jso_builder_get_value(&builder)));
	jso_builder_clear_all(&builder);

	jso_schema_clear(&schema);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_jso_schema_boolean),
		cmocka_unit_test(test_jso_schema_string_with_lengths),
		cmocka_unit_test(test_jso_schema_string_with_pattern),
		cmocka_unit_test(test_jso_schema_integer),
		cmocka_unit_test(test_jso_schema_integer_range_simple),
		cmocka_unit_test(test_jso_schema_integer_range_exclusive),
		cmocka_unit_test(test_jso_schema_number_multiple),
		cmocka_unit_test(test_jso_schema_number_range_simple),
		cmocka_unit_test(test_jso_schema_number_range_exclusive),
		cmocka_unit_test(test_jso_schema_null),
		cmocka_unit_test(test_jso_schema_object_props),
		cmocka_unit_test(test_jso_schema_object_pattern_props),
		cmocka_unit_test(test_jso_schema_object_additional_props_false),
		cmocka_unit_test(test_jso_schema_object_additional_props_type),
		cmocka_unit_test(test_jso_schema_object_all_props_non_overlap),
		cmocka_unit_test(test_jso_schema_object_required_props),
		cmocka_unit_test(test_jso_schema_object_required_props_empty),
		cmocka_unit_test(test_jso_schema_object_size),
		cmocka_unit_test(test_jso_schema_object_with_array),
		cmocka_unit_test(test_jso_schema_array_items),
		cmocka_unit_test(test_jso_schema_array_tuple),
		cmocka_unit_test(test_jso_schema_array_additional_false),
		cmocka_unit_test(test_jso_schema_array_additional_string),
		cmocka_unit_test(test_jso_schema_array_length),
		cmocka_unit_test(test_jso_schema_array_unique),
		cmocka_unit_test(test_jso_schema_type_array),
		cmocka_unit_test(test_jso_schema_enum_anytype_strings),
		cmocka_unit_test(test_jso_schema_enum_anytype_mixed),
		cmocka_unit_test(test_jso_schema_all_of_basic),
		cmocka_unit_test(test_jso_schema_all_of_illogical),
		cmocka_unit_test(test_jso_schema_any_of_basic),
		cmocka_unit_test(test_jso_schema_one_of_basic),
		cmocka_unit_test(test_jso_schema_one_of_factored),
		cmocka_unit_test(test_jso_schema_not_basic),
		cmocka_unit_test(test_jso_schema_composed_mix),
		cmocka_unit_test(test_jso_schema_empty_object),
		cmocka_unit_test(test_jso_schema_not_object),
		cmocka_unit_test(test_jso_schema_root_true),
		cmocka_unit_test(test_jso_schema_root_false),
		cmocka_unit_test(test_jso_schema_refs_with_defs),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
