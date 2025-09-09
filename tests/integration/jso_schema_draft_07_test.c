/*
 * Copyright (c) 2025 Jakub Zelenka. All rights reserved.
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

#define JSO_SCHEMA_DRAFT_TEST_VERSION_VALUE JSO_SCHEMA_VERSION_VALUE_DRAFT_07
#define JSO_SCHEMA_DRAFT_TEST_VERSION_IDENTIFIER JSO_SCHEMA_VERSION_IDENTIFIER_DRAFT_07

#include "jso_schema_draft_test.h"

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
		cmocka_unit_test(test_jso_schema_object_props_bool),
		cmocka_unit_test(test_jso_schema_object_pattern_props),
		cmocka_unit_test(test_jso_schema_object_additional_props_false),
		cmocka_unit_test(test_jso_schema_object_additional_props_type),
		cmocka_unit_test(test_jso_schema_object_all_props_non_overlap),
		cmocka_unit_test(test_jso_schema_object_required_props),
		cmocka_unit_test(test_jso_schema_object_required_props_empty),
		cmocka_unit_test(test_jso_schema_object_property_names),
		cmocka_unit_test(test_jso_schema_object_dependencies_array_of_strings),
		cmocka_unit_test(test_jso_schema_object_dependencies_schema),
		cmocka_unit_test(test_jso_schema_object_size),
		cmocka_unit_test(test_jso_schema_object_with_array),
		cmocka_unit_test(test_jso_schema_array_items_number),
		cmocka_unit_test(test_jso_schema_array_items_any),
		cmocka_unit_test(test_jso_schema_array_tuple),
		cmocka_unit_test(test_jso_schema_array_additional_false),
		cmocka_unit_test(test_jso_schema_array_additional_string),
		cmocka_unit_test(test_jso_schema_array_length),
		cmocka_unit_test(test_jso_schema_array_unique),
		cmocka_unit_test(test_jso_schema_array_contains),
		cmocka_unit_test(test_jso_schema_type_array),
		cmocka_unit_test(test_jso_schema_enum_anytype_strings),
		cmocka_unit_test(test_jso_schema_enum_anytype_mixed),
		cmocka_unit_test(test_jso_schema_const_value),
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
