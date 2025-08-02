/*
 * Copyright (c) 2023 Jakub Zelenka. All rights reserved.
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

#include "../../../src/schema/jso_schema_value.h"
#include "../../../src/jso.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

/* Wrapping. */

/* Wrapper for jso_re_code_free. */
void __wrap_jso_re_code_free(jso_schema_keyword *keyword)
{
	function_called();
	check_expected_ptr(keyword);
}

/* Wrapper for jso_schema_keyword_free. */
void __wrap_jso_schema_keyword_free(jso_schema_keyword *keyword)
{
	function_called();
	check_expected_ptr(keyword);
}

/* Wrapper for jso_schema_reference_free. */
void __wrap_jso_schema_reference_free(jso_schema_reference *ref)
{
	function_called();
	check_expected_ptr(ref);
}

/* Wrapper for jso_schema_uri_clear. */
void __wrap_jso_schema_uri_clear(jso_schema_uri *uri)
{
	function_called();
	check_expected_ptr(uri);
}

/* Tests for jso_schema_value_parse. */

/* Test helpers */
#define JSO_TEST_SCHEMA_FREE_KW(_val, _kw) \
	expect_function_call(__wrap_jso_schema_keyword_free); \
	expect_value(__wrap_jso_schema_keyword_free, keyword, &_val->_kw)

static void jso_test_expect_free_common(jso_schema_value_common *value)
{
	JSO_TEST_SCHEMA_FREE_KW(value, id);
	JSO_TEST_SCHEMA_FREE_KW(value, ref);
	JSO_TEST_SCHEMA_FREE_KW(value, default_value);
	JSO_TEST_SCHEMA_FREE_KW(value, title);
	JSO_TEST_SCHEMA_FREE_KW(value, description);
	JSO_TEST_SCHEMA_FREE_KW(value, type_any);
	JSO_TEST_SCHEMA_FREE_KW(value, type_list);
	JSO_TEST_SCHEMA_FREE_KW(value, all_of);
	JSO_TEST_SCHEMA_FREE_KW(value, any_of);
	JSO_TEST_SCHEMA_FREE_KW(value, one_of);
	JSO_TEST_SCHEMA_FREE_KW(value, not );
	JSO_TEST_SCHEMA_FREE_KW(value, enum_elements);
	JSO_TEST_SCHEMA_FREE_KW(value, const_value);
	JSO_TEST_SCHEMA_FREE_KW(value, definitions);
}

/* Test freeing any value. */
static void test_jso_schema_value_clear_mixed(void **state)
{
	(void) state; /* unused */

	jso_schema_value value;

	jso_schema_value_common *comval = jso_calloc(1, sizeof(jso_schema_value_common));
	value.data.comval = comval;

	JSO_SCHEMA_VALUE_TYPE(value) = JSO_SCHEMA_VALUE_TYPE_MIXED;

	expect_function_call(__wrap_jso_schema_reference_free);
	expect_value(__wrap_jso_schema_reference_free, ref, value.ref);

	expect_function_call(__wrap_jso_schema_uri_clear);
	expect_value(__wrap_jso_schema_uri_clear, uri, &value.base_uri);

	jso_test_expect_free_common(comval);

	jso_schema_value_clear(&value);
}

/* Test freeing null value. */
static void test_jso_schema_value_clear_null(void **state)
{
	(void) state; /* unused */

	jso_schema_value value;
	jso_schema_value_null *nulval = jso_calloc(1, sizeof(jso_schema_value_null));
	value.data.nulval = nulval;

	JSO_SCHEMA_VALUE_TYPE(value) = JSO_SCHEMA_VALUE_TYPE_NULL;

	expect_function_call(__wrap_jso_schema_reference_free);
	expect_value(__wrap_jso_schema_reference_free, ref, value.ref);

	expect_function_call(__wrap_jso_schema_uri_clear);
	expect_value(__wrap_jso_schema_uri_clear, uri, &value.base_uri);

	jso_test_expect_free_common((jso_schema_value_common *) nulval);

	jso_schema_value_clear(&value);
}

/* Test freeing boolean value. */
static void test_jso_schema_value_clear_boolean(void **state)
{
	(void) state; /* unused */

	jso_schema_value value;
	jso_schema_value_boolean *boolval = jso_calloc(1, sizeof(jso_schema_value_boolean));
	value.data.boolval = boolval;

	JSO_SCHEMA_VALUE_TYPE(value) = JSO_SCHEMA_VALUE_TYPE_BOOLEAN;

	expect_function_call(__wrap_jso_schema_reference_free);
	expect_value(__wrap_jso_schema_reference_free, ref, value.ref);

	expect_function_call(__wrap_jso_schema_uri_clear);
	expect_value(__wrap_jso_schema_uri_clear, uri, &value.base_uri);

	jso_test_expect_free_common((jso_schema_value_common *) boolval);

	jso_schema_value_clear(&value);
}

/* Test freeing integer value. */
static void test_jso_schema_value_clear_integer(void **state)
{
	(void) state; /* unused */

	jso_schema_value value;
	jso_schema_value_integer *intval = jso_calloc(1, sizeof(jso_schema_value_integer));
	value.data.intval = intval;

	JSO_SCHEMA_VALUE_TYPE(value) = JSO_SCHEMA_VALUE_TYPE_INTEGER;

	expect_function_call(__wrap_jso_schema_reference_free);
	expect_value(__wrap_jso_schema_reference_free, ref, value.ref);

	expect_function_call(__wrap_jso_schema_uri_clear);
	expect_value(__wrap_jso_schema_uri_clear, uri, &value.base_uri);

	jso_test_expect_free_common((jso_schema_value_common *) intval);
	JSO_TEST_SCHEMA_FREE_KW(intval, exclusive_maximum);
	JSO_TEST_SCHEMA_FREE_KW(intval, exclusive_minimum);
	JSO_TEST_SCHEMA_FREE_KW(intval, maximum);
	JSO_TEST_SCHEMA_FREE_KW(intval, minimum);
	JSO_TEST_SCHEMA_FREE_KW(intval, multiple_of);

	jso_schema_value_clear(&value);
}

/* Test freeing string value. */
static void test_jso_schema_value_clear_string(void **state)
{
	(void) state; /* unused */

	jso_schema_value value;
	jso_schema_value_string *strval = jso_calloc(1, sizeof(jso_schema_value_string));
	value.data.strval = strval;

	JSO_SCHEMA_VALUE_TYPE(value) = JSO_SCHEMA_VALUE_TYPE_STRING;

	expect_function_call(__wrap_jso_schema_reference_free);
	expect_value(__wrap_jso_schema_reference_free, ref, value.ref);

	expect_function_call(__wrap_jso_schema_uri_clear);
	expect_value(__wrap_jso_schema_uri_clear, uri, &value.base_uri);

	jso_test_expect_free_common((jso_schema_value_common *) strval);
	JSO_TEST_SCHEMA_FREE_KW(strval, min_length);
	JSO_TEST_SCHEMA_FREE_KW(strval, max_length);
	JSO_TEST_SCHEMA_FREE_KW(strval, pattern);

	jso_schema_value_clear(&value);
}

/* Test freeing array value. */
static void test_jso_schema_value_clear_array(void **state)
{
	(void) state; /* unused */

	jso_schema_value value;
	jso_schema_value_array *arrval = jso_calloc(1, sizeof(jso_schema_value_array));
	value.data.arrval = arrval;

	JSO_SCHEMA_VALUE_TYPE(value) = JSO_SCHEMA_VALUE_TYPE_ARRAY;

	expect_function_call(__wrap_jso_schema_reference_free);
	expect_value(__wrap_jso_schema_reference_free, ref, value.ref);

	expect_function_call(__wrap_jso_schema_uri_clear);
	expect_value(__wrap_jso_schema_uri_clear, uri, &value.base_uri);

	jso_test_expect_free_common((jso_schema_value_common *) arrval);
	JSO_TEST_SCHEMA_FREE_KW(arrval, additional_items);
	JSO_TEST_SCHEMA_FREE_KW(arrval, items);
	JSO_TEST_SCHEMA_FREE_KW(arrval, max_items);
	JSO_TEST_SCHEMA_FREE_KW(arrval, min_items);
	JSO_TEST_SCHEMA_FREE_KW(arrval, unique_items);
	JSO_TEST_SCHEMA_FREE_KW(arrval, contains);

	jso_schema_value_clear(&value);
}

/* Test freeing object value. */
static void test_jso_schema_value_clear_object(void **state)
{
	(void) state; /* unused */

	jso_schema_value value;
	jso_schema_value_object *objval = jso_calloc(1, sizeof(jso_schema_value_object));
	value.data.objval = objval;

	JSO_SCHEMA_VALUE_TYPE(value) = JSO_SCHEMA_VALUE_TYPE_OBJECT;

	expect_function_call(__wrap_jso_schema_reference_free);
	expect_value(__wrap_jso_schema_reference_free, ref, value.ref);

	expect_function_call(__wrap_jso_schema_uri_clear);
	expect_value(__wrap_jso_schema_uri_clear, uri, &value.base_uri);

	jso_test_expect_free_common((jso_schema_value_common *) objval);
	JSO_TEST_SCHEMA_FREE_KW(objval, additional_properties);
	JSO_TEST_SCHEMA_FREE_KW(objval, max_properties);
	JSO_TEST_SCHEMA_FREE_KW(objval, min_properties);
	JSO_TEST_SCHEMA_FREE_KW(objval, properties);
	JSO_TEST_SCHEMA_FREE_KW(objval, required);
	JSO_TEST_SCHEMA_FREE_KW(objval, pattern_properties);
	JSO_TEST_SCHEMA_FREE_KW(objval, dependencies);
	JSO_TEST_SCHEMA_FREE_KW(objval, dependent_required);
	JSO_TEST_SCHEMA_FREE_KW(objval, dependent_schemas);
	JSO_TEST_SCHEMA_FREE_KW(objval, cond_if);
	JSO_TEST_SCHEMA_FREE_KW(objval, cond_then);
	JSO_TEST_SCHEMA_FREE_KW(objval, cond_else);
	JSO_TEST_SCHEMA_FREE_KW(objval, property_names);

	jso_schema_value_clear(&value);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_jso_schema_value_clear_mixed),
		cmocka_unit_test(test_jso_schema_value_clear_null),
		cmocka_unit_test(test_jso_schema_value_clear_boolean),
		cmocka_unit_test(test_jso_schema_value_clear_integer),
		cmocka_unit_test(test_jso_schema_value_clear_string),
		cmocka_unit_test(test_jso_schema_value_clear_array),
		cmocka_unit_test(test_jso_schema_value_clear_object),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
