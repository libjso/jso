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

/* Wrapper for jso_schema_keyword_set. */
jso_rc __wrap_jso_schema_keyword_set(jso_schema *schema, jso_value *data, const char *key,
		jso_schema_value *value, jso_schema_keyword *schema_keyword,
		jso_schema_keyword_type keyword_type, jso_uint32 keyword_flags)
{
	function_called();
	check_expected_ptr(schema);
	check_expected_ptr(data);
	check_expected(key);
	check_expected_ptr(value);
	check_expected_ptr(schema_keyword);
	check_expected(keyword_type);
	check_expected(keyword_flags);

	return mock_type(jso_rc);
}

/* Wrapper for jso_schema_reference_create. */
jso_schema_reference *__wrap_jso_schema_reference_create(
		jso_schema *schema, jso_string *ref_uri, jso_schema_value *value)
{
	function_called();
	check_expected_ptr(schema);
	check_expected_ptr(ref_uri);
	check_expected_ptr(value);

	return mock_ptr_type(jso_schema_reference *);
}

/* Wrapper for jso_schema_reference_free. */
void __wrap_jso_schema_reference_free(jso_schema_reference *ref)
{
	function_called();
	check_expected_ptr(ref);
}

/* Wrapper for jso_schema_reference_resolve. */
jso_rc __wrap_jso_schema_reference_resolve(jso_schema_reference *ref, jso_schema_uri *base_uri,
		jso_schema_value *root_value, jso_value *doc)
{
	function_called();
	check_expected_ptr(ref);
	check_expected_ptr(base_uri);
	check_expected_ptr(root_value);
	check_expected_ptr(doc);

	return mock_type(jso_rc);
}

/* Wrapper for jso_schema_uri_inherit. */
jso_rc __wrap_jso_schema_uri_inherit(
		jso_schema *schema, jso_schema_uri *current_uri, jso_schema_uri *parent_uri)
{
	function_called();
	check_expected_ptr(schema);
	check_expected_ptr(current_uri);
	check_expected_ptr(parent_uri);

	return mock_type(jso_rc);
}

/* Wrapper for jso_schema_uri_set. */
jso_rc __wrap_jso_schema_uri_set(jso_schema *schema, jso_schema_uri *current_uri,
		jso_schema_uri *parent_uri, jso_string *new_uri)
{
	function_called();
	check_expected_ptr(schema);
	check_expected_ptr(current_uri);
	check_expected_ptr(parent_uri);
	check_expected_ptr(new_uri);

	return mock_type(jso_rc);
}

/* Wrapper for jso_schema_value_alloc. */
jso_schema_value *__wrap_jso_schema_value_alloc(jso_schema *schema, const char *type_name)
{
	function_called();
	check_expected_ptr(schema);
	check_expected(type_name);

	return mock_ptr_type(jso_schema_value *);
}

/* Wrapper for jso_schema_value_data_alloc. */
jso_schema_value_common *__wrap_jso_schema_value_data_alloc(
		size_t value_size, jso_schema *schema, const char *type_name)
{
	function_called();
	check_expected(value_size);
	check_expected_ptr(schema);
	check_expected(type_name);

	return mock_ptr_type(jso_schema_value_common *);
}

/* Wrapper for jso_schema_value_free. */
void __wrap_jso_schema_value_free(jso_schema_value *schema_value)
{
	function_called();
	check_expected_ptr(schema_value);
}

/* Tests for jso_schema_value_init. */

/* Test initializing value if all ok and keyword init is enabled and id and ref not set. */
static void test_jso_schema_value_init_when_all_good_and_init_with_idref_not_set(void **state)
{
	(void) state; /* unused */

	jso_schema schema;
	jso_value data;
	jso_schema_value value, parent;
	jso_schema_value_common value_data;
	memset(&data, 0, sizeof(jso_value));

	jso_schema_init(&schema);

	expect_function_call(__wrap_jso_schema_value_alloc);
	expect_value(__wrap_jso_schema_value_alloc, schema, &schema);
	expect_string(__wrap_jso_schema_value_alloc, type_name, "null");
	will_return(__wrap_jso_schema_value_alloc, &value);

	expect_function_call(__wrap_jso_schema_value_data_alloc);
	expect_value(__wrap_jso_schema_value_data_alloc, value_size, 64);
	expect_value(__wrap_jso_schema_value_data_alloc, schema, &schema);
	expect_string(__wrap_jso_schema_value_data_alloc, type_name, "null");
	will_return(__wrap_jso_schema_value_data_alloc, &value_data);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "default");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.default_value);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_ANY);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "description");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.description);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_STRING);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "title");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.title);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_STRING);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "$id");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.id);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_STRING);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);
	JSO_SCHEMA_KEYWORD_FLAGS(value_data.id) = 0;

	expect_function_call(__wrap_jso_schema_uri_inherit);
	expect_value(__wrap_jso_schema_uri_inherit, schema, &schema);
	expect_value(__wrap_jso_schema_uri_inherit, current_uri, &value.base_uri);
	expect_value(__wrap_jso_schema_uri_inherit, parent_uri, &parent.base_uri);
	will_return(__wrap_jso_schema_uri_inherit, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "$ref");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.ref);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_STRING);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);
	JSO_SCHEMA_KEYWORD_FLAGS(value_data.ref) = 0;

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "enum");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.enum_elements);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_ARRAY);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, JSO_SCHEMA_KEYWORD_FLAG_UNIQUE);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "allOf");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.all_of);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type,
			JSO_SCHEMA_KEYWORD_TYPE_ARRAY_OF_SCHEMA_OBJECTS);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, JSO_SCHEMA_KEYWORD_FLAG_NOT_EMPTY);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "anyOf");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.any_of);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type,
			JSO_SCHEMA_KEYWORD_TYPE_ARRAY_OF_SCHEMA_OBJECTS);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, JSO_SCHEMA_KEYWORD_FLAG_NOT_EMPTY);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "oneOf");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.one_of);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type,
			JSO_SCHEMA_KEYWORD_TYPE_ARRAY_OF_SCHEMA_OBJECTS);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, JSO_SCHEMA_KEYWORD_FLAG_NOT_EMPTY);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "not");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.not );
	expect_value(
			__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_SCHEMA_OBJECT);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "definitions");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.definitions);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type,
			JSO_SCHEMA_KEYWORD_TYPE_OBJECT_OF_SCHEMA_OBJECTS);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	jso_schema_value *result_value = jso_schema_value_init(
			&schema, &data, &parent, "null", 64, JSO_SCHEMA_VALUE_TYPE_NULL, true);

	assert_ptr_equal(&value, result_value);
	assert_ptr_equal(JSO_SCHEMA_VALUE_DATA_COMMON_P(result_value), &value_data);
	assert_ptr_equal(value_data.parent, &parent);
}

/* Test initializing value if all ok and keyword init is enabled and id and ref are set. */
static void test_jso_schema_value_init_when_all_good_and_init_with_idref_set(void **state)
{
	(void) state; /* unused */

	jso_schema schema;
	jso_value data;
	jso_schema_value value, parent;
	jso_schema_value_common value_data;
	jso_schema_reference ref;
	jso_object obj;

	memset(&data, 0, sizeof(jso_value));
	memset(&obj, 0, sizeof(jso_object));

	data.data.obj = &obj;

	jso_schema_init(&schema);
	schema.version = JSO_SCHEMA_VERSION_DRAFT_06;

	expect_function_call(__wrap_jso_schema_value_alloc);
	expect_value(__wrap_jso_schema_value_alloc, schema, &schema);
	expect_string(__wrap_jso_schema_value_alloc, type_name, "null");
	will_return(__wrap_jso_schema_value_alloc, &value);

	expect_function_call(__wrap_jso_schema_value_data_alloc);
	expect_value(__wrap_jso_schema_value_data_alloc, value_size, 64);
	expect_value(__wrap_jso_schema_value_data_alloc, schema, &schema);
	expect_string(__wrap_jso_schema_value_data_alloc, type_name, "null");
	will_return(__wrap_jso_schema_value_data_alloc, &value_data);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "default");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.default_value);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_ANY);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "description");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.description);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_STRING);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "title");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.title);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_STRING);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "$id");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.id);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_STRING);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);
	JSO_SCHEMA_KEYWORD_FLAGS(value_data.id) = JSO_SCHEMA_KEYWORD_FLAG_PRESENT;

	expect_function_call(__wrap_jso_schema_uri_set);
	expect_value(__wrap_jso_schema_uri_set, schema, &schema);
	expect_value(__wrap_jso_schema_uri_set, current_uri, &value.base_uri);
	expect_value(__wrap_jso_schema_uri_set, parent_uri, &parent.base_uri);
	expect_value(__wrap_jso_schema_uri_set, new_uri, JSO_SCHEMA_KEYWORD_DATA_STR(value_data.id));
	will_return(__wrap_jso_schema_uri_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "$ref");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.ref);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_STRING);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);
	JSO_SCHEMA_KEYWORD_FLAGS(value_data.ref) = JSO_SCHEMA_KEYWORD_FLAG_PRESENT;

	expect_function_call(__wrap_jso_schema_reference_create);
	expect_value(__wrap_jso_schema_reference_create, schema, &schema);
	expect_value(__wrap_jso_schema_reference_create, ref_uri,
			JSO_SCHEMA_KEYWORD_DATA_STR(value_data.ref));
	expect_value(__wrap_jso_schema_reference_create, value, &value);
	will_return(__wrap_jso_schema_reference_create, &ref);

	expect_function_call(__wrap_jso_schema_reference_resolve);
	expect_value(__wrap_jso_schema_reference_resolve, ref, &ref);
	expect_value(__wrap_jso_schema_reference_resolve, base_uri, &value.base_uri);
	expect_value(__wrap_jso_schema_reference_resolve, root_value, NULL);
	expect_value(__wrap_jso_schema_reference_resolve, doc, &schema.doc);
	will_return(__wrap_jso_schema_reference_resolve, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "enum");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.enum_elements);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_ARRAY);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, JSO_SCHEMA_KEYWORD_FLAG_UNIQUE);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "const");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.const_value);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_ANY);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "allOf");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.all_of);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type,
			JSO_SCHEMA_KEYWORD_TYPE_ARRAY_OF_SCHEMA_OBJECTS);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, JSO_SCHEMA_KEYWORD_FLAG_NOT_EMPTY);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "anyOf");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.any_of);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type,
			JSO_SCHEMA_KEYWORD_TYPE_ARRAY_OF_SCHEMA_OBJECTS);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, JSO_SCHEMA_KEYWORD_FLAG_NOT_EMPTY);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "oneOf");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.one_of);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type,
			JSO_SCHEMA_KEYWORD_TYPE_ARRAY_OF_SCHEMA_OBJECTS);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, JSO_SCHEMA_KEYWORD_FLAG_NOT_EMPTY);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "not");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.not );
	expect_value(
			__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_SCHEMA_OBJECT);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "definitions");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.definitions);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type,
			JSO_SCHEMA_KEYWORD_TYPE_OBJECT_OF_SCHEMA_OBJECTS);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	jso_schema_value *result_value = jso_schema_value_init(
			&schema, &data, &parent, "null", 64, JSO_SCHEMA_VALUE_TYPE_NULL, true);

	assert_ptr_equal(&value, result_value);
	assert_ptr_equal(JSO_SCHEMA_VALUE_DATA_COMMON_P(result_value), &value_data);
	assert_ptr_equal(value_data.parent, &parent);
}

/* Test initializing value if all ok and keyword init is enabled and draft 4 id and ref are set. */
static void test_jso_schema_value_init_when_all_good_and_init_with_draft4_id_set(void **state)
{
	(void) state; /* unused */

	jso_schema schema;
	jso_value data;
	jso_schema_value value, parent;
	jso_schema_value_common value_data;
	jso_schema_reference ref;
	jso_object obj;

	memset(&data, 0, sizeof(jso_value));
	memset(&obj, 0, sizeof(jso_object));

	data.data.obj = &obj;

	jso_schema_init(&schema);
	schema.version = JSO_SCHEMA_VERSION_DRAFT_04;

	expect_function_call(__wrap_jso_schema_value_alloc);
	expect_value(__wrap_jso_schema_value_alloc, schema, &schema);
	expect_string(__wrap_jso_schema_value_alloc, type_name, "null");
	will_return(__wrap_jso_schema_value_alloc, &value);

	expect_function_call(__wrap_jso_schema_value_data_alloc);
	expect_value(__wrap_jso_schema_value_data_alloc, value_size, 64);
	expect_value(__wrap_jso_schema_value_data_alloc, schema, &schema);
	expect_string(__wrap_jso_schema_value_data_alloc, type_name, "null");
	will_return(__wrap_jso_schema_value_data_alloc, &value_data);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "default");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.default_value);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_ANY);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "description");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.description);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_STRING);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "title");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.title);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_STRING);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "id");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.id);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_STRING);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);
	JSO_SCHEMA_KEYWORD_FLAGS(value_data.id) = JSO_SCHEMA_KEYWORD_FLAG_PRESENT;

	expect_function_call(__wrap_jso_schema_uri_set);
	expect_value(__wrap_jso_schema_uri_set, schema, &schema);
	expect_value(__wrap_jso_schema_uri_set, current_uri, &value.base_uri);
	expect_value(__wrap_jso_schema_uri_set, parent_uri, &parent.base_uri);
	expect_value(__wrap_jso_schema_uri_set, new_uri, JSO_SCHEMA_KEYWORD_DATA_STR(value_data.id));
	will_return(__wrap_jso_schema_uri_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "$ref");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.ref);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_STRING);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);
	JSO_SCHEMA_KEYWORD_FLAGS(value_data.ref) = JSO_SCHEMA_KEYWORD_FLAG_PRESENT;

	expect_function_call(__wrap_jso_schema_reference_create);
	expect_value(__wrap_jso_schema_reference_create, schema, &schema);
	expect_value(__wrap_jso_schema_reference_create, ref_uri,
			JSO_SCHEMA_KEYWORD_DATA_STR(value_data.ref));
	expect_value(__wrap_jso_schema_reference_create, value, &value);
	will_return(__wrap_jso_schema_reference_create, &ref);

	expect_function_call(__wrap_jso_schema_reference_resolve);
	expect_value(__wrap_jso_schema_reference_resolve, ref, &ref);
	expect_value(__wrap_jso_schema_reference_resolve, base_uri, &value.base_uri);
	expect_value(__wrap_jso_schema_reference_resolve, root_value, NULL);
	expect_value(__wrap_jso_schema_reference_resolve, doc, &schema.doc);
	will_return(__wrap_jso_schema_reference_resolve, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "enum");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.enum_elements);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_ARRAY);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, JSO_SCHEMA_KEYWORD_FLAG_UNIQUE);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "allOf");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.all_of);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type,
			JSO_SCHEMA_KEYWORD_TYPE_ARRAY_OF_SCHEMA_OBJECTS);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, JSO_SCHEMA_KEYWORD_FLAG_NOT_EMPTY);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "anyOf");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.any_of);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type,
			JSO_SCHEMA_KEYWORD_TYPE_ARRAY_OF_SCHEMA_OBJECTS);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, JSO_SCHEMA_KEYWORD_FLAG_NOT_EMPTY);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "oneOf");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.one_of);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type,
			JSO_SCHEMA_KEYWORD_TYPE_ARRAY_OF_SCHEMA_OBJECTS);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, JSO_SCHEMA_KEYWORD_FLAG_NOT_EMPTY);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "not");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.not );
	expect_value(
			__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_SCHEMA_OBJECT);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "definitions");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.definitions);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type,
			JSO_SCHEMA_KEYWORD_TYPE_OBJECT_OF_SCHEMA_OBJECTS);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	jso_schema_value *result_value = jso_schema_value_init(
			&schema, &data, &parent, "null", 64, JSO_SCHEMA_VALUE_TYPE_NULL, true);

	assert_ptr_equal(&value, result_value);
	assert_ptr_equal(JSO_SCHEMA_VALUE_DATA_COMMON_P(result_value), &value_data);
	assert_ptr_equal(value_data.parent, &parent);
}

/* Test initializing value if all ok and keyword init is enabled and id and ref not set. */
static void test_jso_schema_value_init_when_all_good_and_init_with_ref_only_set(void **state)
{
	(void) state; /* unused */

	jso_schema schema;
	jso_value data;
	jso_schema_value value, parent;
	jso_schema_value_common value_data;
	jso_schema_reference ref;
	jso_object obj;

	memset(&data, 0, sizeof(jso_value));
	memset(&obj, 0, sizeof(jso_object));

	data.data.obj = &obj;

	jso_schema_init(&schema);

	expect_function_call(__wrap_jso_schema_value_alloc);
	expect_value(__wrap_jso_schema_value_alloc, schema, &schema);
	expect_string(__wrap_jso_schema_value_alloc, type_name, "null");
	will_return(__wrap_jso_schema_value_alloc, &value);

	expect_function_call(__wrap_jso_schema_value_data_alloc);
	expect_value(__wrap_jso_schema_value_data_alloc, value_size, 64);
	expect_value(__wrap_jso_schema_value_data_alloc, schema, &schema);
	expect_string(__wrap_jso_schema_value_data_alloc, type_name, "null");
	will_return(__wrap_jso_schema_value_data_alloc, &value_data);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "default");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.default_value);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_ANY);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "description");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.description);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_STRING);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "title");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.title);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_STRING);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "$id");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.id);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_STRING);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);
	JSO_SCHEMA_KEYWORD_FLAGS(value_data.id) = 0;

	expect_function_call(__wrap_jso_schema_uri_inherit);
	expect_value(__wrap_jso_schema_uri_inherit, schema, &schema);
	expect_value(__wrap_jso_schema_uri_inherit, current_uri, &value.base_uri);
	expect_value(__wrap_jso_schema_uri_inherit, parent_uri, &parent.base_uri);
	will_return(__wrap_jso_schema_uri_inherit, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "$ref");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.ref);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_STRING);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);
	JSO_SCHEMA_KEYWORD_FLAGS(value_data.ref) = JSO_SCHEMA_KEYWORD_FLAG_PRESENT;
	JSO_OBJECT_COUNT(&obj) = 1;

	expect_function_call(__wrap_jso_schema_reference_create);
	expect_value(__wrap_jso_schema_reference_create, schema, &schema);
	expect_value(__wrap_jso_schema_reference_create, ref_uri,
			JSO_SCHEMA_KEYWORD_DATA_STR(value_data.ref));
	expect_value(__wrap_jso_schema_reference_create, value, &value);
	will_return(__wrap_jso_schema_reference_create, &ref);

	expect_function_call(__wrap_jso_schema_reference_resolve);
	expect_value(__wrap_jso_schema_reference_resolve, ref, &ref);
	expect_value(__wrap_jso_schema_reference_resolve, base_uri, &value.base_uri);
	expect_value(__wrap_jso_schema_reference_resolve, root_value, NULL);
	expect_value(__wrap_jso_schema_reference_resolve, doc, &schema.doc);
	will_return(__wrap_jso_schema_reference_resolve, JSO_SUCCESS);

	jso_schema_value *result_value = jso_schema_value_init(
			&schema, &data, &parent, "null", 64, JSO_SCHEMA_VALUE_TYPE_NULL, true);

	assert_ptr_equal(&value, result_value);
	assert_ptr_equal(JSO_SCHEMA_VALUE_DATA_COMMON_P(result_value), &value_data);
	assert_ptr_equal(value_data.parent, &parent);
}

/* Test initializing value if all ok and keyword init is disabled. */
static void test_jso_schema_value_init_when_all_good_and_keyword_init_disabled(void **state)
{
	(void) state; /* unused */

	jso_schema schema;
	jso_value data;
	jso_schema_value value, parent;
	jso_schema_value_common value_data;

	jso_schema_init(&schema);

	expect_function_call(__wrap_jso_schema_value_alloc);
	expect_value(__wrap_jso_schema_value_alloc, schema, &schema);
	expect_string(__wrap_jso_schema_value_alloc, type_name, "null");
	will_return(__wrap_jso_schema_value_alloc, &value);

	expect_function_call(__wrap_jso_schema_value_data_alloc);
	expect_value(__wrap_jso_schema_value_data_alloc, value_size, 64);
	expect_value(__wrap_jso_schema_value_data_alloc, schema, &schema);
	expect_string(__wrap_jso_schema_value_data_alloc, type_name, "null");
	will_return(__wrap_jso_schema_value_data_alloc, &value_data);

	jso_schema_value *result_value = jso_schema_value_init(
			&schema, &data, &parent, "null", 64, JSO_SCHEMA_VALUE_TYPE_NULL, false);

	assert_ptr_equal(&value, result_value);
	assert_ptr_equal(JSO_SCHEMA_VALUE_DATA_COMMON_P(result_value), &value_data);
	assert_ptr_equal(value_data.parent, &parent);
}

/* Test initializing value if reference resolving fails. */
static void test_jso_schema_value_init_when_ref_resolve_fails(void **state)
{
	(void) state; /* unused */

	jso_schema schema;
	jso_value data;
	jso_schema_value value, parent;
	jso_schema_value_common value_data;
	jso_schema_reference ref;
	jso_object obj;

	memset(&data, 0, sizeof(jso_value));
	memset(&obj, 0, sizeof(jso_object));

	data.data.obj = &obj;

	jso_schema_init(&schema);

	expect_function_call(__wrap_jso_schema_value_alloc);
	expect_value(__wrap_jso_schema_value_alloc, schema, &schema);
	expect_string(__wrap_jso_schema_value_alloc, type_name, "null");
	will_return(__wrap_jso_schema_value_alloc, &value);

	expect_function_call(__wrap_jso_schema_value_data_alloc);
	expect_value(__wrap_jso_schema_value_data_alloc, value_size, 64);
	expect_value(__wrap_jso_schema_value_data_alloc, schema, &schema);
	expect_string(__wrap_jso_schema_value_data_alloc, type_name, "null");
	will_return(__wrap_jso_schema_value_data_alloc, &value_data);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "default");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.default_value);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_ANY);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "description");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.description);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_STRING);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "title");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.title);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_STRING);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "$id");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.id);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_STRING);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);
	JSO_SCHEMA_KEYWORD_FLAGS(value_data.id) = 0;

	expect_function_call(__wrap_jso_schema_uri_inherit);
	expect_value(__wrap_jso_schema_uri_inherit, schema, &schema);
	expect_value(__wrap_jso_schema_uri_inherit, current_uri, &value.base_uri);
	expect_value(__wrap_jso_schema_uri_inherit, parent_uri, &parent.base_uri);
	will_return(__wrap_jso_schema_uri_inherit, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "$ref");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.ref);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_STRING);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);
	JSO_SCHEMA_KEYWORD_FLAGS(value_data.ref) = JSO_SCHEMA_KEYWORD_FLAG_PRESENT;
	JSO_OBJECT_COUNT(&obj) = 1;

	expect_function_call(__wrap_jso_schema_reference_create);
	expect_value(__wrap_jso_schema_reference_create, schema, &schema);
	expect_value(__wrap_jso_schema_reference_create, ref_uri,
			JSO_SCHEMA_KEYWORD_DATA_STR(value_data.ref));
	expect_value(__wrap_jso_schema_reference_create, value, &value);
	will_return(__wrap_jso_schema_reference_create, &ref);

	expect_function_call(__wrap_jso_schema_reference_resolve);
	expect_value(__wrap_jso_schema_reference_resolve, ref, &ref);
	expect_value(__wrap_jso_schema_reference_resolve, base_uri, &value.base_uri);
	expect_value(__wrap_jso_schema_reference_resolve, root_value, NULL);
	expect_value(__wrap_jso_schema_reference_resolve, doc, &schema.doc);
	will_return(__wrap_jso_schema_reference_resolve, JSO_FAILURE);

	expect_function_call(__wrap_jso_schema_reference_free);
	expect_value(__wrap_jso_schema_reference_free, ref, &ref);

	jso_schema_value *result_value = jso_schema_value_init(
			&schema, &data, &parent, "null", 64, JSO_SCHEMA_VALUE_TYPE_NULL, true);

	assert_null(result_value);
}

/* Test initializing value if description setting fails. */
static void test_jso_schema_value_init_when_description_fails(void **state)
{
	(void) state; /* unused */

	jso_schema schema;
	jso_value data;
	jso_schema_value value, parent;
	jso_schema_value_common value_data;

	jso_schema_init(&schema);

	expect_function_call(__wrap_jso_schema_value_alloc);
	expect_value(__wrap_jso_schema_value_alloc, schema, &schema);
	expect_string(__wrap_jso_schema_value_alloc, type_name, "null");
	will_return(__wrap_jso_schema_value_alloc, &value);

	expect_function_call(__wrap_jso_schema_value_data_alloc);
	expect_value(__wrap_jso_schema_value_data_alloc, value_size, 64);
	expect_value(__wrap_jso_schema_value_data_alloc, schema, &schema);
	expect_string(__wrap_jso_schema_value_data_alloc, type_name, "null");
	will_return(__wrap_jso_schema_value_data_alloc, &value_data);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "default");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.default_value);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_ANY);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_SUCCESS);

	expect_function_call(__wrap_jso_schema_keyword_set);
	expect_value(__wrap_jso_schema_keyword_set, schema, &schema);
	expect_value(__wrap_jso_schema_keyword_set, data, &data);
	expect_string(__wrap_jso_schema_keyword_set, key, "description");
	expect_value(__wrap_jso_schema_keyword_set, value, &value);
	expect_value(__wrap_jso_schema_keyword_set, schema_keyword, &value_data.description);
	expect_value(__wrap_jso_schema_keyword_set, keyword_type, JSO_SCHEMA_KEYWORD_TYPE_STRING);
	expect_value(__wrap_jso_schema_keyword_set, keyword_flags, 0);
	will_return(__wrap_jso_schema_keyword_set, JSO_FAILURE);

	expect_function_call(__wrap_jso_schema_value_free);
	expect_value(__wrap_jso_schema_value_free, schema_value, &value);

	jso_schema_value *result_value = jso_schema_value_init(
			&schema, &data, &parent, "null", 64, JSO_SCHEMA_VALUE_TYPE_NULL, true);

	assert_null(result_value);
}

/* Test initializing value if data allocation fails. */
static void test_jso_schema_value_init_when_allocating_value_data_fails(void **state)
{
	(void) state; /* unused */

	jso_schema schema;
	jso_value data;
	jso_schema_value value, parent;

	jso_schema_init(&schema);

	expect_function_call(__wrap_jso_schema_value_alloc);
	expect_value(__wrap_jso_schema_value_alloc, schema, &schema);
	expect_string(__wrap_jso_schema_value_alloc, type_name, "null");
	will_return(__wrap_jso_schema_value_alloc, &value);

	expect_function_call(__wrap_jso_schema_value_data_alloc);
	expect_value(__wrap_jso_schema_value_data_alloc, value_size, 64);
	expect_value(__wrap_jso_schema_value_data_alloc, schema, &schema);
	expect_string(__wrap_jso_schema_value_data_alloc, type_name, "null");
	will_return(__wrap_jso_schema_value_data_alloc, NULL);

	expect_function_call(__wrap_jso_schema_value_free);
	expect_value(__wrap_jso_schema_value_free, schema_value, &value);

	jso_schema_value *result_value = jso_schema_value_init(
			&schema, &data, &parent, "null", 64, JSO_SCHEMA_VALUE_TYPE_NULL, true);

	assert_null(result_value);
}

/* Test initializing value if value allocation fails. */
static void test_jso_schema_value_init_when_allocating_value_fails(void **state)
{
	(void) state; /* unused */

	jso_schema schema;
	jso_value data;
	jso_schema_value parent;

	jso_schema_init(&schema);

	expect_function_call(__wrap_jso_schema_value_alloc);
	expect_value(__wrap_jso_schema_value_alloc, schema, &schema);
	expect_string(__wrap_jso_schema_value_alloc, type_name, "null");
	will_return(__wrap_jso_schema_value_alloc, NULL);

	jso_schema_value *result_value = jso_schema_value_init(
			&schema, &data, &parent, "null", 64, JSO_SCHEMA_VALUE_TYPE_NULL, true);

	assert_null(result_value);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_jso_schema_value_init_when_all_good_and_init_with_idref_not_set),
		cmocka_unit_test(test_jso_schema_value_init_when_all_good_and_init_with_idref_set),
		cmocka_unit_test(test_jso_schema_value_init_when_all_good_and_init_with_draft4_id_set),
		cmocka_unit_test(test_jso_schema_value_init_when_all_good_and_init_with_ref_only_set),
		cmocka_unit_test(test_jso_schema_value_init_when_all_good_and_keyword_init_disabled),
		cmocka_unit_test(test_jso_schema_value_init_when_ref_resolve_fails),
		cmocka_unit_test(test_jso_schema_value_init_when_description_fails),
		cmocka_unit_test(test_jso_schema_value_init_when_allocating_value_data_fails),
		cmocka_unit_test(test_jso_schema_value_init_when_allocating_value_fails),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
