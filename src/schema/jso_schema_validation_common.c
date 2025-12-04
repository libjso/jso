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

#include "jso_schema_validation_common.h"
#include "jso_schema_validation_error.h"

#include "jso_schema_error.h"
#include "jso_schema_keyword.h"

#include "../jso.h"

jso_schema_validation_result jso_schema_validation_common_value(jso_schema *schema,
		jso_schema_validation_position *pos, jso_schema_value *value, jso_virt_value *instance)
{
	jso_schema_value_common *comval = JSO_SCHEMA_VALUE_DATA_COMMON_P(value);

	if (JSO_SCHEMA_KW_IS_SET(comval->any_of)) {
		if (!pos->any_of_valid) {
			pos->validation_invalid_reason = JSO_SCHEMA_VALIDATION_INVALID_REASON_COMPOSITION;
			return jso_schema_validation_error_composition_set(
					pos, "any", "No anyOf subschema was valid");
		}
		jso_schema_validation_position_clear_errors(pos);
	}

	if (JSO_SCHEMA_KW_IS_SET(comval->one_of)) {
		if (!pos->one_of_valid) {
			pos->validation_invalid_reason = JSO_SCHEMA_VALIDATION_INVALID_REASON_COMPOSITION;
			return jso_schema_validation_error_composition_set(
					pos, "oneOf", "No oneOf subschema was valid");
		}
		jso_schema_validation_position_clear_errors(pos);
	}

	if (JSO_SCHEMA_KW_IS_SET(comval->type_list)) {
		if (!pos->type_valid) {
			pos->validation_invalid_reason = JSO_SCHEMA_VALIDATION_INVALID_REASON_TYPE;
			return jso_schema_validation_error_type_set(
					pos, "Value is not any of the listed types");
		}
		jso_schema_validation_position_clear_errors(pos);
	}

	if (JSO_SCHEMA_KW_IS_SET(comval->enum_elements)) {
		jso_array *arr = JSO_SCHEMA_KEYWORD_DATA_ARR(comval->enum_elements);
		jso_value *item;
		bool found = false;
		JSO_ARRAY_FOREACH(arr, item)
		{
			if (jso_virt_value_equals(instance, item)) {
				found = true;
				break;
			}
		}
		JSO_ARRAY_FOREACH_END;
		if (!found) {
			pos->validation_invalid_reason = JSO_SCHEMA_VALIDATION_INVALID_REASON_KEYWORD;
			return jso_schema_validation_error_keyword_format(
					pos, "enum", "Instance value not found in enum values");
		}
	}

	if (JSO_SCHEMA_KW_IS_SET(comval->const_value)) {
		if (!jso_virt_value_equals(instance, JSO_SCHEMA_KEYWORD_DATA_ANY(comval->const_value))) {
			pos->validation_invalid_reason = JSO_SCHEMA_VALIDATION_INVALID_REASON_KEYWORD;
			return jso_schema_validation_error_keyword_format(
					pos, "const", "Instance value is not equal to const value");
		}
	}

	return JSO_SCHEMA_VALIDATION_VALID;
}
