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

/**
 * @file jso_schema_validation_error.h
 * @brief JsonSchema validation error helpers.
 */

#ifndef JSO_SCHEMA_VALIDATION_ERROR_H
#define JSO_SCHEMA_VALIDATION_ERROR_H

#include "../jso_schema.h"

#include <stdarg.h>

jso_schema_validation_result jso_schema_validation_error_set(jso_schema_validation_position *pos,
		jso_schema_error_type type, const char *keyword, const char *message);

jso_schema_validation_result jso_schema_validation_error_vformat(
		jso_schema_validation_position *pos, jso_schema_error_type type, const char *keyword,
		const char *format, va_list args);

jso_schema_validation_result jso_schema_validation_error_format(jso_schema_validation_position *pos,
		jso_schema_error_type type, const char *keyword, const char *format, ...);

jso_rc jso_schema_validation_error_propagate_to_parent(jso_schema_validation_position *pos,
		jso_schema_validation_position *parent_pos, jso_uint32 branch);

void jso_schema_validation_errors_free(jso_schema_validation_position_errors *errors);

void jso_schema_validation_errors_branch_free(
		jso_schema_validation_position_errors *errors, jso_uint32 branch);

void jso_schema_validation_position_clear_errors(jso_schema_validation_position *pos);

jso_schema_validation_result jso_schema_validation_value_type_error_ex(
		jso_schema_validation_position *pos, jso_value_type expected,
		jso_value_type expected_alternative, jso_value_type actual);

jso_schema_validation_result jso_schema_validation_value_type_error(
		jso_schema_validation_position *pos, jso_value_type expected, jso_value_type actual);

jso_schema_validation_result jso_schema_validation_schema_value_type_error(
		jso_schema_validation_position *pos, jso_schema_value_type expected,
		jso_schema_value_type actual);

static inline jso_schema_validation_result jso_schema_validation_error_keyword_format(
		jso_schema_validation_position *pos, const char *keyword, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	jso_schema_validation_result res = jso_schema_validation_error_vformat(
			pos, JSO_SCHEMA_ERROR_VALIDATION_KEYWORD, keyword, format, args);
	va_end(args);
	return res;
}

static inline jso_schema_validation_result jso_schema_validation_error_keyword_set(
		jso_schema_validation_position *pos, const char *keyword, const char *message)
{
	return jso_schema_validation_error_set(
			pos, JSO_SCHEMA_ERROR_VALIDATION_KEYWORD, keyword, message);
}

static inline jso_schema_validation_result jso_schema_validation_error_type_format(
		jso_schema_validation_position *pos, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	jso_schema_validation_result res = jso_schema_validation_error_vformat(
			pos, JSO_SCHEMA_ERROR_VALIDATION_TYPE, "type", format, args);
	va_end(args);
	return res;
}

static inline jso_schema_validation_result jso_schema_validation_error_type_set(
		jso_schema_validation_position *pos, const char *message)
{
	return jso_schema_validation_error_set(pos, JSO_SCHEMA_ERROR_VALIDATION_TYPE, "type", message);
}

static inline jso_schema_validation_result jso_schema_validation_error_composition_set(
		jso_schema_validation_position *pos, const char *keyword, const char *message)
{
	return jso_schema_validation_error_set(
			pos, JSO_SCHEMA_ERROR_VALIDATION_COMPOSITION, keyword, message);
}

#endif /* JSO_SCHEMA_VALIDATION_ERROR_H */
