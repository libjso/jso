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

#include "jso_schema_validation_error.h"

#include "jso_schema_error.h"
#include "jso_schema_value.h"

#include "../jso.h"

#include <stdio.h>

#define JSO_SCHEMA_ERROR_INITIAL_LOCATION_CAPACITY 8

static jso_schema_validation_position_error *jso_schema_validation_error_create(
		jso_schema_error_type type, const char *keyword, char *message)
{
	jso_schema_validation_position_error *error
			= jso_calloc(1, sizeof(jso_schema_validation_position_error));
	if (error == NULL) {
		return NULL;
	}

	error->error_type = type;
	error->location_capacity = JSO_SCHEMA_ERROR_INITIAL_LOCATION_CAPACITY;
	error->message = message;

	error->location = jso_malloc(
			error->location_capacity * sizeof(jso_schema_validation_position_error_location));
	if (error->location == NULL) {
		jso_free(error);
		return NULL;
	}

	if (keyword != NULL) {
		error->keyword = jso_strdup(keyword);
		if (error->keyword == NULL) {
			jso_free(error->location);
			jso_free(error);
			return NULL;
		}
	}

	return error;
}

static void jso_schema_validation_error_location_free(
		jso_schema_validation_position_error_location *location)
{
	if (location->type == JSO_SCHEMA_VALIDATION_POSITION_ERROR_LOCATION_OBJECT) {
		jso_string_free(location->key);
	}
}

static void jso_schema_validation_error_free(jso_schema_validation_position_error *error)
{
	if (error == NULL) {
		return;
	}

	if (error->message) {
		jso_free(error->message);
	}

	if (error->location) {
		for (jso_uint32 i = 0; i < error->location_size; i++) {
			jso_schema_validation_error_location_free(&error->location[i]);
		}
		jso_free(error->location);
	}

	jso_free(error);
}

static jso_rc jso_schema_validation_error_add_location(jso_schema_validation_position_error *error,
		jso_schema_validation_position_error_location *location)
{
	if (error->location_size >= error->location_capacity) {
		jso_uint32 new_capacity = error->location_capacity * 2;
		jso_schema_validation_position_error_location *new_location = jso_realloc(error->location,
				new_capacity * sizeof(jso_schema_validation_position_error_location));
		if (new_location == NULL) {
			return JSO_FAILURE;
		}
		error->location = new_location;
		error->location_capacity = new_capacity;
	}

	error->location[error->location_size] = *location;
	error->location_size++;

	return JSO_SUCCESS;
}

static jso_schema_validation_position_errors *jso_schema_validation_errors_create()
{
	jso_schema_validation_position_errors *errors
			= jso_malloc(sizeof(jso_schema_validation_position_errors));
	if (errors == NULL) {
		return NULL;
	}

	errors->head = NULL;
	errors->tail = NULL;
	errors->count = 0;

	return errors;
}

void jso_schema_validation_errors_free(jso_schema_validation_position_errors *errors)
{
	if (errors == NULL) {
		return;
	}

	jso_schema_validation_position_error *current = errors->head;
	while (current != NULL) {
		jso_schema_validation_position_error *next = current->next;
		jso_schema_validation_error_free(current);
		current = next;
	}

	jso_free(errors);
}

void jso_schema_validation_errors_branch_free(
		jso_schema_validation_position_errors *errors, jso_uint32 branch)
{
	if (errors == NULL) {
		return;
	}
	if (branch == 0) {
		jso_schema_validation_errors_free(errors);
		return;
	}

	jso_schema_validation_position_error *current = errors->head;
	jso_schema_validation_position_error *prev = NULL;
	while (current != NULL) {
		jso_schema_validation_position_error *next = current->next;
		if (current->branch == branch) {
			jso_schema_validation_error_free(current);
		} else {
			if (prev) {
				prev->next = current;
			} else {
				errors->head = prev;
			}
			prev = current;
		}
		current = next;
	}
	errors->tail = prev;
}

static void jso_schema_validation_errors_append(
		jso_schema_validation_position_errors *errors, jso_schema_validation_position_error *error)
{
	if (errors->tail == NULL) {
		errors->head = errors->tail = error;
	} else {
		errors->tail->next = error;
		errors->tail = error;
	}
	errors->count++;
}

static jso_schema_validation_result jso_schema_validation_error_set_internal(
		jso_schema_validation_position *pos, jso_schema_error_type type, const char *keyword,
		char *message)
{
	if (pos->errors == NULL) {
		pos->errors = jso_schema_validation_errors_create();
		if (pos->errors == NULL) {
			return JSO_SCHEMA_VALIDATION_ERROR;
		}
	}

	jso_schema_validation_position_error *error
			= jso_schema_validation_error_create(type, keyword, message);
	if (error == NULL) {
		return JSO_SCHEMA_VALIDATION_ERROR;
	}

	jso_schema_validation_errors_append(pos->errors, error);

	return JSO_SCHEMA_VALIDATION_INVALID;
}

jso_schema_validation_result jso_schema_validation_error_set(jso_schema_validation_position *pos,
		jso_schema_error_type type, const char *keyword, const char *message)
{
	char *new_message = jso_strdup(message);
	if (new_message == NULL) {
		return JSO_SCHEMA_VALIDATION_ERROR;
	}
	return jso_schema_validation_error_set_internal(pos, type, keyword, new_message);
}

jso_schema_validation_result jso_schema_validation_error_vformat(
		jso_schema_validation_position *pos, jso_schema_error_type type, const char *keyword,
		const char *format, va_list args)
{
	char buf[JSO_SCHEMA_ERROR_FORMAT_SIZE + 1];

	int written = jso_vsnprintf(buf, JSO_SCHEMA_ERROR_FORMAT_SIZE, format, args);

	if (written < 0) {
		return jso_schema_validation_error_set(pos, type, keyword, "Error with incorrect format");
	}

	if (written >= JSO_SCHEMA_ERROR_FORMAT_SIZE) {
		buf[JSO_SCHEMA_ERROR_FORMAT_SIZE] = '\0';
	}

	return jso_schema_validation_error_set_internal(pos, type, keyword, buf);
}

jso_schema_validation_result jso_schema_validation_error_format(jso_schema_validation_position *pos,
		jso_schema_error_type type, const char *keyword, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	jso_schema_validation_result res
			= jso_schema_validation_error_vformat(pos, type, keyword, format, args);
	va_end(args);
	return res;
}

jso_rc jso_schema_validation_error_propagate_to_parent(jso_schema_validation_position *pos,
		jso_schema_validation_position *parent_pos, jso_uint32 branch)
{
	if (pos->errors == NULL || pos->errors->count == 0) {
		return JSO_SUCCESS;
	}

	if (parent_pos->errors == NULL) {
		parent_pos->errors = jso_schema_validation_errors_create();
		if (parent_pos->errors == NULL) {
			return JSO_FAILURE;
		}
	}

	jso_schema_validation_position_error_location location;

	if (pos->object_key != NULL) {
		// Object property access
		location.type = JSO_SCHEMA_VALIDATION_POSITION_ERROR_LOCATION_OBJECT;
		location.key = jso_string_copy(pos->object_key);
	} else if (parent_pos->current_value
			&& parent_pos->current_value->type == JSO_SCHEMA_VALUE_TYPE_ARRAY) {
		// Array element access
		location.type = JSO_SCHEMA_VALIDATION_POSITION_ERROR_LOCATION_ARRAY;
		location.index = pos->count;
	} else {
		// No location information (possibly root) to add, just transfer errors
		jso_schema_validation_position_error *current = pos->errors->head;
		while (current != NULL) {
			jso_schema_validation_position_error *next = current->next;
			current->next = NULL;
			jso_schema_validation_errors_append(parent_pos->errors, current);
			current = next;
		}
		pos->errors->head = pos->errors->tail = NULL;
		pos->errors->count = 0;
		return JSO_SUCCESS;
	}

	// Add location to each error and transfer to parent
	jso_schema_validation_position_error *current = pos->errors->head;
	while (current != NULL) {
		jso_schema_validation_position_error *next = current->next;

		if (jso_schema_validation_error_add_location(current, &location) == JSO_FAILURE) {
			jso_schema_validation_error_location_free(&location);
			return JSO_FAILURE;
		}

		// Transfer error to parent
		current->branch = branch;
		current->next = NULL;
		jso_schema_validation_errors_append(parent_pos->errors, current);
		current = next;
	}

	// Clear the child errors list
	pos->errors->head = pos->errors->tail = NULL;
	pos->errors->count = 0;

	return JSO_SUCCESS;
}

void jso_schema_validation_position_clear_errors(jso_schema_validation_position *pos)
{
	if (pos->errors != NULL) {
		jso_schema_validation_errors_free(pos->errors);
		pos->errors = NULL;
	}
}

jso_schema_validation_result jso_schema_validation_value_type_error_ex(
		jso_schema_validation_position *pos, jso_value_type expected,
		jso_value_type expected_alternative, jso_value_type actual)
{
	pos->validation_invalid_reason = JSO_SCHEMA_VALIDATION_INVALID_REASON_TYPE;
	return jso_schema_validation_error_type_format(pos,
			"Invalid validation type, expected %s or %s but received %s",
			jso_value_type_to_string(expected), jso_value_type_to_string(expected_alternative),
			jso_value_type_to_string(actual));
}

jso_schema_validation_result jso_schema_validation_value_type_error(
		jso_schema_validation_position *pos, jso_value_type expected, jso_value_type actual)
{
	pos->validation_invalid_reason = JSO_SCHEMA_VALIDATION_INVALID_REASON_TYPE;
	return jso_schema_validation_error_type_format(pos,
			"Invalid validation type, expected %s but received %s",
			jso_value_type_to_string(expected), jso_value_type_to_string(actual));
}

jso_schema_validation_result jso_schema_validation_schema_value_type_error(
		jso_schema_validation_position *pos, jso_schema_value_type expected,
		jso_schema_value_type actual)
{
	pos->validation_invalid_reason = JSO_SCHEMA_VALIDATION_INVALID_REASON_TYPE;
	return jso_schema_validation_error_type_format(pos,
			"Invalid schema type, expected %s but received %s",
			jso_schema_value_type_to_string(expected), jso_schema_value_type_to_string(actual));
}
