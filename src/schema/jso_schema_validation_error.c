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

#include "jso_schema_error.h"
#include "jso_schema_value.h"

#include "../jso.h"

#include <stdio.h>

#define JSO_SCHEMA_ERROR_INITIAL_LOCATION_CAPACITY 8

static jso_schema_validation_position_error *jso_schema_validation_error_create(
		jso_schema *schema, jso_schema_error_type type, const char *message)
{
	jso_schema_validation_position_error *error
			= jso_malloc(sizeof(jso_schema_validation_position_error));
	if (error == NULL) {
		return NULL;
	}

	error->next = NULL;
	error->error_type = type;
	error->location_size = 0;
	error->location_capacity = JSO_SCHEMA_ERROR_INITIAL_LOCATION_CAPACITY;

	error->location = jso_malloc(
			error->location_capacity * sizeof(jso_schema_validation_position_error_location));
	if (error->location == NULL) {
		jso_free(error);
		return NULL;
	}

	error->message = jso_malloc(strlen(message) + 1);
	if (error->message == NULL) {
		jso_free(error->location);
		jso_free(error);
		return NULL;
	}
	strcpy(error->message, message);

	return error;
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
			if (error->location[i].type == JSO_SCHEMA_VALIDATION_POSITION_ERROR_LOCATION_OBJECT
					&& error->location[i].key) {
				jso_string_free(error->location[i].key);
			}
		}
		jso_free(error->location);
	}

	jso_free(error);
}

static jso_rc jso_schema_validation_error_add_location(jso_schema_validation_position_error *error,
		jso_schema_validation_position_error_location_type type, void *value)
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

	// Insert at the beginning (reverse order - from leaf to root)
	if (error->location_size > 0) {
		memmove(&error->location[1], &error->location[0],
				error->location_size * sizeof(jso_schema_validation_position_error_location));
	}

	error->location[0].type = type;
	if (type == JSO_SCHEMA_VALIDATION_POSITION_ERROR_LOCATION_OBJECT) {
		error->location[0].key = (jso_string *) value;
	} else {
		error->location[0].index = (size_t) value;
	}
	error->location_size++;

	return JSO_SUCCESS;
}

static jso_schema_validation_position_errors *jso_schema_validation_errors_create(void)
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

jso_schema_validation_result jso_schema_validation_error_set(jso_schema *schema,
		jso_schema_validation_position *pos, jso_schema_error_type type, const char *message)
{
	if (pos->errors == NULL) {
		pos->errors = jso_schema_validation_errors_create();
		if (pos->errors == NULL) {
			return JSO_SCHEMA_VALIDATION_ERROR;
		}
	}

	jso_schema_validation_position_error *error
			= jso_schema_validation_error_create(schema, type, message);
	if (error == NULL) {
		return JSO_SCHEMA_VALIDATION_ERROR;
	}

	jso_schema_validation_errors_append(pos->errors, error);

	return JSO_SCHEMA_VALIDATION_INVALID;
}

jso_schema_validation_result jso_schema_validation_error_format(jso_schema *schema,
		jso_schema_validation_position *pos, jso_schema_error_type type, const char *format, ...)
{
	va_list args;
	char buf[JSO_SCHEMA_ERROR_FORMAT_SIZE + 1];

	va_start(args, format);
	int written = vsnprintf(buf, JSO_SCHEMA_ERROR_FORMAT_SIZE, format, args);
	va_end(args);

	if (written < 0) {
		return jso_schema_validation_error_set(schema, pos, type, "Error with incorrect format");
	}

	if (written >= JSO_SCHEMA_ERROR_FORMAT_SIZE) {
		buf[JSO_SCHEMA_ERROR_FORMAT_SIZE] = '\0';
	}

	return jso_schema_validation_error_set(schema, pos, type, buf);
}

jso_rc jso_schema_validation_error_propagate_to_parent(
		jso_schema_validation_position *pos, jso_schema_validation_position *parent_pos)
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

	// Determine location to add based on parent position
	void *location_value = NULL;
	jso_schema_validation_position_error_location_type location_type;

	if (pos->object_key != NULL) {
		// Object property access
		location_type = JSO_SCHEMA_VALIDATION_POSITION_ERROR_LOCATION_OBJECT;
		// Need to duplicate the key
		jso_string *key_copy = jso_string_create_from_cstr(jso_virt_string_val(pos->object_key));
		if (key_copy == NULL) {
			return JSO_FAILURE;
		}
		location_value = key_copy;
	} else if (parent_pos->current_value
			&& parent_pos->current_value->type == JSO_SCHEMA_VALUE_TYPE_ARRAY) {
		// Array element access
		location_type = JSO_SCHEMA_VALIDATION_POSITION_ERROR_LOCATION_ARRAY;
		location_value = (void *) pos->count;
	} else {
		// No location information to add, just transfer errors
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

		if (jso_schema_validation_error_add_location(current, location_type, location_value)
				== JSO_FAILURE) {
			if (location_type == JSO_SCHEMA_VALIDATION_POSITION_ERROR_LOCATION_OBJECT) {
				jso_string_free((jso_string *) location_value);
			}
			return JSO_FAILURE;
		}

		// Transfer error to parent
		current->next = NULL;
		jso_schema_validation_errors_append(parent_pos->errors, current);
		current = next;

		// For object keys, we need to duplicate for each error after the first
		if (next != NULL && location_type == JSO_SCHEMA_VALIDATION_POSITION_ERROR_LOCATION_OBJECT) {
			jso_string *key_copy = jso_string_copy((jso_string *) location_value);
			if (key_copy == NULL) {
				return JSO_FAILURE;
			}
			location_value = key_copy;
		}
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

jso_schema_validation_result jso_schema_validation_value_type_error_ex(jso_schema *schema,
		jso_schema_validation_position *pos, jso_value_type expected,
		jso_value_type expected_alternative, jso_value_type actual)
{
	jso_schema_error_format(schema, JSO_SCHEMA_ERROR_VALIDATION_TYPE,
			"Invalid validation type, expected %s or %s but received %s",
			jso_value_type_to_string(expected), jso_value_type_to_string(expected_alternative),
			jso_value_type_to_string(actual));
	pos->validation_invalid_reason = JSO_SCHEMA_VALIDATION_INVALID_REASON_TYPE;
	return JSO_SCHEMA_VALIDATION_INVALID;
}

jso_schema_validation_result jso_schema_validation_value_type_error(jso_schema *schema,
		jso_schema_validation_position *pos, jso_value_type expected, jso_value_type actual)
{
	jso_schema_error_format(schema, JSO_SCHEMA_ERROR_VALIDATION_TYPE,
			"Invalid validation type, expected %s but received %s",
			jso_value_type_to_string(expected), jso_value_type_to_string(actual));
	pos->validation_invalid_reason = JSO_SCHEMA_VALIDATION_INVALID_REASON_TYPE;
	return JSO_SCHEMA_VALIDATION_INVALID;
}

jso_schema_validation_result jso_schema_validation_schema_value_type_error(jso_schema *schema,
		jso_schema_validation_position *pos, jso_schema_value_type expected,
		jso_schema_value_type actual)
{
	jso_schema_error_format(schema, JSO_SCHEMA_ERROR_VALIDATION_TYPE,
			"Invalid schema type, expected %s but received %s",
			jso_schema_value_type_to_string(expected), jso_schema_value_type_to_string(actual));
	pos->validation_invalid_reason = JSO_SCHEMA_VALIDATION_INVALID_REASON_TYPE;
	return JSO_SCHEMA_VALIDATION_INVALID;
}
