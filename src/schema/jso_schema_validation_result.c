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
#include "jso_schema_validation_result.h"

#include "jso_schema_error.h"

#include "../jso.h"

static void jso_schema_validation_result_set_parent_result(
		jso_schema_validation_position *parent_pos, jso_schema_validation_result result)
{
	jso_schema_validation_set_result(parent_pos, result, parent_pos->dependency_key == NULL);
}

jso_rc jso_schema_validation_result_propagate(
		jso_schema *schema, jso_schema_validation_position *pos)
{
	jso_schema_validation_position *parent_pos = pos->parent;
	if (parent_pos == NULL) {
		return JSO_SUCCESS;
	}
	if (parent_pos->is_final_validation_result) {
		return JSO_SUCCESS;
	}

	jso_bool should_propagate_errors = false;
	jso_uint32 branch_to_propagate = 0, branch_to_free = 0;

	if (pos->position_type == JSO_SCHEMA_VALIDATION_POSITION_BASIC) {
		if (pos->validation_result != JSO_SCHEMA_VALIDATION_VALID) {
			jso_schema_validation_result_set_parent_result(parent_pos, pos->validation_result);
			should_propagate_errors = true;
		}
	} else {
		JSO_ASSERT_EQ(pos->position_type, JSO_SCHEMA_VALIDATION_POSITION_COMPOSED);
		switch (pos->composition_type) {
			case JSO_SCHEMA_VALIDATION_COMPOSITION_REF:
				jso_schema_validation_result_set_parent_result(parent_pos, pos->validation_result);
				should_propagate_errors = pos->validation_result != JSO_SCHEMA_VALIDATION_VALID;
				break;

			case JSO_SCHEMA_VALIDATION_COMPOSITION_TYPE_ANY:
				// Typed composition ignores failures for invalid type
				if (pos->validation_result != JSO_SCHEMA_VALIDATION_VALID) {
					if (pos->validation_invalid_reason
							== JSO_SCHEMA_VALIDATION_INVALID_REASON_TYPE) {
						should_propagate_errors = true;
					} else {
						jso_schema_validation_result_set_parent_result(
								parent_pos, pos->validation_result);
					}
				}
				break;

			case JSO_SCHEMA_VALIDATION_COMPOSITION_TYPE_LIST:
				// Typed composition ignores failures for invalid type
				if (pos->validation_result != JSO_SCHEMA_VALIDATION_VALID) {
					if (pos->validation_invalid_reason
							!= JSO_SCHEMA_VALIDATION_INVALID_REASON_TYPE) {
						jso_schema_validation_result_set_parent_result(
								parent_pos, pos->validation_result);
						should_propagate_errors = true;
					}
				} else {
					parent_pos->type_valid = true;
				}
				break;

			case JSO_SCHEMA_VALIDATION_COMPOSITION_ALL:
				if (pos->validation_result != JSO_SCHEMA_VALIDATION_VALID) {
					jso_schema_validation_result_set_parent_result(
							parent_pos, pos->validation_result);
					should_propagate_errors = true;
				}
				break;

			case JSO_SCHEMA_VALIDATION_COMPOSITION_ANY:
				if (pos->validation_result == JSO_SCHEMA_VALIDATION_VALID) {
					parent_pos->any_of_valid = true;
				} else {
					should_propagate_errors = true;
				}
				break;

			case JSO_SCHEMA_VALIDATION_COMPOSITION_ONE:
				if (pos->validation_result == JSO_SCHEMA_VALIDATION_VALID) {
					if (parent_pos->one_of_valid) {
						jso_schema_validation_error_composition_set(
								parent_pos, "oneOf", "More than one oneOf subschema was valid");
						pos->validation_invalid_reason
								= JSO_SCHEMA_VALIDATION_INVALID_REASON_COMPOSITION;
						jso_schema_validation_result_set_parent_result(
								parent_pos, JSO_SCHEMA_VALIDATION_INVALID);
					} else {
						parent_pos->one_of_valid = true;
					}
				} else {
					should_propagate_errors = true;
				}
				break;

			case JSO_SCHEMA_VALIDATION_COMPOSITION_IF:
				parent_pos->cond_if_validated = true;
				parent_pos->cond_if_valid = pos->validation_result == JSO_SCHEMA_VALIDATION_VALID;
				if (parent_pos->cond_if_valid) {
					if (parent_pos->cond_then_validated && !parent_pos->cond_then_valid) {
						jso_schema_validation_result_set_parent_result(
								parent_pos, JSO_SCHEMA_VALIDATION_INVALID);
					}
					if (parent_pos->cond_else_validated && !parent_pos->cond_else_valid) {
						branch_to_free = 2;
					}
				} else {
					if (parent_pos->cond_else_validated && !parent_pos->cond_else_valid) {
						jso_schema_validation_result_set_parent_result(
								parent_pos, JSO_SCHEMA_VALIDATION_INVALID);
					}
					if (parent_pos->cond_then_validated && !parent_pos->cond_then_valid) {
						branch_to_free = 1;
					}
				}
				break;

			case JSO_SCHEMA_VALIDATION_COMPOSITION_THEN:
				parent_pos->cond_then_validated = true;
				parent_pos->cond_then_valid = pos->validation_result == JSO_SCHEMA_VALIDATION_VALID;
				if (parent_pos->cond_if_validated && parent_pos->cond_if_valid) {
					if (!parent_pos->cond_then_valid) {
						jso_schema_validation_result_set_parent_result(
								parent_pos, pos->validation_result);
						should_propagate_errors = true;
					}
					if (parent_pos->cond_else_validated && !parent_pos->cond_else_valid) {
						branch_to_free = 2;
					}
				} else if (!parent_pos->cond_then_valid) {
					branch_to_propagate = 1;
					should_propagate_errors = true;
				}
				break;

			case JSO_SCHEMA_VALIDATION_COMPOSITION_ELSE:
				parent_pos->cond_else_validated = true;
				parent_pos->cond_else_valid = pos->validation_result == JSO_SCHEMA_VALIDATION_VALID;
				if (parent_pos->cond_if_validated && !parent_pos->cond_if_valid) {
					if (!parent_pos->cond_else_valid) {
						jso_schema_validation_result_set_parent_result(
								parent_pos, pos->validation_result);
						should_propagate_errors = true;
					}
					if (parent_pos->cond_then_validated && !parent_pos->cond_then_valid) {
						branch_to_free = 1;
					}
				} else if (!parent_pos->cond_else_valid) {
					branch_to_propagate = 2;
					should_propagate_errors = true;
				}
				break;

			default:
				JSO_ASSERT_EQ(pos->composition_type, JSO_SCHEMA_VALIDATION_COMPOSITION_NOT);
				if (pos->validation_result == JSO_SCHEMA_VALIDATION_VALID) {
					jso_schema_validation_error_keyword_set(
							parent_pos, "not", "Negated valid validation");
					pos->validation_invalid_reason
							= JSO_SCHEMA_VALIDATION_INVALID_REASON_COMPOSITION;
					jso_schema_validation_result_set_parent_result(
							parent_pos, JSO_SCHEMA_VALIDATION_INVALID);
				} else {
					// not succeeded, clear the child errors
					should_propagate_errors = false;
				}
				break;
		}
	}

	if (should_propagate_errors) {
		if (jso_schema_validation_error_propagate_to_parent(pos, parent_pos, branch_to_propagate)
				== JSO_FAILURE) {
			// On allocation failure, set a generic error on parent
			return jso_schema_error_set(
					schema, JSO_SCHEMA_ERROR_VALIDATION_PROPAGATION, "Error propagation failed");
		}
	} else {
		jso_schema_validation_errors_branch_free(pos->errors, branch_to_free);
	}

	return JSO_SUCCESS;
}
