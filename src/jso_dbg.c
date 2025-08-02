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

#include "jso_dbg.h"

#ifdef JSO_DEBUG_ENABLED

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
	FILE *fp;
	char component[32];
	int initialized;
	int timestamp_enabled;
} jso_dbg_config_t;

static jso_dbg_config_t jso_g_dbg_config
		= { .fp = NULL, .component = { 0 }, .initialized = 0, .timestamp_enabled = 0 };

static char *jso_dbg_trim_whitespace(char *str)
{
	char *end;

	while (*str == ' ' || *str == '\t')
		str++;

	if (*str == 0)
		return str;

	end = str + strlen(str) - 1;
	while (end > str && (*end == ' ' || *end == '\t'))
		end--;

	end[1] = '\0';
	return str;
}

static char *jso_dbg_strdup(const char *s)
{
	size_t len = strlen(s) + 1;
	char *copy = malloc(len);
	if (copy) {
		memcpy(copy, s, len);
	}
	return copy;
}

void jso_dbg_init_from_config(const char *config_string)
{
	if (!config_string || jso_g_dbg_config.initialized) {
		return;
	}

	char *config_copy = jso_dbg_strdup(config_string);
	if (!config_copy) {
		return;
	}

	char *file_path = NULL;
	char component[32] = { 0 };
	int timestamp_enabled = 0;

	char *token = strtok(config_copy, ",");
	while (token != NULL) {
		token = jso_dbg_trim_whitespace(token);

		if (strncmp(token, "file:", 5) == 0) {
			file_path = token + 5;
		} else if (strncmp(token, "component:", 10) == 0) {
			char *comp_str = token + 10;
			strncpy(component, comp_str, sizeof(component) - 1);
			component[sizeof(component) - 1] = '\0';
		} else if (strncmp(token, "timestamp:", 10) == 0) {
			char *ts_str = token + 10;
			if (strcmp(ts_str, "yes") == 0 || strcmp(ts_str, "1") == 0) {
				timestamp_enabled = 1;
			}
		}

		token = strtok(NULL, ",");
	}

	if (!file_path || strlen(file_path) == 0) {
		free(config_copy);
		return;
	}

	FILE *fp = fopen(file_path, "a");
	if (!fp) {
		free(config_copy);
		return;
	}

	jso_g_dbg_config.fp = fp;
	jso_g_dbg_config.timestamp_enabled = timestamp_enabled;
	if (strlen(component) > 0) {
		strncpy(jso_g_dbg_config.component, component, sizeof(jso_g_dbg_config.component) - 1);
	}
	jso_g_dbg_config.initialized = 1;

	free(config_copy);

	fprintf(fp, "[DBG_INIT] Debug logging initialized for component: %s\n",
			strlen(component) > 0 ? component : "ALL");
	fflush(fp);
}

void jso_dbg_init_from_env(const char *env_name)
{
	const char *config_env_name = env_name == NULL ? JSO_DBG_DEFAULT_ENV_NAME : env_name;
	const char *config_string = getenv(config_env_name);
	if (config_string != NULL) {
		jso_dbg_init_from_config(config_string);
	}
}

void jso_dbg_log(const char *type, const char *fmt, ...)
{
	if (!jso_g_dbg_config.initialized || !jso_g_dbg_config.fp) {
		return;
	}

	if (strlen(jso_g_dbg_config.component) > 0 && strcmp(jso_g_dbg_config.component, type) != 0) {
		return;
	}

	va_list args;
	va_start(args, fmt);

	if (jso_g_dbg_config.timestamp_enabled) {
		time_t now = time(NULL);
		struct tm *tm_info = localtime(&now);
		fprintf(jso_g_dbg_config.fp, "[%04d-%02d-%02d %02d:%02d:%02d] ", tm_info->tm_year + 1900,
				tm_info->tm_mon + 1, tm_info->tm_mday, tm_info->tm_hour, tm_info->tm_min,
				tm_info->tm_sec);
	}

	fprintf(jso_g_dbg_config.fp, "[%s] ", type);
	vfprintf(jso_g_dbg_config.fp, fmt, args);
	fprintf(jso_g_dbg_config.fp, "\n");
	fflush(jso_g_dbg_config.fp);

	va_end(args);
}

void jso_dbg_cleanup(void)
{
	if (jso_g_dbg_config.initialized && jso_g_dbg_config.fp) {
		fclose(jso_g_dbg_config.fp);
		jso_g_dbg_config.fp = NULL;
		jso_g_dbg_config.initialized = 0;
	}
}

#endif
