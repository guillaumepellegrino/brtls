#pragma once

/*
 * Copyright (C) 2020 Guillaume Pellegrino
 * This file is part of brtls <https://github.com/guillaumepellegrino/brtls>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <syslog.h>

#define log(fmt, ...) syslog(LOG_INFO, fmt " in %s:%d\n", ##__VA_ARGS__, __FUNCTION__, __LINE__)
#define debug(fmt, ...) syslog(LOG_INFO, fmt "\n", ##__VA_ARGS__)
#define console(fmt, ...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)
#define countof(array) (sizeof(array)/sizeof(*array))

