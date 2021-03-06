/* vi: set expandtab sw=4 sts=4: */
/*
 * Utility routines.
 *
 * Copyright (C) 1999,2000,2001 by Erik Andersen <andersee@debian.org>
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include "config.h"

#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "opkg_message.h"
#include "xfuncs.h"

extern void *xmalloc(size_t size)
{
    void *ptr = malloc(size);
    if (ptr == NULL && size != 0) {
        opkg_perror(ERROR, "malloc");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

extern void *xrealloc(void *ptr, size_t size)
{
    ptr = realloc(ptr, size);
    if (ptr == NULL && size != 0) {
        opkg_perror(ERROR, "realloc");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

extern void *xcalloc(size_t nmemb, size_t size)
{
    void *ptr = calloc(nmemb, size);
    if (ptr == NULL && nmemb != 0 && size != 0) {
        opkg_perror(ERROR, "calloc");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

extern char *xstrdup(const char *s)
{
    char *t;

    if (s == NULL)
        return NULL;

    t = strdup(s);

    if (t == NULL) {
        opkg_perror(ERROR, "strdup");
        exit(EXIT_FAILURE);
    }

    return t;
}

extern char *xstrndup(const char *s, int n)
{
    char *t;

    if (s == NULL)
        return NULL;

    t = strndup(s, n);

    if (t == NULL) {
        opkg_perror(ERROR, "strdup");
        exit(EXIT_FAILURE);
    }

    return t;
}

/* Sane dirname. */
extern char *xdirname(const char *path)
{
    char *pathcopy, *parent, *tmp;

    /* dirname is unsafe, it may both modify the memory of the path argument
     * and may return a pointer to static memory, which can then be modified
     * by consequtive calls to dirname.
     */
    pathcopy = xstrdup(path);
    tmp = dirname(pathcopy);
    parent = xstrdup(tmp);
    free(pathcopy);
    return parent;
}
