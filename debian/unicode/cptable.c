/*
 * Codepage tables
 *
 * Copyright 2000 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdlib.h>

#include "wine/unicode.h"

/* Everything below this line is generated automatically by cpmap.pl */
/* ### cpmap begin ### */
/* ### cpmap end ### */
/* Everything above this line is generated automatically by cpmap.pl */

#define NB_CODEPAGES  (sizeof(cptables)/sizeof(cptables[0]))


static int cmp_codepage( const void *codepage, const void *entry )
{
    return *(const unsigned int *)codepage - (*(const union cptable *const *)entry)->info.codepage;
}


/* get the table of a given code page */
const union cptable *wine_cp_get_table( unsigned int codepage )
{
    const union cptable **res;

    if (!(res = bsearch( &codepage, cptables, NB_CODEPAGES,
                         sizeof(cptables[0]), cmp_codepage ))) return NULL;
    return *res;
}


/* enum valid codepages */
const union cptable *wine_cp_enum_table( unsigned int index )
{
    if (index >= NB_CODEPAGES) return NULL;
    return cptables[index];
}
