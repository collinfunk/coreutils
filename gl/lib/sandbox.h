/* Functions for platform-specific sandboxing interfaces.

   Copyright 2026 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

#ifndef _GL_SANDBOX_H
#define _GL_SANDBOX_H 1

/* Setup a sandbox with minimal permissions.
   This means that, generally, reads and writes will only allowed on
   standard file descriptors.  Additionally, some directories will
   be left readable to allow for translations.  */
extern void sandbox_restrict_all (void);

#endif
