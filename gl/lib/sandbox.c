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

#include <config.h>

#include "sandbox.h"

#include <errno.h>
#include <error.h>
#include <stdcountof.h>
#include <string.h>

#if HAVE_LINUX_LANDLOCK_H
# include <linux/landlock.h>
# include <sys/prctl.h>
# include <sys/syscall.h>
# include <stdint.h>
/* These rules did not exist in Landlock ABI version 1.
   Define them here since we may be using an older header.  */
# ifndef LANDLOCK_ACCESS_FS_REFER
#  define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
# endif
# ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#  define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
# endif
# ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#  define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)
# endif
# ifndef LANDLOCK_ACCESS_FS_RESOLVE_UNIX
#  define LANDLOCK_ACCESS_FS_RESOLVE_UNIX (1ULL << 16)
# endif
#elif HAVE_SYS_CAPSICUM_H
# include <sys/capsicum.h>
#endif

#include "gettext.h"
#define _(msgid) gettext (msgid)

#include "attribute.h"
#include "configmake.h"
#include "fcntl--.h"
#include "idx.h"
#include "unistd--.h"

#ifdef O_PATH
enum { O_PATHSEARCH = O_PATH };
#else
enum { O_PATHSEARCH = O_SEARCH };
#endif

#if HAVE_LINUX_LANDLOCK_H
static int
landlock_create_ruleset (struct landlock_ruleset_attr const *const attr,
                         size_t const size, uint32_t const flags)
{
  return syscall (SYS_landlock_create_ruleset, attr, size, flags);
}

static int
landlock_restrict_self (int const fd, uint32_t const flags)
{
  long result = syscall (SYS_landlock_restrict_self, fd, flags);
  if (0 <= result)
    return 0;
  errno = -result;
  return -1;
}


static int
landlock_add_rule (int const fd, enum landlock_rule_type const rule_type,
                   void const *const rule_attr, uint32_t const flags)
{
  long result = syscall (SYS_landlock_add_rule, fd, rule_type,
                         rule_attr, flags);
  if (0 <= result)
    return 0;
  errno = -result;
  return -1;
}
#endif

/* Permit the reading of translation files.  Don't try to guess libc
   internals, which may try to open various files, and just permit
   access to paths under /usr and LOCALEDIR.  Neither should contain
   information that is too sensitive to read.  */
static void
permit_translations (MAYBE_UNUSED int const ruleset_fd,
                     MAYBE_UNUSED unsigned long long int const access_mask)
{
#ifdef HAVE_CAPSICUM_H
#else

  char const *dirs[] = { "/usr", LOCALEDIR };
  idx_t const n_dirs = countof (dirs) - str_startswith (LOCALEDIR, "/usr");

# if HAVE_LINUX_LANDLOCK_H

  struct landlock_path_beneath_attr path_beneath =
    {
      .allowed_access = (LANDLOCK_ACCESS_FS_READ_FILE
                         | LANDLOCK_ACCESS_FS_READ_DIR)
    };
  path_beneath.allowed_access &= access_mask;

  for (idx_t i = 0; i < n_dirs; ++i)
    {
      if (0 < path_beneath.allowed_access)
        {
          path_beneath.parent_fd = open (dirs[i], O_PATHSEARCH | O_DIRECTORY);
          if (0 <= path_beneath.parent_fd)
            {
              landlock_add_rule (ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                                 &path_beneath, 0);
              close (path_beneath.parent_fd);
            }
        }
    }

# elif HAVE_DECL_PLEDGE

  for (idx_t i = 0; i < n_dirs; ++i)
    unveil (dirs[i], "r");

# endif
#endif
}

void
sandbox_restrict_all (void)
{
#if HAVE_LINUX_LANDLOCK_H

  int const abi = landlock_create_ruleset (NULL, 0,
                                           LANDLOCK_CREATE_RULESET_VERSION);

  /* The currently running kernel may not support Landlock.  */
  if (abi < 0)
    return;

  struct landlock_ruleset_attr ruleset_attr =
    {
      .handled_access_fs = (LANDLOCK_ACCESS_FS_EXECUTE
                            | LANDLOCK_ACCESS_FS_WRITE_FILE
                            | LANDLOCK_ACCESS_FS_READ_FILE
                            | LANDLOCK_ACCESS_FS_READ_DIR
                            | LANDLOCK_ACCESS_FS_REMOVE_DIR
                            | LANDLOCK_ACCESS_FS_REMOVE_FILE
                            | LANDLOCK_ACCESS_FS_MAKE_CHAR
                            | LANDLOCK_ACCESS_FS_MAKE_DIR
                            | LANDLOCK_ACCESS_FS_MAKE_REG
                            | LANDLOCK_ACCESS_FS_MAKE_SOCK
                            | LANDLOCK_ACCESS_FS_MAKE_FIFO
                            | LANDLOCK_ACCESS_FS_MAKE_BLOCK
                            | LANDLOCK_ACCESS_FS_MAKE_SYM
                            | LANDLOCK_ACCESS_FS_REFER
                            | LANDLOCK_ACCESS_FS_TRUNCATE
                            | LANDLOCK_ACCESS_FS_IOCTL_DEV
                            | LANDLOCK_ACCESS_FS_RESOLVE_UNIX),
# ifdef LANDLOCK_ACCESS_NET_BIND_TCP
      /* This member did not exist until the TCP flags were added
         in ABI 4.  The UDP flags were added in ABI 10.  */
#  ifndef LANDLOCK_ACCESS_NET_BIND_UDP
#   define LANDLOCK_ACCESS_NET_BIND_UDP (1ULL << 2)
#   define LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP (1ULL << 3)
#  endif
      .handled_access_net = (LANDLOCK_ACCESS_NET_BIND_TCP
                             | LANDLOCK_ACCESS_NET_CONNECT_TCP
                             | LANDLOCK_ACCESS_NET_BIND_UDP
                             | LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP),
# endif
# if LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET
      /* This member did not exist until both flags were added
         in ABI 6.  */
      .scoped = (LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET
                 | LANDLOCK_SCOPE_SIGNAL),
# endif
  };

  switch (abi)
    {
    case 1:
      ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_REFER;
      FALLTHROUGH;
    case 2:
      ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_TRUNCATE;
      FALLTHROUGH;
    case 3:
# ifdef LANDLOCK_ACCESS_NET_BIND_TCP
      ruleset_attr.handled_access_net = 0;
# endif
      FALLTHROUGH;
    case 4:
      ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_IOCTL_DEV;
      FALLTHROUGH;
    case 5:
# ifdef LANDLOCK_SCOPE_SIGNAL
      ruleset_attr.scoped = 0;
# endif
      FALLTHROUGH;
    case 6:
    case 7:
    case 8:
      ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_RESOLVE_UNIX;
      FALLTHROUGH;
    case 9:
# ifdef LANDLOCK_ACCESS_NET_BIND_TCP
      ruleset_attr.handled_access_net
        &= ~(LANDLOCK_ACCESS_NET_BIND_UDP
             | LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP);
# endif
      FALLTHROUGH;
    default:
      break;
    }

  int const ruleset_fd
    = fd_safer (landlock_create_ruleset (&ruleset_attr,
                                         sizeof ruleset_attr, 0));
  if (ruleset_fd < 0)
    goto err;

  permit_translations (ruleset_fd, ruleset_attr.handled_access_fs);

  if (prctl (PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0
      || landlock_restrict_self (ruleset_fd, 0) < 0)
    goto err;

  close (ruleset_fd);

#elif HAVE_SYS_CAPSICUM_H
# error FIXME
#elif HAVE_DECL_PLEDGE

  /* Use unveil first, so that it cannot be called again after
     pledge is used without unveil in the promises string.  */
  permit_translations (0, 0);

  if (pledge ("stdio rpath", NULL) < 0)
    goto err;

#endif

  return;
 err:
  error (EXIT_FAILURE, errno, _("failed to initialize sandbox"));
}
