/* vi: set expandtab sw=4 sts=4: */
/* opkg_usign.c - the opkg package management system

    Copyright (C) 2019 Tobias Koch

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; either version 2, or (at
    your option) any later version.

    This program is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.
*/

#include "config.h"

#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>

#include "opkg_conf.h"
#include "opkg_message.h"
#include "opkg_usign.h"

int opkg_verify_usign_signature(const char *file, const char *sigfile)
{
    int status = -1;
    int pid;

    pid = fork();

    if(pid < 0) {
        opkg_perror(ERROR, "Failed to fork usign process");
        return -1;
    }

    if(!pid) {
        execl("/usr/bin/usign", "usign", "-q", "-V",
              "-P", "/etc/opkg/usign/trustdb", "-m", file, "-x", sigfile,
              NULL);
        exit(255);
    }

    waitpid(pid, &status, 0);
    if(!WIFEXITED(status) || WEXITSTATUS(status))
        return -1;

    return 0;
}
