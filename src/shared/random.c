/*
 *
 *  Random number generation
 *
 *  based on IPv4 Local Link library with GLib integration,
 *	    Copyright (C) 2009-2010  Aldebaran Robotics. All rights reserved.
 *
 *  Copyright (C) 2018  Commend International. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "shared/random.h"

#define URANDOM "/dev/urandom"

static int random_fd = -1;

int get_random(uint64_t *val)
{
	int r;

	if (random_fd < 0) {
		random_fd = open(URANDOM, O_RDONLY);
		if (random_fd < 0) {
			r = -errno;
			*val = random();

			return r;
		}
	}

	if (read(random_fd, val, sizeof(uint64_t)) < 0) {
		r = -errno;
		*val = random();

		return r;
	}

	return 0;
}

void cleanup_random(void)
{
	if (random_fd < 0)
		return;

	close(random_fd);
	random_fd = -1;
}

/**
 * Return a random delay in range of zero to secs*1000
 */
unsigned int random_delay_ms(unsigned int secs)
{
	uint64_t rand;

	get_random(&rand);
	return rand % (secs * 1000);
}

