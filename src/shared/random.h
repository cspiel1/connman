/*
 *
 *  Random number generation library
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
 */

#ifndef SHARED_RANDOM_H
#define SHARED_RANDOM_H

#include <stdint.h>

int get_random(uint64_t *val);
void cleanup_random(void);
unsigned int random_delay_ms(unsigned int secs);

#endif
