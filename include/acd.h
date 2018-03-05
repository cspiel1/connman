/*
 *
 *  Address Conflict Detection (RFC 5227)
 *
 *  based on DHCP client library with GLib integration,
 *      Copyright (C) 2009-2014  Intel Corporation. All rights reserved.
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

#ifndef __CONNMAN_ACD_H
#define __CONNMAN_ACD_H

#include <stdint.h>
#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

struct _ACDHost;

typedef struct _ACDHost ACDHost;

ACDHost *acdhost_new(int ifindex);
int acdhost_start(ACDHost *acd, uint32_t ip);

typedef void (*ACDHostEventFunc) (ACDHost *acd, gpointer user_data);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_ACD_H */
