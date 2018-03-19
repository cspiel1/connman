/*
 *
 *  Connection Manager
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

/*
 *  Address Conflict Detection (RFC 5227)
 *
 *  based on DHCP client library with GLib integration,
 *      Copyright (C) 2009-2014  Intel Corporation. All rights reserved.
 *
 */

#ifndef __CONNMAN_ACD_H
#define __CONNMAN_ACD_H

#include <stdint.h>
#include <glib.h>
#include <gdbus.h>

#ifdef __cplusplus
extern "C" {
#endif

struct acd_host;

struct acd_host *acd_host_new(int ifindex, const char* path);
int acd_host_start(struct acd_host *acd, uint32_t ip);
void acd_host_stop(struct acd_host *acd);

typedef void (*ACDHostEventFunc) (struct acd_host *acd, gpointer user_data);

typedef enum {
	ACDHOST_EVENT_IPV4_AVAILABLE,
	ACDHOST_EVENT_IPV4_LOST,
	ACDHOST_EVENT_IPV4_CONFLICT,
	ACDHOST_EVENT_IPV4_MAXCONFLICT,
} ACDHostEvent;

void acdhost_register_event(struct acd_host *acd,
			    ACDHostEvent event,
			    ACDHostEventFunc func,
			    gpointer user_data);

void acdhost_append_dbus_property(struct acd_host *acd, DBusMessageIter *dict);

unsigned int acdhost_get_conflicts_count(struct acd_host *acd);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_ACD_H */
