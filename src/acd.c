/*
 *  Connection Manager, Address Conflict Detection (ACD) RFC 5227
 *
 *  Copyright (C) 2018  Commend International GmbH. All rights reserved.
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

#include <connman/acd.h>
#include <connman/log.h>
#include <connman/inet.h>
#include <shared/arp.h>
#include <glib.h>

typedef enum _acd_state {
	ACD_PROBE,
	ACD_ANNOUNCE,
	ACD_MONITOR,
	ACD_DEFEND,
} ACDState;

struct _ACDHost {
	int ref_count;
	ACDState state;
	int ifindex;
	char *interface;
	uint8_t mac_address[6];
	uint32_t requested_ip; /* host byte order */

	bool listen_on;
	int listener_sockfd;
	unsigned int retry_times;
	unsigned int conflicts;
	guint timeout;
	guint listener_watch;
};

ACDHost *acdhost_new(int ifindex)
{
	ACDHost *acd;

	if (ifindex < 0) {
		connman_error("Invalid interface index %d", ifindex);
		return NULL;
	}

	acd = g_try_new0(ACDHost, 1);
	if (!acd) {
		connman_error("Could not allocate acd data structure");
		return NULL;
	}

	acd->interface = connman_inet_ifname(ifindex);
	if (!acd->interface) {
		connman_error("Interface with index %d is not available", ifindex);
		goto error;
	}

	if (!connman_inet_is_ifup(ifindex)) {
		connman_error("Interface with index %d and name %s is down", ifindex,
				acd->interface);
		goto error;
	}

	get_interface_mac_address(ifindex, acd->mac_address);

	acd->listener_sockfd = -1;
	acd->listen_on = FALSE;
	acd->ref_count = 1;
	acd->ifindex = ifindex;
	acd->listener_watch = 0;
	acd->retry_times = 0;

	return acd;

error:
	g_free(acd->interface);
	g_free(acd);
	return NULL;
}
