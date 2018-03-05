/*
 *
 *  ARP library
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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>

#include <linux/if.h>

#include <arpa/inet.h>

#include "shared/arp.h"

int send_arp_packet(uint8_t* source_eth, uint32_t source_ip,
		    uint32_t target_ip, int ifindex)
{
	struct sockaddr_ll dest;
	struct ether_arp p;
	uint32_t ip_source;
	uint32_t ip_target;
	int fd, n;

	fd = socket(PF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	memset(&dest, 0, sizeof(dest));
	memset(&p, 0, sizeof(p));

	dest.sll_family = AF_PACKET;
	dest.sll_protocol = htons(ETH_P_ARP);
	dest.sll_ifindex = ifindex;
	dest.sll_halen = ETH_ALEN;
	memset(dest.sll_addr, 0xFF, ETH_ALEN);
	if (bind(fd, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
		int err = errno;
		close(fd);
		return -err;
	}

	ip_source = htonl(source_ip);
	ip_target = htonl(target_ip);
	p.arp_hrd = htons(ARPHRD_ETHER);
	p.arp_pro = htons(ETHERTYPE_IP);
	p.arp_hln = ETH_ALEN;
	p.arp_pln = 4;
	p.arp_op = htons(ARPOP_REQUEST);

	memcpy(&p.arp_sha, source_eth, ETH_ALEN);
	memcpy(&p.arp_spa, &ip_source, sizeof(p.arp_spa));
	memcpy(&p.arp_tpa, &ip_target, sizeof(p.arp_tpa));

	n = sendto(fd, &p, sizeof(p), 0,
	       (struct sockaddr*) &dest, sizeof(dest));
	if (n < 0)
		n = -errno;

	close(fd);

	return n;
}

int arp_socket(int ifindex)
{
	int fd;
	struct sockaddr_ll sock;

	fd = socket(PF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return fd;

	memset(&sock, 0, sizeof(sock));

	sock.sll_family = AF_PACKET;
	sock.sll_protocol = htons(ETH_P_ARP);
	sock.sll_ifindex = ifindex;

	if (bind(fd, (struct sockaddr *) &sock, sizeof(sock)) != 0) {
		int err = errno;
		close(fd);
		return -err;
	}

	return fd;
}

void get_interface_mac_address(int index, uint8_t *mac_address)
{
	struct ifreq ifr;
	int sk, err;

	sk = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0) {
		perror("Open socket error");
		return;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = index;

	err = ioctl(sk, SIOCGIFNAME, &ifr);
	if (err < 0) {
		perror("Get interface name error");
		goto done;
	}

	err = ioctl(sk, SIOCGIFHWADDR, &ifr);
	if (err < 0) {
		perror("Get MAC address error");
		goto done;
	}

	memcpy(mac_address, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

done:
	close(sk);
}

