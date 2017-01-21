/*
 * common.h - Provide global definitions
 *
 * Copyright (C) 2013 - 2016, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef _COMMON_H
#define _COMMON_H

#include "socks5.h"

#define DEFAULT_CONF_PATH "/etc/fuckshadows-libev/config.json"

#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

#if defined(MODULE_TUNNEL) || defined(MODULE_REDIR)
#define MODULE_LOCAL
#endif

int init_udprelay(const char *server_host, const char *server_port,
#ifdef MODULE_LOCAL
                  const struct sockaddr *remote_addr, const int remote_addr_len,
#ifdef MODULE_TUNNEL
                  const ss_addr_t tunnel_addr,
#endif
#endif
                  int mtu, int method, int timeout, const char *iface);

void free_udprelay(void);

#ifdef ANDROID
int protect_socket(int fd);
int send_traffic_stat(uint64_t tx, uint64_t rx);
#endif

#define STAGE_ERROR     -1  /* Error detected                   */
#define STAGE_INIT       0  /* Initial stage                    */
#define STAGE_HANDSHAKE  1  /* Handshake with client            */
#define STAGE_PARSE      2  /* Parse the header                 */
#define STAGE_RESOLVE    4  /* Resolve the hostname             */
#define STAGE_STREAM     5  /* Stream between client and server */

/*
 * for each opening port, we have a TCP Relay
 *
 * for each connection, we have a TCP Relay Handler to handle the connection
 *
 * for each handler, we have 2 sockets:
 *  local:   connected to the client
 *  remote:  connected to remote server
 *
 * for each handler, it could be at one of several stages:
 *
 * as sslocal:
 * stage 0 auth METHOD received from local, reply with selection message
 * stage 1 addr received from local, query DNS for remote
 * stage 2 UDP assoc
 * stage 3 DNS resolved, connect to remote
 * stage 4 still connecting, more data from local received
 * stage 5 remote connected, piping local and remote
 *
 * as ssserver:
 * stage 0 just jump to stage 1
 * stage 1 addr received from local, query DNS for remote
 * stage 3 DNS resolved, connect to remote
 * stage 4 still connecting, more data from local received
 * stage 5 remote connected, piping local and remote
 */

#endif // _COMMON_H
