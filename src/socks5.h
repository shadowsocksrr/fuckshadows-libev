/*
 * socks5.h - Define SOCKS5's header
 *
 * Copyright (C) 2013, clowwindy <clowwindy42@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
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

#ifndef _SOCKS5_H
#define _SOCKS5_H

#define SOCKS_VER5 0x05
#define SOCKS_RSV 0x00

#define REP_SUCCEED 0x00

#define CMD_CONNECT 0x01
#define CMD_UDP_ASSOCIATE 0x03
#define CMD_NOT_SUPPORTED 0x07

#define ADDR_IPV4 0x01
#define ADDR_DOMAIN 0x03
#define ADDR_IPV6 0x04

struct method_select_request {
    char ver;
    char nmethods;
    char methods[255];
} __attribute__((packed, aligned(1)));

struct method_select_response {
    char ver;
    char method;
} __attribute__((packed, aligned(1)));

struct socks5_request {
    char ver;
    char cmd;
    char rsv;
    char atyp;
} __attribute__((packed, aligned(1)));

struct socks5_response {
    char ver;
    char rep;
    char rsv;
    char atyp;
} __attribute__((packed, aligned(1)));

#endif // _SOCKS5_H
