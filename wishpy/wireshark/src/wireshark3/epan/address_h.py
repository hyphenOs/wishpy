epan_address_h_types_cdef = """
/* address.h
 * Definitions for structures storing addresses, and for the type of
 * variables holding port-type values
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Types of "global" addresses Wireshark knows about. */
/* Address types can be added here if there are many dissectors that use them or just
 * within a specific dissector.
 * If an address type is added here, it must be "registered" within address_types.c
 * For dissector address types, just use the address_type_dissector_register function
 * from address_types.h
 */
typedef enum {
    AT_NONE,               /* no link-layer address */
    AT_ETHER,              /* MAC (Ethernet, 802.x, FDDI) address */
    AT_IPv4,               /* IPv4 */
    AT_IPv6,               /* IPv6 */
    AT_IPX,                /* IPX */
    AT_FC,                 /* Fibre Channel */
    AT_FCWWN,              /* Fibre Channel WWN */
    AT_STRINGZ,            /* null-terminated string */
    AT_EUI64,              /* IEEE EUI-64 */
    AT_IB,                 /* Infiniband GID/LID */
    AT_AX25,               /* AX.25 */
    AT_VINES,              /* Banyan Vines address */

    AT_END_OF_LIST         /* Must be last in list */
} address_type;

typedef struct _address {
    int           type;         /* type of address */
    int           len;          /* length of address, in bytes */
    const void   *data;         /* pointer to address data */

    /* private */
    void         *priv;
} address;

/* Types of port numbers Wireshark knows about. */
typedef enum {
    PT_NONE,            /* no port number */
    PT_SCTP,            /* SCTP */
    PT_TCP,             /* TCP */
    PT_UDP,             /* UDP */
    PT_DCCP,            /* DCCP */
    PT_IPX,             /* IPX sockets */
    PT_DDP,             /* DDP AppleTalk connection */
    PT_IDP,             /* XNS IDP sockets */
    PT_USB,             /* USB endpoint 0xffff means the host */
    PT_I2C,
    PT_IBQP,            /* Infiniband QP number */
    PT_BLUETOOTH
} port_type;

"""
