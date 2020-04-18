wsutil_plugins_h_cdef = """

/* plugins.h
 * definitions for plugins structures
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

typedef void plugins_t;

typedef enum {
    WS_PLUGIN_EPAN,
    WS_PLUGIN_WIRETAP,
    WS_PLUGIN_CODEC
} plugin_type_e;

extern plugins_t *plugins_init(plugin_type_e type);

typedef void (*plugin_description_callback)(const char *name, const char *version,
                                            const char *types, const char *filename,
                                            void *user_data);

extern void plugins_get_descriptions(plugin_description_callback callback, void *user_data);

extern void plugins_dump_all(void);

extern int plugins_get_count(void);

extern void plugins_cleanup(plugins_t *plugins);

"""
