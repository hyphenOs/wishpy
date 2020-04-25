epan_register_h_types_cdef = """
/* register.h
 * Definitions for protocol registration
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

typedef enum {
    RA_NONE,              /* For initialization */
    RA_DISSECTORS,        /* Initializing dissectors */
    RA_LISTENERS,         /* Tap listeners */
    RA_EXTCAP,            /* extcap register preferences */
    RA_REGISTER,          /* Built-in dissector registration */
    RA_PLUGIN_REGISTER,   /* Plugin dissector registration */
    RA_HANDOFF,           /* Built-in dissector handoff */
    RA_PLUGIN_HANDOFF,    /* Plugin dissector handoff */
    RA_LUA_PLUGINS,       /* Lua plugin register */
    RA_LUA_DEREGISTER,    /* Lua plugin deregister */
    RA_PREFERENCES,       /* Module preferences */
    RA_INTERFACES         /* Local interfaces */
} register_action_e;

#define RA_BASE_COUNT 8 // RA_EXTCAP, RA_LUA_PLUGINS, RA_LUA_DEREGISTER

typedef void (*register_cb)(register_action_e action, const char *message, gpointer client_data);

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */

"""
