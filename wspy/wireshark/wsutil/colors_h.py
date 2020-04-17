wsutil_colors_h_cdef = """

/* color.h
 * Definitions for colors
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Data structure holding RGB value for a color, 16 bits per channel.
 */
typedef struct {
    guint16 red;
    guint16 green;
    guint16 blue;
} color_t;

/* FIXME: May be move it to set_source?
 * Convert a color_t to a 24-bit RGB value, reducing each channel to
 * 8 bits and combining them.
inline static unsigned int
color_t_to_rgb(const color_t *color) {
    return (((color->red >> 8) << 16)
          | ((color->green >> 8) << 8)
          | (color->blue >> 8));
}
*/

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */

"""
