wsutil_buffer_h_cdef = """
/* buffer.h
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

typedef struct Buffer {
	guint8	*data;
	gsize	allocated;
	gsize	start;
	gsize	first_free;
} Buffer;


void ws_buffer_init(Buffer* buffer, gsize space);

void ws_buffer_free(Buffer* buffer);

void ws_buffer_assure_space(Buffer* buffer, gsize space);

void ws_buffer_append(Buffer* buffer, guint8 *from, gsize bytes);

void ws_buffer_remove_start(Buffer* buffer, gsize bytes);

void ws_buffer_cleanup(void);

/* FIXME : Following may have to go in set_source? Or may be as simple functions
# define ws_buffer_clean(buffer) ws_buffer_remove_start((buffer), ws_buffer_length(buffer))
# define ws_buffer_increase_length(buffer,bytes) (buffer)->first_free += (bytes)
# define ws_buffer_length(buffer) ((buffer)->first_free - (buffer)->start)
# define ws_buffer_start_ptr(buffer) ((buffer)->data + (buffer)->start)
# define ws_buffer_end_ptr(buffer) ((buffer)->data + (buffer)->first_free)
# define ws_buffer_append_buffer(buffer,src_buffer) ws_buffer_append((buffer), ws_buffer_start_ptr(src_buffer), ws_buffer_length(src_buffer))
*/

/*
#else
 void ws_buffer_clean(Buffer* buffer);
 void ws_buffer_increase_length(Buffer* buffer, unsigned int bytes);
 unsigned gsize ws_buffer_length(Buffer* buffer);
 guint8* ws_buffer_start_ptr(Buffer* buffer);
 guint8* ws_buffer_end_ptr(Buffer* buffer);
 void ws_buffer_append_buffer(Buffer* buffer, Buffer* src_buffer);
*/
"""
