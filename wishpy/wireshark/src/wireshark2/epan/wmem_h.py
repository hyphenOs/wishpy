# In Python world we are most likely never going to be allocating memory
# ourselves, so we'll only take the types here and we should be good.
# Will revisit if this if we indeed need to allocate memory ourselves.

epan_wmem_h_types_cdef = """

// From <wireshark/epan/wmem/wmem_list.h>

struct _wmem_list_t;
struct _wmem_list_frame_t;

typedef struct _wmem_list_t       wmem_list_t;
typedef struct _wmem_list_frame_t wmem_list_frame_t;



/* wmem_allocator.h
 * Definitions for the Wireshark Memory Manager Allocator
 * Copyright 2012, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

struct _wmem_user_cb_container_t;

/** An enumeration of the different types of available allocators. */
typedef enum _wmem_allocator_type_t {
    WMEM_ALLOCATOR_SIMPLE, /**< A trivial allocator that mallocs requested
                memory and tracks allocations via a hash table. As simple as
                possible, intended more as a demo than for practical usage. Also
                has the benefit of being friendly to tools like valgrind. */
    WMEM_ALLOCATOR_BLOCK, /**< A block allocator that grabs large chunks of
                memory at a time (8 MB currently) and serves allocations out of
                those chunks. Designed for efficiency, especially in the
                free_all operation. */
    WMEM_ALLOCATOR_STRICT, /**< An allocator that does its best to find invalid
                memory usage via things like canaries and scrubbing freed
                memory. Valgrind is the better choice on platforms that support
                it. */
    WMEM_ALLOCATOR_BLOCK_FAST /**< A block allocator like WMEM_ALLOCATOR_BLOCK
                but even faster by tracking absolutely minimal metadata and
                making 'free' a no-op. Useful only for very short-lived scopes
                where there's no reason to free individual allocations because
                the next free_all is always just around the corner. */
} wmem_allocator_type_t;

/** A public opaque type representing one wmem allocation pool. */
typedef struct _wmem_allocator_t wmem_allocator_t;


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
epan_wmem_h_funcs_cdef = """
extern
void
wmem_free(wmem_allocator_t *allocator, void *ptr);
"""

wmem_allocator_struct = """
/* See section "4. Internal Design" of doc/README.wmem for details
 * on this structure */
struct _wmem_allocator_t {
    /* Consumer functions */
    void *(*walloc)(void *private_data, const size_t size);
    void  (*wfree)(void *private_data, void *ptr);
    void *(*wrealloc)(void *private_data, void *ptr, const size_t size);

    /* Producer/Manager functions */
    void  (*free_all)(void *private_data);
    void  (*gc)(void *private_data);
    void  (*cleanup)(void *private_data);

    /* Callback List */
    struct _wmem_user_cb_container_t *callbacks;

    /* Implementation details */
    void                        *private_data;
    enum _wmem_allocator_type_t  type;
    gboolean                     in_scope;
};
"""
