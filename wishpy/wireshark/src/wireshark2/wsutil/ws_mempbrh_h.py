wsutil_ws_mempbrk_h_types_cdef = """

/* FIXME: Later may be
#ifdef HAVE_SSE4_2
#include <emmintrin.h>
#endif
*/

/** The pattern object used for ws_mempbrk_exec().
 */
typedef long long __m128i;

typedef struct {
    gchar patt[256];
/*  FIXME : Later may be
#ifdef HAVE_SSE4_2
#endif
*/
    gboolean use_sse42;
    __m128i mask;
} ws_mempbrk_pattern;


"""


wsutil_ws_mempbrk_h_funcs_cdef = """

/** Compile the pattern for the needles to find using ws_mempbrk_exec().
 */
extern void ws_mempbrk_compile(ws_mempbrk_pattern* pattern, const gchar *needles);

/** Scan for the needles specified by the compiled pattern.
 */
extern const guint8 *ws_mempbrk_exec(const guint8* haystack, size_t haystacklen, const ws_mempbrk_pattern* pattern, guchar *found_needle);

"""
