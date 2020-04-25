

glib_h_cdef = """

// From </usr/lib/x86_64-gnu-linux/gconfig.h>

typedef signed char gint8;
typedef unsigned char guint8;
typedef signed short gint16;
typedef unsigned short guint16;

typedef signed int gint32;
typedef unsigned int guint32;
#define G_HAVE_GINT64 1          /* deprecated, always true */

typedef signed long gint64;
typedef unsigned long guint64;

typedef signed long gssize;
typedef unsigned long gsize;

// From <glib-2.0/glib/gtypes.h>
typedef char   gchar;
typedef short  gshort;
typedef long   glong;
typedef int    gint;
typedef gint   gboolean;

typedef unsigned char   guchar;
typedef unsigned short  gushort;
typedef unsigned long   gulong;
typedef unsigned int    guint;

typedef float   gfloat;
typedef double  gdouble;

/* Define min and max constants for the fixed size numerical types
// Following are not allowed - Let's see how to fix this later

#define G_MININT8	((gint8) -0x80)
#define G_MAXINT8	((gint8)  0x7f)
#define G_MAXUINT8	((guint8) 0xff)

#define G_MININT16	((gint16) -0x8000)
#define G_MAXINT16	((gint16)  0x7fff)
#define G_MAXUINT16	((guint16) 0xffff)

#define G_MININT32	((gint32) -0x80000000)
#define G_MAXINT32	((gint32)  0x7fffffff)
#define G_MAXUINT32	((guint32) 0xffffffff)

#define G_MININT64	((gint64) G_GINT64_CONSTANT(-0x8000000000000000))
#define G_MAXINT64	G_GINT64_CONSTANT(0x7fffffffffffffff)
#define G_MAXUINT64	G_GUINT64_CONSTANT(0xffffffffffffffff)
*/
typedef void* gpointer;
typedef const void *gconstpointer;

// from <glib-2.0/glib/gslist.h>

typedef struct _GSList GSList;

struct _GSList
{
    gpointer data;
    GSList *next;
};

// from <glib-2.0/glib/gregex.h>
typedef struct _GRegex		GRegex;

typedef gint            (*GCompareFunc)         (gconstpointer  a,
                                                 gconstpointer  b);
typedef gint            (*GCompareDataFunc)     (gconstpointer  a,
                                                 gconstpointer  b,
						 gpointer       user_data);
typedef gboolean        (*GEqualFunc)           (gconstpointer  a,
                                                 gconstpointer  b);
typedef void            (*GDestroyNotify)       (gpointer       data);
typedef void            (*GFunc)                (gpointer       data,
                                                 gpointer       user_data);
typedef guint           (*GHashFunc)            (gconstpointer  key);
typedef void            (*GHFunc)               (gpointer       key,
                                                 gpointer       value,
                                                 gpointer       user_data);

"""
