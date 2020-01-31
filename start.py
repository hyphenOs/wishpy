from cffi import FFI


iface = FFI()


### Stuff that we want in our library or basically this is our API
cdef = iface.cdef('''

/** First All types definitions that are required by our API */
/* Type Definitions Begin */

// stuff from C standard library without having to do lot of including
typedef long int time_t; // Taken from /usr/include/x86_64


// From <epan/epan.h>
typedef struct epan_session epan_t;


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


// from <epan/register.h>

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

// #define RA_BASE_COUNT (RA_INTERFACES - 3) // RA_EXTCAP, RA_LUA_PLUGINS, RA_LUA_DEREGISTER

typedef void (*register_cb)(register_action_e action, const char *message, gpointer client_data);

// From <wsutil/nstime.h>

typedef struct {
	time_t	secs;
	int	nsecs;
} nstime_t;

// From <epan/frame_data.h>

typedef struct _frame_data {
  GSList      *pfd;          /**< Per frame proto data */
  guint32      num;          /**< Frame number */
  guint32      pkt_len;      /**< Packet length */
  guint32      cap_len;      /**< Amount actually captured */
  guint32      cum_bytes;    /**< Cumulative bytes into the capture */
  gint64       file_off;     /**< File offset */
  guint16      subnum;       /**< subframe number, for protocols that require this */
  gint16       tsprec;       /**< Time stamp precision */
  struct {
    unsigned int passed_dfilter : 1; /**< 1 = display, 0 = no display */
    unsigned int dependent_of_displayed : 1; /**< 1 if a displayed frame depends on this frame */
    /* Do NOT use packet_char_enc enum here: MSVC compiler does not handle an enum in a bit field properly */
    unsigned int encoding       : 1; /**< Character encoding (ASCII, EBCDIC...) */
    unsigned int visited        : 1; /**< Has this packet been visited yet? 1=Yes,0=No*/
    unsigned int marked         : 1; /**< 1 = marked by user, 0 = normal */
    unsigned int ref_time       : 1; /**< 1 = marked as a reference time frame, 0 = normal */
    unsigned int ignored        : 1; /**< 1 = ignore this frame, 0 = normal */
    unsigned int has_ts         : 1; /**< 1 = has time stamp, 0 = no time stamp */
    unsigned int has_phdr_comment : 1; /** 1 = there's comment for this packet */
    unsigned int has_user_comment : 1; /** 1 = user set (also deleted) comment for this packet */
    unsigned int need_colorize  : 1; /**< 1 = need to (re-)calculate packet color */
  } flags;

  const struct _color_filter *color_filter;  /**< Per-packet matching color_filter_t object */

  nstime_t     abs_ts;       /**< Absolute timestamp */
  nstime_t     shift_offset; /**< How much the abs_tm of the frame is shifted */
  guint32      frame_ref_num; /**< Previous reference frame (0 if this is one) */
  guint32      prev_dis_num; /**< Previous displayed frame (0 if first one) */
} frame_data;

/* Type Definitions End */

    epan_t *epan_new(struct packet_provider_data *prov, const struct packet_provider_funcs *funcs);

    const char *epan_get_user_comment(const epan_t *session, const frame_data *fd);

    const char *epan_get_interface_name(const epan_t *session, guint32 interface_id);

    const char *epan_get_interface_description(const epan_t *session, guint32 interface_id);

    void epan_free(epan_t *session);

    const gchar* epan_get_version(void);

    void epan_get_version_number(int *major, int *minor, int *micro);

    gboolean epan_init(void (*register_all_protocols_func)(register_cb cb, gpointer client_data),
	           void (*register_all_handoffs_func)(register_cb cb, gpointer client_data),
	           register_cb cb, void *client_data);
        ''')

lib = iface.verify('''
        #include <wireshark/epan/epan.h>

        ''',
        libraries=['glib-2.0', 'wireshark', 'wsutil'],
        extra_compile_args=['-I/usr/include/wireshark',
            '-I/usr/include/glib-2.0',
            '-I/usr/lib/x86_64-linux-gnu/glib-2.0/include'])


major = iface.new('int *')
minor = iface.new('int *')
micro = iface.new('int *')
lib.epan_get_version_number(major, minor, micro)

print(major[0], minor[0], micro[0])
