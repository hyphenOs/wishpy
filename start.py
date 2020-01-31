from cffi import FFI


iface = FFI()


### Stuff that we want in our library or basically this is our API
cdef = iface.cdef('''
            void epan_get_version_number(int *major, int *minor, int *micro);

            typedef struct epan_dissect epan_dissect_t;
            //epan_t *epan_new(struct packet_provider_data *prov, const struct packet_provider_funcs *funcs);


// from /usr/include/wireshark/glib-2.0/glib/gtypes.h
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

// from /usr/include/wirepy/epan/register.h

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

            gboolean epan_init(void (*register_all_protocols_func)(register_cb cb, gpointer client_data),
	           void (*register_all_handoffs_func)(register_cb cb, gpointer client_data),
	           register_cb cb, void *client_data);
        ''')

lib = iface.verify('''
        #include <wireshark/epan/epan.h>

        ''',
        libraries=['glib-2.0', 'wireshark'],
        extra_compile_args=['-I/usr/include/wireshark',
            '-I/usr/include/glib-2.0',
            '-I/usr/lib/x86_64-linux-gnu/glib-2.0/include'])


major = iface.new('int *')
minor = iface.new('int *')
micro = iface.new('int *')
lib.epan_get_version_number(major, minor, micro)

print(major[0], minor[0], micro[0])
