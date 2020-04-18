glib_gstring_h_types_cdef = """

typedef struct _GString         GString;

struct _GString
{
  gchar  *str;
  gsize len;
  gsize allocated_len;
};

"""
