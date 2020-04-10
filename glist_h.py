# Definitions from glib/glist.h

glist_h_cdef = """
typedef struct _GList GList;

struct _GList
{
  gpointer data;
  GList *next;
  GList *prev;
};
"""
