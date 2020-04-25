
epan_h_cdef = """


typedef struct epan_dissect epan_dissect_t;

struct epan_dfilter;
struct epan_column_info;

/*
 * Opaque structure provided when an epan_t is created; it contains
 * information needed to allow the user of libwireshark to provide
 * time stamps, comments, and other information outside the packet
 * data itself.
 */
struct packet_provider_data;

/*
 * Structure containing pointers to functions supplied by the user
 * of libwireshark.
 */
struct packet_provider_funcs {
	const nstime_t *(*get_frame_ts)(struct packet_provider_data *prov, guint32 frame_num);
	const char *(*get_interface_name)(struct packet_provider_data *prov, guint32 interface_id);
	const char *(*get_interface_description)(struct packet_provider_data *prov, guint32 interface_id);
	const char *(*get_user_comment)(struct packet_provider_data *prov, const frame_data *fd);
};

// FIXME : perhaps not required extern plugins_t *libwireshark_plugins;

/**
	@mainpage Wireshark EPAN the packet analyzing engine. Source code can be found in the epan directory

	@section Introduction

	XXX

	@b Sections:
*/
/*
Ref 1
Epan
Ethereal Packet ANalyzer (XXX - is this correct?) the packet analyzing engine. Source code can be found in the epan directory.

Protocol-Tree - Keep data of the capture file protocol information.

Dissectors - The various protocol dissectors in epan/dissectors.

Plugins - Some of the protocol dissectors are implemented as plugins. Source code can be found at plugins.

Display-Filters - the display filter engine at epan/dfilter



Ref2 for further edits - delete when done
	\section Introduction

	This document describes the data structures and the functions exported by the CACE Technologies AirPcap library.
	The AirPcap library provides low-level access to the AirPcap driver including advanced capabilities such as channel setting,
	link type control and WEP configuration.<br>
	This manual includes the following sections:

	\note throughout this documentation, \e device refers to a physical USB AirPcap device, while \e adapter is an open API
	instance. Most of the AirPcap API operations are adapter-specific but some of them, like setting the channel, are
	per-device and will be reflected on all the open adapters. These functions will have "Device" in their name, e.g.
	AirpcapSetDeviceChannel().

	\b Sections:

	- \ref airpcapfuncs
	- \ref airpcapdefs
	- \ref radiotap
*/

/**
 * Init the whole epan module.
 *
 * Must be called only once in a program.
 *
 * Returns TRUE on success, FALSE on failure.
 */
extern
gboolean epan_init(register_cb cb, void *client_data, gboolean epan_load_plugins);

/**
 * Load all settings, from the current profile, that affect epan.
 */
extern
e_prefs *epan_load_settings(void);

/** cleanup the whole epan module, this is used to be called only once in a program */
extern
void epan_cleanup(void);

typedef struct {
	void (*init)(void);
	void (*dissect_init)(epan_dissect_t *);
	void (*dissect_cleanup)(epan_dissect_t *);
	void (*cleanup)(void);
	void (*register_all_protocols)(register_cb, gpointer);
	void (*register_all_handoffs)(register_cb, gpointer);
        void (*register_all_tap_listeners)(void);
} epan_plugin;

extern void epan_register_plugin(const epan_plugin *plugin);
/**
 * Initialize the table of conversations.  Conversations are identified by
 * their endpoints; they are used for protocols such as IP, TCP, and UDP,
 * where packets contain endpoint information but don't contain a single
 * value indicating to which flow the packet belongs.
 */
/* FIXME: Not exported
void epan_conversation_init(void);
*/

/** A client will create one epan_t for an entire dissection session.
 * A single epan_t will be used to analyze the entire sequence of packets,
 * sequentially, in a single session. A session corresponds to a single
 * packet trace file. The reasons epan_t exists is that some packets in
 * some protocols cannot be decoded without knowledge of previous packets.
 * This inter-packet "state" is stored in the epan_t.
 */
typedef struct epan_session epan_t;

extern epan_t *epan_new(struct packet_provider_data *prov,
    const struct packet_provider_funcs *funcs);

extern const char *epan_get_user_comment(const epan_t *session, const frame_data *fd);

extern const char *epan_get_interface_name(const epan_t *session, guint32 interface_id);

extern const char *epan_get_interface_description(const epan_t *session, guint32 interface_id);

// FIXME : Not exported const nstime_t *epan_get_frame_ts(const epan_t *session, guint32 frame_num);

extern void epan_free(epan_t *session);

extern const gchar*
epan_get_version(void);

extern void epan_get_version_number(int *major, int *minor, int *micro);

/**
 * Set/unset the tree to always be visible when epan_dissect_init() is called.
 * This state change sticks until cleared, rather than being done per function call.
 * This is currently used when Lua scripts request all fields be generated.
 * By default it only becomes visible if epan_dissect_init() makes it so, usually
 * only when a packet is selected.
 * Setting this overrides that so it's always visible, although it will still not be
 * created if create_proto_tree is false in the call to epan_dissect_init().
 * Clearing this reverts the decision to epan_dissect_init() and proto_tree_visible.
 */
/* FIXME : Not required
void epan_set_always_visible(gboolean force);
*/

/** initialize an existing single packet dissection */
extern
void
epan_dissect_init(epan_dissect_t *edt, epan_t *session, const gboolean create_proto_tree, const gboolean proto_tree_visible);

/** get a new single packet dissection
 * should be freed using epan_dissect_free() after packet dissection completed
 */
extern
epan_dissect_t*
epan_dissect_new(epan_t *session, const gboolean create_proto_tree, const gboolean proto_tree_visible);

extern
void
epan_dissect_reset(epan_dissect_t *edt);

/** Indicate whether we should fake protocols or not */
extern
void
epan_dissect_fake_protocols(epan_dissect_t *edt, const gboolean fake_protocols);

/** run a single packet dissection */
extern
void
epan_dissect_run(epan_dissect_t *edt, int file_type_subtype,
        wtap_rec *rec, tvbuff_t *tvb, frame_data *fd,
        struct epan_column_info *cinfo);

extern
void
epan_dissect_run_with_taps(epan_dissect_t *edt, int file_type_subtype,
        wtap_rec *rec, tvbuff_t *tvb, frame_data *fd,
        struct epan_column_info *cinfo);

/** run a single file packet dissection */
extern
void
epan_dissect_file_run(epan_dissect_t *edt, wtap_rec *rec,
        tvbuff_t *tvb, frame_data *fd, struct epan_column_info *cinfo);

extern
void
epan_dissect_file_run_with_taps(epan_dissect_t *edt, wtap_rec *rec,
        tvbuff_t *tvb, frame_data *fd, struct epan_column_info *cinfo);

/** Prime an epan_dissect_t's proto_tree using the fields/protocols used in a dfilter. */
extern
void
epan_dissect_prime_with_dfilter(epan_dissect_t *edt, const struct epan_dfilter *dfcode);

/** Prime an epan_dissect_t's proto_tree with a field/protocol specified by its hfid */
extern
void
epan_dissect_prime_with_hfid(epan_dissect_t *edt, int hfid);

/** Prime an epan_dissect_t's proto_tree with a set of fields/protocols specified by their hfids in a GArray */
extern
void
epan_dissect_prime_with_hfid_array(epan_dissect_t *edt, GArray *hfids);

/** fill the dissect run output into the packet list columns */
extern
void
epan_dissect_fill_in_columns(epan_dissect_t *edt, const gboolean fill_col_exprs, const gboolean fill_fd_colums);

/** Check whether a dissected packet contains a given named field */
extern
gboolean
epan_dissect_packet_contains_field(epan_dissect_t* edt,
                                   const char *field_name);

/** releases resources attached to the packet dissection. DOES NOT free the actual pointer */
extern
void
epan_dissect_cleanup(epan_dissect_t* edt);

/** free a single packet dissection */
extern
void
epan_dissect_free(epan_dissect_t* edt);

/** Sets custom column */
/* FIXME : Not required
const gchar *
epan_custom_set(epan_dissect_t *edt, GSList *ids, gint occurrence,
				gchar *result, gchar *expr, const int size);
*/

/**
 * Get compile-time information for libraries used by libwireshark.
 */
extern
void
epan_get_compiled_version_info(GString *str);

/**
 * Get runtime information for libraries used by libwireshark.
 */
extern
void
epan_get_runtime_version_info(GString *str);

"""
