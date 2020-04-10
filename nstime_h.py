
nstime_h_cdef = """

// stuff from C standard library without having to do lot of including
typedef long int time_t; // Taken from /usr/include/x86_64

// From <wsutil/nstime.h>

typedef struct {
	time_t	secs;
	int	nsecs;
} nstime_t;



"""
