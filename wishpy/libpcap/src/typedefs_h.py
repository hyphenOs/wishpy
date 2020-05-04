libc_typedefs_h_cdef = """

typedef unsigned int u_int;
typedef unsigned short u_short;
typedef unsigned char u_char;

// From sys/time.h -- __kernel_time_t is long
struct timeval {
    long tv_sec;
    long tv_usec;

};

"""
