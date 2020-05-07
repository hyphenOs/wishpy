"""
Capture Capture API using the libpcap.

"""



class WishpyCapturer:
    """ ase WishpyCapturer class.

        Following API are provided  `open`, `close`, `start`, `stop`.
    """

    def open(self):
        """open: Opens the capturer.

            Use this to perform any Capturer specific initialization. For
            instance, our API deals with Packet Capture Pipelines that can
            be connected using Python Queues. So Setting up Queues etc. can
            be performed here in this method.
        """
        raise NotImplementedError

    def start(self, **kw):
        """start: Start actual capture of packets.

           Implement in such a way tha it should be possible to start/stop
           capture multiple times for an instance of the capturer.
        """
        raise NotImplementedError

    def stop(self, **kw):
        """stop: Stop actual capture of packets.

            Implement in such a way that it should be possible to start/stop
            capture multiple times for an instance of the capturer.
        """
        raise NotImplementedError

    def close(self):
        """close: Perform any resource cleanup related to the capturer.
        """
        pass

class LibpcapCapturer(WishpyCapturer):
    """'libpcap' based packet capturer for an interface on the system.

        This capturer captures packet from the OS interface and posts them,
        on the Queue. Right now it is not completely abstracted out what gets
        posted on the queue. Assume they are tuples like - (header, data)
    """

    def __init__(self, iface, queue, snaplen=0, promisc=True, timeout=10):
        """Constructor

            Args:
                iface:   string - An Interface Name on the local OS.
                queue:   Python Queue like objects that supported Get/Put APIs
                         in a thread/process safe manner. (eg. Queue,
                         multiprocessing Queue etc.)
                snaplen: integer (optional), should be non-zero, if provided,
                         maximum capture data for packet will be capped to this
                         value. Default - Don't set Capture length (ie. if
                         input value is 0.)
                promisc: Boolean (optional). Default True To determine whether
                         to start capturing in 'promiscuous' mode.
                timeout: integer - Timeout in miliseconds to wait before next
                         'batch' of captured packets is returned (maps
                         directly to `libpcap: packet buffer timeout`.)
                         Default value is 10ms. Use lower values for more
                         'responsive' capture, higher values for larger
                         batches.
        """

        self.__iface = iface
        self.__queue = queue
        self.__snaplen = snaplen
        self.__promisc = promisc
        self.__timeout = timeout

    # Property Classes: All are read-only there is little value in making
    # these, read-write. For now at-least
    @property
    def iface(self):
        return self.__iface

    @property
    def queue(self):
        return self.__queue

    @property
    def snaplen(self):
        return self.__snaplen

    @property
    def promisc(self):
        return self.__promisc

    @property
    def timeout(self):
        return self.__timeout

    def start(self):
        pass

    def stop(self):
        pass

    def open(self):
        pass

    def close(self):
        pass

    def __repr__(self):
        return "LibpcapCapturer iface:{}, snaplen:{}, promisc:{}, timeout:{}".\
                format(self.__iface, self.__snaplen,
                        self.__promisc, self.__timeout)

if __name__ == '__main__':
    from queue import Queue
    c = LibpcapCapturer('eth0', Queue())
    print(c)
