import struct

# supported record types 
RT_END_OF_MESSAGE = 0
RT_NEXT_PROTO_NEG = 1
RT_ERROR = 2
RT_WARNING = 3
RT_AEAD_NEG = 4
RT_NEW_COOKIE = 5
RT_NTPV4_SERVER = 6
RT_NTPV4_PORT = 7
RT_ASSOCIATION_MODE = 1024
RT_CURRENT_PARAMETERS = 1025
RT_HEARTBEAT_TIMEOUT = 1026
RT_NEXT_PARAMETERS = 1027
RT_NTS_MESSAGE_TYPE = 1028
RT_PTP_TIME_SERVER = 1029
RT_SECURITY_ASSOCIATION = 1030
RT_SOURCE_PORT_ID = 1031
RT_STATUS = 1032
RT_SUPPORTED_MAC_ALGOS = 1033
RT_TICKET = 1034
RT_TICKET_KEY = 1035
RT_TICKET_KEY_ID = 1036
RT_VALIDITY_PERIOD = 1037

ERR_UNREC_CRIT = 0
ERR_BAD_REQUEST = 1

class Record:
    def __init__(self, rec=None):
        if rec is None:
            self.critical = False
            self.rec_type = 0
            self.body = b''
            return
        if len(rec) < 4:
            raise ValueError("Record too short to be valid")
        (crit_type, body_len) = struct.unpack(">HH", rec[0:4])
        if len(rec) < body_len + 4:
            raise ValueError("Record shorter than indicated length")
        self.critical = crit_type >> 15 == 1
        self.rec_type = crit_type & 0x7fff
        self.body = rec[4:body_len+4]

    # retrieve length of a record
    def __len__(self):
        return len(self.body)+4

    # retrieve the byte field of a record
    def __bytes__(self):
        crit_type = self.rec_type
        if self.critical:
            crit_type |= 0x8000
        return struct.pack(">HH", crit_type, len(self.body)) + self.body

    # allocate a new record
    @classmethod
    def make(cls, critical, rec_type, body = b''):
        rec = Record()
        rec.critical = critical
        rec.rec_type = rec_type
        rec.body = body
        return rec
