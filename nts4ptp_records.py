#! /usr/bin/python3

from ntske_record import *

# definition of AssociationMode
class AssociationMode(object):
    TYPE_LEN = 2
    DOMAIN_NUMBER_LEN = 1
    SDO_LEN = 2
    SUBGROUP_LEN = 2

    def __init__(self):
        self.debug = 0

    def unpackType(self, mode_bytes):
        if self.debug:
            print(mode_bytes[:self.TYPE_LEN])

        type = int.from_bytes(mode_bytes[:self.TYPE_LEN], byteorder='big', signed='False')
        if self.debug:
            print("type: " + str(type))

        return type


    def unpackGroup(self, mode_bytes):
        # confirm the mode passed is 2 bytes for type + 5 bytes for group
        if len(mode_bytes) != self.TYPE_LEN + self.DOMAIN_NUMBER_LEN + self.SDO_LEN + self.SUBGROUP_LEN:
            return

        # group starts at offset 2 of the association mode record body
        offset = self.TYPE_LEN

        if self.debug:
            print(mode_bytes[offset:])

        domain_number = int.from_bytes(mode_bytes[offset : offset + self.DOMAIN_NUMBER_LEN], byteorder='big', signed='False')
        offset += self.DOMAIN_NUMBER_LEN

        sdo_id = int.from_bytes(mode_bytes[offset : offset + self.SDO_LEN], byteorder='big', signed='False') & 0x0FFF
        offset += self.SDO_LEN

        sub_group = int.from_bytes(mode_bytes[offset:], byteorder='big', signed='False')

        if self.debug:
            print("domain_number: " + str(domain_number))
            print("sdo_id: " + str(sdo_id))
            print("sub_group: " + str(sub_group))

        return domain_number, sdo_id, sub_group

    def unpack(self, mode_bytes):
        type = self.unpackType(mode_bytes)
        if type != 0:
            print("Unsupported Mode Type: " + str(type))
            return

        group = self.unpackGroup(mode_bytes)
        return type, group

    def packType(self, type):
        if self.debug:
            print("type: " + str(type))

        type_bytes = type.to_bytes(self.TYPE_LEN, byteorder='big', signed='False')
        if self.debug:
            print(type_bytes)

        return type_bytes

    def packGroup(self, group):
        domain_number, sdo_id, sub_group = group
        # sdo_id is only a 12bit field, make sure nothing is left in padded area
        sdo_id = sdo_id & 0x0FFF

        if self.debug:
            print("domain_number: " + str(domain_number))
            print("sdo_id: " + str(sdo_id))
            print("sub_group: " + str(sub_group))

        domain_number_bytes = domain_number.to_bytes(self.DOMAIN_NUMBER_LEN, byteorder='big', signed='False')
        sdo_id_bytes = sdo_id.to_bytes(self.SDO_LEN, byteorder='big', signed='False')
        sub_group_bytes = sub_group.to_bytes(self.SUBGROUP_LEN, byteorder='big', signed='False')

        group_bytes = domain_number_bytes + sdo_id_bytes + sub_group_bytes
        if self.debug:
            print(group_bytes)

        return group_bytes

    def pack(self, type, group):
        type_bytes = self.packType(type)
        value_bytes = self.packGroup(group)

        mode_bytes = type_bytes + value_bytes
        if self.debug:
            print(mode_bytes)

        return mode_bytes

class Parameters(object):

    def __init__(self):
        self.debug = 0

    def unpack(self, parameters_bytes):
        offset = 0

        security_associations = []
        validity_periods = []

        while offset < len(parameters_bytes):
            body_len = struct.unpack(">H", parameters_bytes[offset + 2: offset + 4])[0]
            bytes = parameters_bytes[offset : offset + 4 + body_len]
            offset += 4 + body_len
            record = Record(bytes)

            if record.rec_type == RT_ASSOCIATION_MODE:
                security_associations.append(SecurityAssociation().unpack(record.body))
            elif record.rec_type == RT_VALIDITY_PERIOD:
                if len(validity_periods) != 0:
                    print("more than one validity period received")
                validity_periods.append(ValidityPeriod().unpack(record.body))
            else:
                print("Unrecognized record")

        return security_associations, validity_periods[0]

    def pack(self, security_associations, validity_period):
        
        records = []

        for association in security_associations:
            security_association = SecurityAssociation().pack(association)
            records.append(Record.make(False, RT_ASSOCIATION_MODE, security_association))

        validity_period = ValidityPeriod().pack(validity_period)
        records.append(Record.make(False, RT_VALIDITY_PERIOD, validity_period))

        return b''.join(map(bytes, records))

class SecurityAssociation(object):
    SPP_LEN = 1
    IAT_LEN = 2
    KEYID_LEN = 4
    KEYLEN_LEN = 2

    def __init__(self):
        self.debug = 0

    def unpack(self, association_bytes):
        offset = 0

        if self.debug:
            print(association_bytes)

        spp = int.from_bytes(association_bytes[offset : offset + self.SPP_LEN], byteorder='big', signed='False')
        offset += self.SPP_LEN

        iat = int.from_bytes(association_bytes[offset : offset + self.IAT_LEN], byteorder='big', signed='False')
        offset += self.IAT_LEN

        key_id = int.from_bytes(association_bytes[offset : offset + self.KEYID_LEN], byteorder='big', signed='False')
        offset += self.KEYID_LEN

        key_len = int.from_bytes(association_bytes[offset : offset + self.KEYLEN_LEN], byteorder='big', signed='False')
        offset += self.KEYLEN_LEN

        key = association_bytes[offset:]

        if self.debug:
            print("spp: " + str(spp))
            print("iat: " + str(iat))
            print("key_id: " + str(key_id))
            print("key_len: " + str(key_len))
            print("key: " + str(key))

        return spp, iat, key_id, key_len, key

    def pack(self, security_association):

        spp, iat, key_id, key_len, key = security_association
        if self.debug:
            print("spp: " + str(spp))
            print("iat: " + str(iat))
            print("key_id: " + str(key_id))
            print("key_len: " + str(key_len))
            print("key: " + str(key))

        spp_bytes = spp.to_bytes(self.SPP_LEN, byteorder='big', signed='False')
        iat_bytes = iat.to_bytes(self.IAT_LEN, byteorder='big', signed='False')
        key_id_bytes = key_id.to_bytes(self.KEYID_LEN, byteorder='big', signed='False')
        key_len_bytes = key_len.to_bytes(self.KEYLEN_LEN, byteorder='big', signed='False')
        key_bytes = key

        association_bytes = spp_bytes + iat_bytes + key_id_bytes + key_len_bytes + key_bytes

        if self.debug:
            print(association_bytes)

        return association_bytes

class ValidityPeriod(object):
    LIFETIME_LEN = 4
    UPDATE_LEN = 4
    GRACE_LEN = 4

    def __init__(self):
        self.debug = 0

    def unpack(self, period_bytes):
        offset = 0

        if self.debug:
            print(period_bytes)

        lifetime = int.from_bytes(period_bytes[offset : offset + self.LIFETIME_LEN], byteorder='big', signed='False')
        offset += self.LIFETIME_LEN

        update = int.from_bytes(period_bytes[offset : offset + self.UPDATE_LEN], byteorder='big', signed='False')
        offset += self.UPDATE_LEN

        grace = int.from_bytes(period_bytes[offset:], byteorder='big', signed='False')

        if self.debug:
            print("lifetime: " + str(lifetime))
            print("update period: " + str(update))
            print("grace period: " + str(grace))

        return lifetime, update, grace

    def pack(self, validity_period):
        lifetime, update, grace = validity_period
        
        if self.debug:
            print("lifetime: " + str(lifetime))
            print("update period: " + str(update))
            print("grace period: " + str(grace))

        lifetime_bytes = lifetime.to_bytes(self.LIFETIME_LEN, byteorder='big', signed='False')
        update_bytes = update.to_bytes(self.UPDATE_LEN, byteorder='big', signed='False')
        grace_bytes = grace.to_bytes(self.GRACE_LEN, byteorder='big', signed='False')

        period_bytes = lifetime_bytes + update_bytes + grace_bytes

        if self.debug:
            print(period_bytes)

        return period_bytes