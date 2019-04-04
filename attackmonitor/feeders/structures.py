from collections import namedtuple
from stone_engine.log_event import LogEvent
from pyshark.packet.packet import Packet

TYPE_LOG_EVENT = 'log_event'
TYPE_FS_CHANGE = "fs_change"
TYPE_NETWORK_PACKET = 'network_packet'
mq = namedtuple('mq', 'data type source datetime_with_timezone key extra_data')
mq_debug = namedtuple('mq_debug', 'mq supported')
fs_change_event = namedtuple('fs_change_event', 'event_type object_type new_path old_path filesize')
process_info = namedtuple('process_info', 'start_nice_date end_nice_date pid image commandline currentdirectory user logonid sessionid integritylevel ppid')
process_anchor = namedtuple('process_anchor', 'start_nice_date pid')
user_info = namedtuple('user_info', 'domain user')
alert = namedtuple('alert', 'enhanced_data title body')


def generate_mq_key(data, source):

    #LogEvent
    if isinstance(data, LogEvent):
        return "log_event_{}_{}".format(source, data.get_raw_field_event_id())
    elif isinstance(data, fs_change_event):
        return "fs_change_global"
    elif isinstance(data, Packet):
        return "packet"
    else:
        raise AssertionError

def none_to_str(val):
    if val is None:
        return "None"
    else:
        return val


def merge_fields_alert(al):
    return merge_fields_mq(al.enhanced_data)

def merge_fields_mq(mqvar):
    all_fields = dict()

    extra_data = mqvar.extra_data

    # LOG EVENT SPECIFIC
    if mqvar.type == TYPE_LOG_EVENT:
        er = mqvar.data

        (success, er_raw_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)

        if success:
            all_fields['source'] = mqvar.source
            all_fields['eid'] = str(er.get_raw_field_event_id())
            all_fields = {**all_fields, **er_raw_fields}
    elif mqvar.type == TYPE_FS_CHANGE:
        fsce = mqvar.data

        all_fields['event_type'] = none_to_str(fsce.event_type)
        all_fields['object_type'] = none_to_str(fsce.object_type)
        all_fields['new_path'] = none_to_str(fsce.new_path)
        all_fields['old_path'] = none_to_str(fsce.old_path)
        all_fields['filesize'] = none_to_str(fsce.filesize)

    elif mqvar.type == TYPE_NETWORK_PACKET:
        packet = mqvar.data
        all_fields['highest_layer'] = packet.highest_layer

        for field_key, field_container in packet[packet.highest_layer]._all_fields.items():
            val = field_container.showname
            if not val is None:
                all_fields[field_key] = field_container.showname_value

    if type(extra_data) is dict:
        for key in extra_data.keys():
            all_fields[key] = extra_data[key]

    return all_fields

def no_newlines(strvar):
    return strvar.replace("\r", " ").replace("\n", " ")
