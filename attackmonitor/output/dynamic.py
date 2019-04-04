from utils.nicedate import NiceDate
from feeders.structures import *
from stone_engine.log_event import LogEvent

#var = mq or alert
def determine_log_file_name_from_var(var):
    if isinstance(var, mq):
        return var.datetime_with_timezone.strftime("%Y-%m-%d")
    elif isinstance(var, alert):
        return determine_log_file_name_from_var(var.enhanced_data)
    else:
        return "notsupported"
        #raise AssertionError


def alert_to_oneline(al):
    out = ""
    mqvar = al.enhanced_data

    out += "{} ".format(mqvar.datetime_with_timezone.strftime("%H:%M:%S [%Z]"))
    out += "| Source: {} ".format(mqvar.source)
    out += "| Title: {} ".format(al.title)
    out += "| Body: {} ".format(al.body)

    return out


def mq_to_oneline(mqvar):
    out = ""

    out += "{} ".format(mqvar.datetime_with_timezone.strftime("%H:%M:%S [%Z]"))
    out += "| Source: {} ".format(mqvar.source)

    if mqvar.type == TYPE_LOG_EVENT:
        fields = merge_fields_mq(mqvar)
        del fields['source']

        for field_name in fields:
            val = fields[field_name]

            if type(val) is str:
                out += "| {} = {} ".format(field_name, val)
            elif type(val) is list:
                out += "| {} = {} ".format(field_name, ",".join(val))
            else:
                raise AssertionError

    elif mqvar.type == TYPE_FS_CHANGE:
        fsvar = mqvar.data
        out += "| Action: {} ".format(fsvar.event_type)
        out += "| Type: {} ".format(fsvar.object_type)
        out += "| New path: {} ".format(fsvar.new_path)

        if not fsvar.old_path is None:
            out += "| Old path: {} ".format(fsvar.old_path)

        if not fsvar.filesize is None:
            out += "| Filesize: {} ".format(fsvar.filesize)
    elif mqvar.type == TYPE_NETWORK_PACKET:
        packet = mqvar.data
        out = "Highest layer packet: {}".format(packet.highest_layer)


    else:
        raise AssertionError

    return out

