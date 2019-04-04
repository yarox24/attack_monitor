from multiprocessing import Process
from feeders.structures import *
from enhancers.enhancer_process_tree import enhancer_process_tree
from utils.nicedate import NiceDate
from parsers.parser import Parser
from parsers import parser_evtx_security, parser_evtx_system, parser_evtx_samba, \
    parser_evtx_schtasks, parser_evtx_powershell_main, parser_evtx_powershell_scriptblock, \
    parser_evtx_wmi_sysmon, parser_evtx_wmi_trace, parser_evtx_processes, parser_evtx_network, \
    parser_dirwatcher, parser_evtx_sysmon_others, parser_tshark_network

class Integrator(Process):
    def __init__(self, ULTRA_MQ, ALERT_MQ, DEBUG_MQ, GATHERING_OPTIONS, PROCESS_TREE):
        super(Process, self).__init__()
        self.daemon = True
        self.ULTRA_MQ = ULTRA_MQ
        self.ALERT_MQ = ALERT_MQ
        self.DEBUG_MQ = DEBUG_MQ
        self.GATHERING_OPTIONS = GATHERING_OPTIONS
        self.PROCESS_TREE = PROCESS_TREE

        # PREPARE CAPABILITY MATRIX
        self.prepare_capability_matrix()
        #print(self.capability_matrix)

    def create_enhanced_mq(self, old_m, extra_data):
        return mq(old_m.data, old_m.type, old_m.source, old_m.datetime_with_timezone, old_m.key, extra_data)

    def enhance_process_creation(self, pass_mq):
        # ENHANCES PROCESS CREATION BY PROCESS TREE
        if pass_mq.type == TYPE_LOG_EVENT:
            er = pass_mq.data

            # PROCESS CREATED
            if er.get_raw_field_event_id() == 1 and er.get_raw_field_provider_name().lower() == 'microsoft-windows-sysmon':
                (success, e_param) = er.get_raw_param_all_dict(convert_null=True)
                # print("PID: {} - {}".format(e_param['ProcessId'],e_param['Image']))
                if success:
                    utc_time = e_param['UtcTime']
                    nd_start = NiceDate.sysmon_process_string_to_nicedate(utc_time)
                    ppid = int(e_param['ParentProcessId'])

                    process_tree = enhancer_process_tree.generate_process_tree(ppid, nd_start, self.PROCESS_TREE)
                    if len(process_tree) > 0:
                        extra_info = {'process_list': process_tree, }
                        return self.create_enhanced_mq(pass_mq, extra_info)
        return pass_mq

    def enable_malware_gathering(self, pass_mq):
        if pass_mq.type == TYPE_LOG_EVENT:
            er = pass_mq.data

            # PROCESS CREATED
            if er.get_raw_field_event_id() == 1 and er.get_raw_field_provider_name().lower() == 'microsoft-windows-sysmon':
                (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=False)
                if success:
                    image = er_fields['Image']

                    # START CASE
                    if image.find(self.GATHERING_OPTIONS['control_start_proc']) != -1:
                        cmdline = er_fields['CommandLine'][len(self.GATHERING_OPTIONS['control_start_proc']):].strip()
                        options = cmdline.split(" ")
                        for opt in options:
                            opt_split = opt.split("=")
                            if len(opt) > 3 and len(opt_split) == 2:
                                key = opt_split[0].lstrip("-")
                                value = opt_split[1].strip('"')
                                self.GATHERING_OPTIONS[key] = value

                        self.GATHERING_OPTIONS['enabled'] = True
                        self.GATHERING_OPTIONS['absolute_time'] = NiceDate.get_now()
                        print("Malware gathering ENABLED")
                        return True

                    elif image.find(self.GATHERING_OPTIONS['control_generate_proc']) != -1:
                        self.GATHERING_OPTIONS['generate_report'] = True
                        print("Generate malware report ENABLED")
                        return True

        return False

    def enhance_powershell_event(self, pass_mq):
        if pass_mq.type == TYPE_LOG_EVENT:
            er = pass_mq.data

            # PROCESS CREATED
            if er.get_raw_field_event_id() == 400 and er.get_raw_field_provider_name().lower() == "PowerShell".lower():
                (success, tab) = er.get_raw_param_by_index(2, convert_null=True)
                if success:
                    extra_info = dict()

                    for line in tab.split("\n"):
                        temp = line.replace("\t", "")
                        equal_pos = temp.find("=")
                        if equal_pos == -1:
                            continue
                        else:
                            key = temp[:equal_pos].lower()
                            value = temp[equal_pos + 1:].strip()
                            extra_info[key] = value

                    if len(extra_info.keys()) > 0:
                        return self.create_enhanced_mq(pass_mq, extra_info)
                else:
                    raise AssertionError
        return pass_mq

    def generate_alert(self, pass_mq):
        #print(pass_mq)

        if pass_mq.type in self.capability_matrix.keys():
            if pass_mq.source in self.capability_matrix[pass_mq.type].keys():
                for parser in self.capability_matrix[pass_mq.type][pass_mq.source]:
                    result = parser.create_alert(pass_mq)

                    # NONE - Not supported by this parser, check next one
                    if result is None:
                        continue

                    # FALSE - Supported but ignore
                    elif result == False:
                        break

                    # OK
                    elif isinstance(result, alert):
                        return result
                    else:
                        raise AssertionError
            else:
                pass
                #raise AssertionError
        else:
            pass
            #raise AssertionError

        return None

    def prepare_capability_matrix(self):
        self.capability_matrix = {TYPE_LOG_EVENT: dict(),
                                  TYPE_FS_CHANGE: dict(),
                                  TYPE_NETWORK_PACKET: dict(),
                                  }

        for parserx in Parser.__subclasses__():
            parser_instance = parserx()
            parser_instance.init()
            parser_capab = parser_instance.get_capabilities()

            for source in parser_capab['feeders_list']:
                if not source in self.capability_matrix[parser_capab['type']].keys():
                    self.capability_matrix[parser_capab['type']][source] = list()

                if not parser_instance in self.capability_matrix[parser_capab['type']][source]:
                    self.capability_matrix[parser_capab['type']][source].append(parser_instance)

    def run(self):
        while True:
            # GRAB FROM ULTRA MQ
            try:
                pass_mq = self.ULTRA_MQ.get()

                #START MALWARE GATHERING INFORMATION - INVISIBLE EVENT
                if self.enable_malware_gathering(pass_mq):
                    continue

                # ENHANCERS INFORMATION APPLIED
                pass_mq = self.enhance_process_creation(pass_mq)
                pass_mq = self.enhance_powershell_event(pass_mq)

                # GENERATE ALERT
                result = self.generate_alert(pass_mq)

                # PASS ALERT
                if not result is None:
                    self.ALERT_MQ.put(result)

                # DEBUG SAVE
                if not self.DEBUG_MQ is None:
                    supported = True
                    if result is None:
                        supported = False
                    mqd = mq_debug(pass_mq, supported)
                    self.DEBUG_MQ.put(mqd)

            except Exception as e:
                print("Error when parsing event. Event is lost ...")