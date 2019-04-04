from .parser import Parser
from feeders.structures import *
from utils.nicedate import *
from malware_engine.report_structures import *
import os

class parser_evtx_processes(Parser):
    capabilities = {'type': TYPE_LOG_EVENT,
                    "feeders_list": ['evtx_sysmon']
                    }

    def init(self, CONTAINERS=None, GATHERING_OPTIONS=None):
        self.CONTAINERS = CONTAINERS
        self.GATHERING_OPTIONS = GATHERING_OPTIONS

    def create_alert(self, pass_mq):
        # GRAB EVENT
        er = pass_mq.data
        alout = None

        #PROCESS CREATED
        if er.get_raw_field_event_id() == 1:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                #FIELDS
                cmdline = er_fields["CommandLine"]
                image = er_fields["Image"]
                filename = os.path.basename(image)
                pid = er_fields["ProcessId"]
                company = er_fields["Company"]
                user = er_fields["User"]
                integrity = er_fields["IntegrityLevel"]
                hashes = er_fields["Hashes"]
                parent_cmdline = er_fields["ParentCommandLine"]
                parent_pid = er_fields["ParentProcessId"]
                logonid = er_fields["LogonId"]

                # TITLE

                title = "{} ({}) - process started".format(filename, pid)
                body = ""

                #NETWORK INVOKED
                #details_logonid = get_logon_id_info(logonid)

                #if len(details_logonid) > 0:
                    #header = "Network invoked - {} ({})".format(filename, pid)
                    #desc += details_logonid

                body += "Image: {} Company: {}\n".format(image, company)
                body += "Args: {}\n".format(cmdline)
                body += "User: {} Integrity: {}\n".format(user, integrity)
                body += "Hashes: {}\n".format(hashes)
                body += "Parent: {} ({})".format(parent_cmdline,parent_pid)

                alout = alert(pass_mq, title, body)

        #if not alout is None:
            #print(alout)

        return alout

    def add_to_malware_report(self, pass_mq):
        er = pass_mq.data

        # PROCESS CREATED
        if er.get_raw_field_event_id() == 1:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:

                # DATE
                utc_time = er_fields['UtcTime']
                nd_start = NiceDate.sysmon_process_string_to_nicedate(utc_time)
                pid = int(er_fields['ProcessId'])
                panchor = process_anchor(nd_start, pid)

                #mbu = create_malware_basic_unit(panchor, self.GATHERING_OPTIONS['absolute_time'], pass_mq, None)
                self.CONTAINERS['MALWARE_INTERESTING_PIDS'].append(panchor)

                return True

        return None






