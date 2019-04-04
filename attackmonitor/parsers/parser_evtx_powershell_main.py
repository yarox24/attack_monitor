from .parser import Parser
from feeders.structures import *

class parser_evtx_powershell_main(Parser):
    capabilities = {'type': TYPE_LOG_EVENT,
                    "feeders_list": ['evtx_windows_powershell']
                    }

    def init(self, CONTAINERS=None, GATHERING_OPTIONS=None):
        self.CONTAINERS = CONTAINERS
        self.GATHERING_OPTIONS = GATHERING_OPTIONS

    def create_alert(self, pass_mq):
        # GRAB EVENT
        er = pass_mq.data
        alout = None

        if er.get_raw_field_event_id() == 400 and er.get_raw_field_provider_name().lower() == "PowerShell".lower():
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            extra_fields = pass_mq.extra_data
            if success:

                # TITLE
                local_part = ""
                if extra_fields['hostname'] == 'ServerRemoteHost': #and parsed_values['hostname'] != 'ConsoleHost':
                    local_part = "Remote "
                elif extra_fields['hostname'] == 'ConsoleHost' or extra_fields['hostname'] == 'Default Host':
                    local_part = "Local "
                else:
                    local_part = ""

                ps_version = extra_fields['engineversion'][0:3]
                title = "{} Powershell {} has been started".format(local_part, ps_version)

                # BODY
                body = ""
                if 'commandline' in extra_fields.keys() and len(extra_fields['commandline']) > 0:
                    body += "Command line: {}\n".format(extra_fields['commandline'])
                body += "HostApplication: {}\n".format(extra_fields['hostapplication'])

                alout = alert(pass_mq, title, body)

        #if not alout is None:
            #print(alout)

        return alout

    def add_to_malware_report(self, pass_mq):
        pass