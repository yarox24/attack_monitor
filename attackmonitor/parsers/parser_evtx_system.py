from .parser import Parser
from feeders.structures import *

# FALSE - Supported but ignore
# NONE - Not supported


class parser_system_evtx(Parser):
    capabilities = {'type': TYPE_LOG_EVENT,
                    "feeders_list": ['evtx_system']
                    }

    def init(self, CONTAINERS=None, GATHERING_OPTIONS=None):
        self.CONTAINERS = CONTAINERS
        self.GATHERING_OPTIONS = GATHERING_OPTIONS

    def create_alert(self, pass_mq):
        # GRAB EVENT
        er = pass_mq.data
        alout = None

        #Service has been installed
        # sc create testservice binpath= c:\windows\system32\NewServ.exe type= share start= auto
        # sc delete testservice
        if er.get_raw_field_event_id() == 7045 and er.get_raw_field_provider_name().lower() == "Service Control Manager".lower():
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                # TITLE
                title = "New service has been installed ({})".format(er_fields['ServiceName'])

                # BODY
                body = "Image Path: {}".format(er_fields['ImagePath'])
                body += "\nService type: {} Start Type: {}".format(er_fields['ServiceType'], er_fields['StartType'])
                body += "\nAccount name: {}".format(er_fields['AccountName'])

                alout = alert(pass_mq, title, body)

        #Service has been launched/exited - WIN 7 ONLY
        elif er.get_raw_field_event_id() == 7036:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                ServiceName = er_fields["param1"]
                param2 = er_fields["param2"]

                # TITLE
                title = "Service has been launched/exited ({})".format(ServiceName)

                # BODY
                body = "New state: {}".format(param2)

                alout = alert(pass_mq, title, body)

        #Log clear
        elif er.get_raw_field_event_id() == 104 and er.get_raw_field_provider_name().lower() == 'Microsoft-Windows-Eventlog'.lower():
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                # TITLE
                title = "Evtx log cleared - {}".format(er_fields['Channel'])

                # BODY
                body = "Invoked by: {}\{}".format(er_fields['SubjectDomainName'], er_fields['SubjectUserName'])

                alout = alert(pass_mq, title, body)

        #if not alout is None:
            #print(alout)

        return alout

    def add_to_malware_report(self, pass_mq):
        pass