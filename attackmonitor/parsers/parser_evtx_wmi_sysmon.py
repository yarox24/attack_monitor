from .parser import Parser
from feeders.structures import *

class parser_evtx_wmi_sysmon(Parser):
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

        #WmiEventFilter
        if er.get_raw_field_event_id() == 19:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                # TITLE
                title = "WMI EventFilter {} (Potential APT)".format(er_fields['Operation'])

                # BODY
                body = ""

                body += "Name: {}\n".format(er_fields['Name'])
                body += "User: {}\n".format(er_fields['User'])
                body += "Namespace: {}\n".format(er_fields['EventNamespace'])
                body += "Query: {}".format(er_fields['Query'])

                alout = alert(pass_mq, title, body)

        #WmiEventConsumer
        if er.get_raw_field_event_id() == 20:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                # TITLE
                title = "WMI EventConsumer {} (Potential APT)".format(er_fields['Operation'])

                # BODY
                body = ""
                body += "Name: {}\n".format(er_fields['Name'])
                body += "User: {}\n".format(er_fields['User'])
                body += "Type: {}\n".format(er_fields['Type'])
                body += "Destination: {}".format(er_fields['Destination'])

                alout = alert(pass_mq, title, body)

        #WmiEventConsumerToFilter
        if er.get_raw_field_event_id() == 21:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                # TITLE
                title = "WMI WmiEventConsumerToFilter {} (Potential APT)".format(er_fields['Operation'])

                # BODY
                body = ""
                body += "Name: {}\n".format(er_fields['Name'])
                body += "User: {}\n".format(er_fields['User'])
                body += "Consumer: {}\n".format(er_fields['Consumer'])
                body += "Filter: {}".format(er_fields['Filter'])

                alout = alert(pass_mq, title, body)

        #if not alout is None:
            #print(alout)

        return alout

    def add_to_malware_report(self, pass_mq):
        pass
