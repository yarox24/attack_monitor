from .parser import Parser
from feeders.structures import *
from malware_engine.report_structures import *

class parser_tshark_network(Parser):
    capabilities = {'type': TYPE_NETWORK_PACKET,
                    "feeders_list": ['network_tshark']
                    }

    def init(self, CONTAINERS=None, GATHERING_OPTIONS=None):
        self.CONTAINERS = CONTAINERS
        self.GATHERING_OPTIONS = GATHERING_OPTIONS

    def create_alert(self, pass_mq):

        # GRAB PACKET
        packet = pass_mq.data
        alout = None

        highest_layer = packet.highest_layer

        # DNS
        if highest_layer == "DNS":

            # DNS Query
            if packet.dns.flags_response.int_value == 0:
                qry_name = packet.dns.qry_name.showname_value
                qry_type = packet.dns.qry_type.showname_value

                title = "DNS Query"
                body = "Domain: {}\n".format(qry_name)
                body += "Type: {} \n".format(qry_type)

                alout = alert(pass_mq, title, body)

            # Response
            elif packet.dns.flags_response.int_value == 1:
                return alout
                #raise NotImplementedError
                resp_name = packet.dns.resp_name.showname_value
                resp_type = packet.dns.resp_type.showname_value


                title = "DNS Response"
                body = "Domain asked: {}\n".format(resp_name)
                body += "Type: {} \n".format(resp_type)

                if "a" in packet.dns.field_names:
                    body += "Answer: {} \n".format(packet.dns.a.showname_value)

                alout = alert(pass_mq, title, body)

        return alout

    def add_to_malware_report(self, pass_mq):

        # GRAB PACKET
        packet = pass_mq.data
        highest_layer = packet.highest_layer

        # DNS
        if highest_layer == "DNS":

            # DNS Query
            if packet.dns.flags_response.int_value == 0:
                qry_name = packet.dns.qry_name.showname_value
                qry_type = packet.dns.qry_type.showname_value.split(" ")[0]

                mbu = create_malware_basic_unit(malware_dns_query(qry_name, qry_type), self.GATHERING_OPTIONS['absolute_time'], pass_mq, None)
                self.CONTAINERS['DNS_QUERIES'].append(mbu)
                return True

        return None
