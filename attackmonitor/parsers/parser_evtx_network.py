from .parser import Parser
from feeders.structures import *

class parser_evtx_network(Parser):
    capabilities = {'type': TYPE_LOG_EVENT,
                    "feeders_list": ['evtx_security']
                    }

    # PROTOCOLS
    PROTOCOL_TCP = "6"
    PROTOCOL_UDP = "17"
    PROTOCOL_ICMP = "1"

    def is_port_interesting(self, port_nr):
        #print("is_port_int = {}".format(port_nr))
        if int(port_nr) in [20, 21, 22, 23, 25, 69, 110, 143, 161, 162, 1433, 3306, 3389, 4444, 5800, 5900, 6667, 8080]:
            return True
        return False

    def resolve_port_name(self, port_nr):
        port_names = {20: 'FTP',
                      21: 'FTP',
                      22: 'SSH',
                      23: 'TELNET',
                      25: 'SMTP',
                      69: 'TFTP',
                      110: 'POP3',
                      143: 'IMAP',
                      161: 'SNMP',
                      162: 'SNMP',
                      1433: 'MS SQL',
                      3306: 'MySQL',
                      3389: 'RDP',
                      4444: 'Meterpreter',
                      5800: 'VNC (Web)',
                      5900: 'VNC',
                      6667: 'IRC',
                      8080: 'Proxy',
                      }
        try:
            return port_names[int(port_nr)]
        except Exception:
            pass
        return port_nr

    def resolve_protocol(self, protocol_nr):
        if protocol_nr == self.PROTOCOL_TCP:
            return 'TCP'
        elif protocol_nr == self.PROTOCOL_UDP:
            return 'UDP'
        elif protocol_nr == self.PROTOCOL_ICMP:
            return 'ICMP'
        else:
            return 'unknown'

    def init(self, CONTAINERS=None, GATHERING_OPTIONS=None):
        self.CONTAINERS = CONTAINERS
        self.GATHERING_OPTIONS = GATHERING_OPTIONS

    def create_alert(self, pass_mq):
        # GRAB EVENT
        er = pass_mq.data
        alout = None

        # The Windows Filtering Platform has blocked a packet.
        '''if er.get_raw_field_event_id() == 5152:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                protocol_resolved = self.resolve_protocol(er_fields['Protocol'])

                Direction = er_fields['Direction']
                SourceAddress = er_fields['SourceAddress']
                Protocol = er_fields['Protocol']
                DestPort = er_fields['DestPort']
                DestAddress = er_fields['DestAddress']

                title = ''
                body = ''

                #NON-INTERESTING PORT - SKIP
                #if not self.is_port_interesting(DestPort) and protocol_resolved != 'ICMP':
                #    return True

                #INBOUND
                if Direction.lower() == "inbound":
                    title = "Dropped connection from: {} to port: {}".format(SourceAddress, self.resolve_port_name(DestPort))
                    body += 'Protocol: {}\n'.format(protocol_resolved)

                    #ICMP
                    if Protocol == self.PROTOCOL_ICMP:
                        title = "Blocked ping from: {}".format(SourceAddress)
                        body = 'Protocol: {}\n'.format(protocol_resolved)

                #OUTBOUND
                else:
                    title = "Blocked connection to: {} on port: {}".format(DestAddress, self.resolve_port_name(DestPort))
                    body += 'Protocol: {}\n'.format(protocol_resolved)

                alout = alert(pass_mq, title, body)

        # The Windows Filtering Platform has permitted a connection'''

        if er.get_raw_field_event_id() == 5156:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                ProcessID = er_fields["ProcessID"]
                Application = er_fields["Application"]
                Direction = er_fields["Direction"]
                SourceAddress = er_fields["SourceAddress"]
                SourcePort = er_fields["SourcePort"]
                DestAddress = er_fields["DestAddress"]
                DestPort = er_fields["DestPort"]
                Protocol = er_fields["Protocol"]

                protocol_resolved = self.resolve_protocol(Protocol)

                title = ''
                body = ''

                #NON-INTERESTING PORT - SKIP
                #if not is_port_interesting(DestPort) and protocol_resolved != 'ICMP':
                    #return

                #INBOUND
                if Direction.lower() == "inbound":
                    title = "Allowed connection from: {} to port: {}".format(SourceAddress, self.resolve_port_name(DestPort))
                    body += 'Protocol: {}\n'.format(protocol_resolved)

                    #ICMP
                    if Protocol == self.PROTOCOL_ICMP:
                        title = "Someone is pinging from: {}".format(SourceAddress)
                        body = 'Protocol: {}\n'.format(protocol_resolved)

                #OUTBOUND
                else:
                    title = "Outgoing connection to: {} on port: {}".format(DestAddress, self.resolve_port_name(DestPort))
                    body += 'Protocol: {}\n'.format(protocol_resolved)

                body += 'Process: {} ({})\n'.format(Application, ProcessID)

                alout = alert(pass_mq, title, body)

        #if not alout is None:
            #print(alout)

        return alout

    def add_to_malware_report(self, pass_mq):
        pass