from .parser import Parser
from feeders.structures import *

# SEARCH: .*Name="(.*)".*
# REPLACE: \1 = er.get_data_value_named\("\1"\)

# FALSE - Supported but ignore
# NONE - Not supported

class parser_evtx_security(Parser):
    capabilities = {'type': TYPE_LOG_EVENT,
                    "feeders_list": ['evtx_security']
                    }

    def init(self, CONTAINERS=None, GATHERING_OPTIONS=None):
        self.CONTAINERS = CONTAINERS
        self.GATHERING_OPTIONS = GATHERING_OPTIONS
        self.substatus_failed = {
                        '0XC0000064': 'user name does not exist',
                        '0XC000006A': 'user name is correct but the password is wrong',
                        '0XC0000234': 'user is currently locked out',
                        '0XC0000072': 'account is currently disabled',
                        '0XC000006F': 'user tried to logon outside his day of week or time of day restrictions',
                        '0XC0000070': 'workstation restriction, or Authentication Policy Silo violation (look for event ID 4820 on domain controller)',
                        '0XC0000193': 'account expiration',
                        '0XC0000071': 'expired password',
                        '0XC0000133': 'clocks between DC and other computer too far out of sync',
                        '0XC0000224': 'user is required to change password at next logon',
                        '0XC0000225': 'evidently a bug in Windows and not a risk',
                        '0Xc000015B': 'The user has not been granted the requested logon type (aka logon right) at this machine',
                        }


    def create_alert(self, pass_mq):
        # GRAB EVENT
        er = pass_mq.data
        alout = None

        # Logon success
        if er.get_raw_field_event_id() == 4624:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                LogonType = int(er_fields["LogonType"])

                #FOR SHARED MEMORY
                #if len(IpAddress) > 1 and IpAddress != "127.0.0.1":
                    #add_logon_id(TargetLogonId, TargetUserName, IpAddress)

                #LOCALHOST AND LOCALUSER - SKIP
                #if int(LogonType) == 3 and (TargetUserName.lower() in self.comp_accs) and (IpAddress == "-" or IpAddress == "127.0.0.1"):
                #   return True

                # LOGON TYPE 5 OR 7 SKIP
                if LogonType == 5 or LogonType == 7:
                    return False

                # TITLE
                title = "An account was successfully logged on"

                # BODY
                body = "Target user: {}\{}".format(er_fields['TargetDomainName'], er_fields['TargetUserName'])
                body += "\nLogon type: {} LM Package: {}".format(LogonType, er_fields['LmPackageName'])
                body += "\nSource IP: {} ({})".format(er_fields['IpAddress'].strip(), er_fields['WorkstationName'])

                alout = alert(pass_mq, title, body)

        # Logon failed
        if er.get_raw_field_event_id() == 4625:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:

                # TITLE
                title = "User failed to logon"

                # BODY
                body = ""
                if len(er_fields['SubjectUserName']) > 1:
                    body += "Source user: {}\{}\n".format(er_fields['SubjectDomainName'], er_fields['SubjectUserName'])
                body += "Target user: {}\{}\n".format(er_fields['TargetDomainName'], er_fields['TargetUserName'])
                body += "Logon type: {} LM Package: {}\n".format(er_fields['LogonType'], er_fields['LmPackageName'])
                body += "Attack source: {}:{} ({})\n".format(er_fields['IpAddress'], er_fields['IpPort'], er_fields['WorkstationName'])

                # SUBSTATUS
                try:
                    body += "Failure reason: {}\n".format(self.substatus_failed[er_fields['SubStatus'].upper()])
                except (KeyError, ValueError):
                    body += "Failure reason: {}\n".format(er_fields['SubStatus'])

                alout = alert(pass_mq, title, body)


        # A logon was attempted using explicit credentials
        ''' Runas different user with [SHIFT]'''
        if er.get_raw_field_event_id() == 4648:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                # TITLE
                title = "Run as: {} -> {}".format(er_fields['SubjectUserName'], er_fields['TargetUserName'])

                # BODY
                body = ""
                body += "Source user: {}\{}\n".format(er_fields['SubjectDomainName'], er_fields['SubjectUserName'])
                body += "Target user: {}\{}\n".format(er_fields['TargetDomainName'], er_fields['TargetUserName'])
                body += "Targer server: {}\n".format(er_fields['TargetServerName'])
                body += "Source IP: {}:{}\n".format(er_fields['IpAddress'], er_fields['IpPort'])
                body += "Process: {} ({})\n".format(er_fields['ProcessName'], er_fields['ProcessId'])

                alout = alert(pass_mq, title, body)

        # A user account was created
        ''' net user John fadf24as /ADD '''
        if er.get_raw_field_event_id() == 4720:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                # TITLE
                title = "New account created: {}".format(er_fields['TargetUserName'])

                # BODY
                body = ""
                body += "by: {}\{}\n".format(er_fields['SubjectDomainName'], er_fields['SubjectUserName'])
                #body += get_logon_id_info(SubjectLogonId, user=False)
                body += "SAM name: {}\n".format(er_fields['SamAccountName'])
                body += "Display name: {}\n".format(er_fields['DisplayName'])
                body += "Home: {}\n".format(er_fields['HomeDirectory'])
                body += "Primary GID: {}\n".format(er_fields['PrimaryGroupId'])

                alout = alert(pass_mq, title, body)

        # A user account was enabled
        if er.get_raw_field_event_id() == 4722:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                # TITLE
                title = "Account enabled: '{}\{}'".format(er_fields['TargetDomainName'], er_fields['TargetUserName'])

                # BODY
                body = ""
                body += "by: {}\{}\n".format(er_fields['SubjectDomainName'], er_fields['SubjectUserName'])
                #body +=  get_logon_id_info(SubjectLogonId, user=False)

                alout = alert(pass_mq, title, body)



        # An attempt was made to change an account's password
        if er.get_raw_field_event_id() == 4723:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                # TITLE
                title = "Account '{}\{}' password was changed".format(er_fields['TargetDomainName'], er_fields['TargetUserName'])

                # BODY
                body = "by: {}\{}\n".format(er_fields['SubjectDomainName'], er_fields['SubjectUserName'])
                #body += get_logon_id_info(SubjectLogonId, user=False)
                body += "Privs: {}\n".format(er_fields['PrivilegeList'])

                alout = alert(pass_mq, title, body)


        # An attempt was made to reset an account's password
        if er.get_raw_field_event_id() == 4724:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                # TITLE
                title = "Account '{}\{}' password was reset".format(er_fields['TargetDomainName'], er_fields['TargetUserName'])

                # BODY
                body = "by: {}\{}\n".format(er_fields['SubjectDomainName'], er_fields['SubjectUserName'])
                #body += get_logon_id_info(SubjectLogonId, user=False)

                alout = alert(pass_mq, title, body)

        # A user account was disabled
        if er.get_raw_field_event_id() == 4725:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                # TITLE
                title = "Account '{}\{}' was disabled".format(er_fields['TargetDomainName'], er_fields['TargetUserName'])

                # BODY
                body = "by: {}\{}\n".format(er_fields['SubjectDomainName'], er_fields['SubjectUserName'])
                #body += get_logon_id_info(SubjectLogonId, user=False)

                alout = alert(pass_mq, title, body)


        # A user account was deleted
        if er.get_raw_field_event_id() == 4726:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                # TITLE
                title = "Account '{}\{}' was deleted".format(er_fields['TargetDomainName'], er_fields['TargetUserName'])

                # BODY
                body = "by: {}\{}\n".format(er_fields['SubjectDomainName'], er_fields['SubjectUserName'])
                #body += get_logon_id_info(SubjectLogonId, user=False)
                body += "Privs: {}\n".format(er_fields['PrivilegeList'])

                alout = alert(pass_mq, title, body)

        # A user account was changed.
        if er.get_raw_field_event_id() == 4738:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                # TITLE
                title = "Account '{}\{}' parameters was changed".format(er_fields['TargetDomainName'], er_fields['TargetUserName'])

                # BODY
                body = "by: {}\{}\n".format(er_fields['SubjectDomainName'], er_fields['SubjectUserName'])
                #body += get_logon_id_info(SubjectLogonId, user=False)
                body += "Privs: {}\n".format(er_fields['PrivilegeList'])
                body += "Display name: {}\n".format(er_fields['DisplayName'])
                body += "SAM name: {}\n".format(er_fields['SamAccountName'])

                if er_fields['OldUacValue'] != er_fields['NewUacValue']:
                    body += "UAC Value: {} -> {}\n".format(er_fields['OldUacValue'], er_fields['NewUacValue'])

                alout = alert(pass_mq, title, body)


        # A user account was locked out NOT TESTED
        if er.get_raw_field_event_id() == 4740:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                # TITLE
                title = "Account '{}\{}' was locked out".format(er_fields['TargetDomainName'],
                                                                er_fields['TargetUserName'])

                # BODY
                body = "by: {}\{}\n".format(er_fields['SubjectDomainName'], er_fields['SubjectUserName'])
                #body += get_logon_id_info(SubjectLogonId, user=False)

                alout = alert(pass_mq, title, body)


        # A user account was unlocked NOT TESTED
        if er.get_raw_field_event_id() == 4767:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                # TITLE
                title = "Account '{}\{}' was unlocked".format(er_fields['TargetDomainName'], er_fields['TargetUserName'])

                # BODY
                body = "by: {}\{}\n".format(er_fields['SubjectDomainName'], er_fields['SubjectUserName'])
                #body += get_logon_id_info(SubjectLogonId, user=False)

                alout = alert(pass_mq, title, body)


        # The name of an account was changed
        if er.get_raw_field_event_id() == 4781:
            (success, er_fields) = er.get_raw_param_all_dict(convert_null=True, resolve_double_percentage=True)
            if success:
                # TITLE
                title = "Account name was changed"

                # BODY
                body = "Domain: {}\n".format(er_fields['TargetDomainName'])
                body += "Name: {} -> {}\n".format(er_fields['OldTargetUserName'], er_fields['NewTargetUserName'])
                body += "by: {}\{}\n".format(er_fields['SubjectDomainName'], er_fields['SubjectUserName'])
                #body += get_logon_id_info(er_fields['SubjectLogonId'], user=False)

                alout = alert(pass_mq, title, body)

        #if not alout is None:
            #print(alout)

        return alout

    def add_to_malware_report(self, pass_mq):
        pass