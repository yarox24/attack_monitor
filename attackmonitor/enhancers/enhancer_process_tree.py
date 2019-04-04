from .enhancer import Enhancer
import psutil
from feeders.structures import process_info, user_info
from utils.nicedate import *
from stone_engine import evtx_subscriber
import time
import datetime

class enhancer_process_tree(Enhancer):
    def getName(self):
        return "process_tree"

    @staticmethod
    def pid_entry(pid, id):
        return "{}_{}".format(pid,id)

    def find_empty_pid_id(self, pid):
        root = self.storage
        id = 0
        while True:
            if self.pid_entry(pid,id) in root.keys():
                id += 1
            else:
                return id

    def find_all_version_of_pid(self, pid):
        root = self.storage
        id = 0
        out_pe_list = list()
        while True:
            pe = self.pid_entry(pid, id)
            if pe in root.keys():
                out_pe_list.append(pe)
            else:
                break

            id += 1
        return out_pe_list

    def check_if_duplicate_exists(self, pi):
        root = self.storage

        for pe_existing in self.find_all_version_of_pid(pi.pid):
            pi_existing = root[pe_existing]
            if pi_existing.start_nice_date == pi.start_nice_date:
                return True

        return False

    def add_process_to_storage(self, pi):
        pid = pi.pid
        root = self.storage

        #CHECK DUPLICATES
        if self.check_if_duplicate_exists(pi):
            return

        #NEXT ONE
        pe = self.pid_entry(pid, self.find_empty_pid_id(pid))
        root[pe] = pi

    def copy_pi_with_end_date(self, pi_old, end_date):
        return process_info(pi_old.start_nice_date, end_date, pi_old.pid, pi_old.image, pi_old.commandline,
                            pi_old.currentdirectory, pi_old.user, pi_old.logonid, pi_old.sessionid,
                            pi_old.integritylevel, pi_old.ppid)

    def initial_process_gathering(self):
        ONLY_FIELDS = ['pid', 'exe', 'cmdline', 'cwd', 'username', 'ppid', 'create_time']

        for proc in psutil.process_iter(attrs=ONLY_FIELDS):

            try:
                pinfo = proc.as_dict(attrs=ONLY_FIELDS)

                start_nice_date = NiceDate.naive_datetime_localize(datetime.datetime.fromtimestamp(pinfo['create_time']))

                pid = pinfo['pid']
                image = pinfo['exe']
                commandline = None
                if type(pinfo['cmdline']) is list:
                    commandline = " ".join(pinfo['cmdline'])
                currentdirectory = pinfo['cwd']

                #User
                split_user = list()
                uuii = None

                if not pinfo['username'] is None:
                    split_user = pinfo['username'].split("\\")

                if len(split_user) == 2:
                    uuii = user_info(split_user[0],split_user[1])
                elif len(split_user) == 1:
                    uuii = user_info(None, split_user[0])

                ppid = pinfo['ppid']

                pi = process_info(start_nice_date, None, pid, image, commandline, currentdirectory, uuii, None, None, None, ppid)
                self.add_process_to_storage(pi)

            except psutil.NoSuchProcess:
                pass

    @staticmethod
    def get_best_version_by_date(pid, live_date, storage_ptr):
        # PARENT START DATE < LIVE DATE < NOW OR END DATE

        # ITERATE OVER ALL VERSIONS
        id = 0
        while True:
            pe = enhancer_process_tree.pid_entry(pid, id)
            if pe in storage_ptr.keys():
                if storage_ptr[pe].start_nice_date <= live_date:
                    if storage_ptr[pe].end_nice_date is None or storage_ptr[pe].end_nice_date >= live_date:
                        return pe
            else:
                break
            id += 1

        return None

    @staticmethod
    def generate_process_tree(starting_ppid, live_date, storage_ptr):
        tree = list()

        current_ppid = starting_ppid
        current_date = live_date
        for i in range(0,3):
            while True:
                grandpa_pe = enhancer_process_tree.get_best_version_by_date(current_ppid, current_date, storage_ptr)
                if grandpa_pe is None:
                    break
                else:
                    if storage_ptr[grandpa_pe].image is None:
                        tree.append("PID:{}".format(storage_ptr[grandpa_pe].pid))
                    else:
                        tree.append(storage_ptr[grandpa_pe].image)

                    current_ppid = storage_ptr[grandpa_pe].ppid
                    current_date = storage_ptr[grandpa_pe].start_nice_date
            if len(tree) > 0:
                break

            # MAYBE AFTER THIS TIME INFORMATION WILL BE AVAILIABLE
            time.sleep(1)

        return list(reversed(tree))

    @staticmethod
    def find_all_parents(starting_pid, live_date, storage_ptr):
        tree = list()

        current_ppid = starting_pid
        current_date = live_date
        for i in range(0,3):
            while True:
                grandpa_pe = enhancer_process_tree.get_best_version_by_date(current_ppid, current_date, storage_ptr)
                if grandpa_pe is None:
                    break
                else:
                    tree.append(storage_ptr[grandpa_pe])

                    current_ppid = storage_ptr[grandpa_pe].ppid
                    current_date = storage_ptr[grandpa_pe].start_nice_date
            if len(tree) > 0:
                break

            # MAYBE AFTER THIS TIME INFORMATION WILL BE AVAILIABLE
            time.sleep(1)

        return list(reversed(tree))

    def run(self):

        # INITIAL PROCESS GATHERING
        self.initial_process_gathering()

        middle_process_gathered = False

        # NEW PROCESS INIFINITE LOOP
        for er in evtx_subscriber.subscribe_and_yield_events('Microsoft-Windows-Sysmon/Operational'):
            eid = er.get_raw_field_event_id()

            # IN MIDDLE EXTRA SYNC
            if middle_process_gathered == False:
                self.initial_process_gathering()
                middle_process_gathered = True

            # PROCESS CREATED
            if eid == 1:
                (success, e_param) = er.get_raw_param_all_dict(convert_null=True)
                if not success:
                    raise AttributeError

                # DATE
                utc_time = e_param['UtcTime']
                nd_start = NiceDate.sysmon_process_string_to_nicedate(utc_time)

                # USER
                split_user = e_param['User'].split("\\")
                ui = None
                if len(split_user) == 2:
                    ui = user_info(split_user[0], split_user[1])
                else:
                    raise NotImplemented

                pi = process_info(nd_start, None, int(e_param['ProcessId']), e_param['Image'], e_param['CommandLine'],
                                  e_param['CurrentDirectory'], ui, int(e_param['LogonId'], 0), int(e_param['TerminalSessionId']),
                                  e_param['IntegrityLevel'], int(e_param['ParentProcessId']) )

                self.add_process_to_storage(pi)


            # PROCESS TERMINATED
            if eid == 5:
                (success, e_param) = er.get_raw_param_all_dict(convert_null=True)
                if not success:
                    raise AssertionError

                # FIND ALL PIDS
                utc_time = e_param['UtcTime']
                nd_end = NiceDate.sysmon_process_string_to_nicedate(utc_time)
                pid = e_param['ProcessId']
                image = e_param['Image']

                all_pe = self.find_all_version_of_pid(pid)
                if len(all_pe) == 0:
                    continue # ERROR SITUATION
                    #raise AssertionError

                for pe_specific in all_pe:
                    # FIND LOWEST PID WITHOUT END DATE
                    if self.storage[pe_specific].end_nice_date is None:
                        self.storage[pe_specific] = self.copy_pi_with_end_date(self.storage[pe_specific], nd_end)
                        break

