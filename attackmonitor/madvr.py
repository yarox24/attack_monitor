import os
import sys

# PYTHON 2 EXIT
if (sys.version_info.major == 2):
    sys.stdout.write("This software is designed to run with Python 3. Your version is 2\n")
    sys.stdout.write("Best version will be Python 3.6 (x64)\n")
    os.system("pause")
    sys.exit(0)

import multiprocessing
import json
import platform
from win32com.shell import shell

from utils import configer
from feeders.feeder import Feeder
from feeders import feeder_dirwatcher_notifier, feeder_evtx_security, \
    feeder_evtx_sysmon, feeder_evtx_windows_powershell, \
    feeder_evtx_task_scheduler, feeder_evtx_powershell_operational,\
    feeder_evtx_system, feeder_tshark
from enhancers.enhancer import Enhancer
from enhancers.integrator import Integrator
from enhancers import enhancer_process_tree
from exception_package.exception_filter import ExceptionFilter
from guidir import gui_process
from output import debug, alarm
from malware_engine.gatherer import Gatherer
from stone_engine import evtx_subscriber

def is_user_an_admin():
    if not shell.IsUserAnAdmin():
        print("Please run this program as administrator")
        os.system("pause")
        sys.exit(0)

def is_sysmon_installed():
    if not evtx_subscriber.test_channel_existence('Microsoft-Windows-Sysmon/Operational'):
        print("Sysmon is not installed")
        os.system("pause")
        sys.exit(0)


def generate_env_variables(REPLACE_VARIABLES_PATH):
    REPLACE_VARIABLES = {"%%%USERNAME%%%" : os.getlogin(),
                        "%%%HOSTNAME%%%": platform.node(),
                        }

    if not os.path.exists(REPLACE_VARIABLES_PATH):
        with open(REPLACE_VARIABLES_PATH, 'w', encoding='utf8') as outfile:
            str_ = json.dumps(REPLACE_VARIABLES, indent=4, separators=(',', ': '), ensure_ascii=False)
            outfile.write(str_)

def load_exceptions():
    cc = configer.Config()
    cc.get_config_options()

def load_initial_exception_rules(cc, EXCEPTION_RULES):
    EXCEPTION_RULES_BASEDIR = cc.get_exception_files_basedir()

    # LIST RULES FILE
    exception_files =  os.listdir(EXCEPTION_RULES_BASEDIR)
    for exception_file in exception_files:
        exception_path = EXCEPTION_RULES_BASEDIR + exception_file

        # LOAD
        rules = json.load(open(exception_path, 'r', encoding='utf8'))
        EXCEPTION_RULES += rules

def logo():
    VERSION = ""
    SCRIPT_DIR = os.path.dirname(os.path.realpath(sys.argv[0]))
    with open(SCRIPT_DIR + "\\" + "VERSION") as v:
        VERSION = v.readline().strip()


    print("""
                            ###########
                           ####     ### 
  Attack Monitor         ####       ### 
   """  + VERSION + """        ####        ### 
                      #####         ### 
                     ####          #### 
                    ####          ####  
                   ###          #####   
                 ####         #####     
                ####        ####        
      #        ####       ####          
    #####    ####       #####           
  ########  ####       ####             
 ##### #######       #####              
####     ####      #####                
 ####     #####  #####                   
   ####     ########  Provided by Jarosław Oparka 
    ####      ####    https://github.com/yarox24/attack_monitor
    ######     #####                 
 ##########     #####                   
##   ########     ####                  
##    ########   ####                   
 ##   ###   ########                    
  #####       ####                      


""")

def main():
    logo()

    print()
    cc = configer.Config()
    is_user_an_admin()
    is_sysmon_installed()

    # CONFIG
    debug_enabled = cc.get_config_single_variable_from_category(configer.MAIN_CONFIG, "logs", "debug")

    # SHARED STRUCTURES AMONGST PROCESSESS
    MM = multiprocessing.Manager()

    # ULTRA MQ
    ULTRA_MQ = MM.Queue()

    # ALERT MQ
    ALERT_MQ = MM.Queue()

    # SHOW MQ
    SHOW_MQ = MM.Queue()

    # TRAY MQ
    TRAY_MQ = MM.Queue()

    # MALWARE MQ
    GATHERING_OPTIONS = MM.dict()
    GATHERING_OPTIONS['enabled'] = False
    GATHERING_OPTIONS['malware_dir'] = None
    GATHERING_OPTIONS['generate_report'] = False
    GATHERING_OPTIONS['report_dir'] = None
    GATHERING_OPTIONS['absolute_time'] = None
    GATHERING_OPTIONS['control_start_proc'] = 'malware_monitor_start.exe'
    GATHERING_OPTIONS['control_generate_proc'] = 'malware_monitor_report_generate.exe'

    # MALWARE STORAGE
    CONTAINERS = MM.dict()
    MALWARE_MQ = MM.Queue()
    MALWARE_INTERESTING_PIDS = MM.list()
    DNS_QUERIES = MM.list()

    # AGGREGATE
    CONTAINERS['MALWARE_INTERESTING_PIDS'] = MALWARE_INTERESTING_PIDS
    CONTAINERS['DNS_QUERIES'] = DNS_QUERIES

    # SHARED DATA / MALWARE REPORT
    PROCESS_TREE = MM.dict()

    # EXCEPTIONS
    EXCEPTION_RULES = MM.list()

    # LOGGING OUTPUT
    DEBUG_MQ = MM.Queue()
    if not debug_enabled:
        DEBUG_MQ = None
    ALARM_MQ = MM.Queue()

    # GENERATE REPLACE VARIABLES - %%%
    generate_env_variables(cc.get_replace_variables_path())
    load_initial_exception_rules(cc, EXCEPTION_RULES)

    # GUI PROCESS
    gp = gui_process.GUI_Process(SHOW_MQ, TRAY_MQ, ALARM_MQ, MALWARE_MQ, EXCEPTION_RULES)
    gp.start()

    # -------------------------------------------
    # ACTIVE PROCESSING START - BEYOND THIS POINT
    # ACTIVE PROCESSING START - BEYOND THIS POINT
    # -------------------------------------------

    if debug_enabled:
        dlog = debug.LoggerDebug()
        dlog.set_input_queqe(DEBUG_MQ)
        dlog.start()

    # ALARMS ONLY LOGGER (MAIN ONE)
    alog = alarm.LoggerAlarm()
    alog.set_input_queqe(ALARM_MQ)
    alog.start()

    # ENHANCERS
    enhancer_config = cc.get_config_single_category(configer.MAIN_CONFIG, "enhancers")
    for enhancer in Enhancer.__subclasses__():
        enhancer_instance = enhancer()

        # SPECIFIC FOR PROCESS TREE
        if isinstance(enhancer_instance, enhancer_process_tree.enhancer_process_tree):
            enhancer_instance.setStorage(PROCESS_TREE)

        enhancer_instance.name = enhancer_instance.getName()

        # IS ENABLED
        if enhancer_config[enhancer_instance.name]:
            enhancer_instance.start()
            print("Enhancer: {} started".format(enhancer_instance.getName()))
        else:
            print("[Disabled in config] Enhancer: {} started".format(enhancer_instance.getName()))

    # FEEDERS
    feeders_active = []
    feeders_config = cc.get_config_single_category(configer.MAIN_CONFIG, "feeders")

    for feeder in Feeder.__subclasses__():
        feeder_instance = feeder()
        feeder_instance.name = feeder_instance.getName()

        # IS ENABLED
        if feeders_config[feeder_instance.name]:
            feeder_instance.set_ultra_mq(ULTRA_MQ)
            feeder_instance.set_config_options(cc.get_options_for_feeder(feeder_instance.getName()))
            feeder_instance.start()
            print("Feeder: {} started".format(feeder_instance.getName()))
        else:
            print("Feeder: {} [Disabled in config]".format(feeder_instance.getName()))

    # INTEGRATORS
    INTEGRATORS_COUNT = 3

    for i in range(0, INTEGRATORS_COUNT):
        inor = Integrator(ULTRA_MQ, ALERT_MQ, DEBUG_MQ, GATHERING_OPTIONS, PROCESS_TREE)
        inor.name = "INTEGRATOR_{}".format(i)
        inor.start()
        print("{} started".format(inor.name))

    # EXCEPTION ENGINE
    EXCEPTION_ENGINE_COUNT = 2
    for i in range(0, EXCEPTION_ENGINE_COUNT):
        eengine = ExceptionFilter(ALERT_MQ, SHOW_MQ, EXCEPTION_RULES)
        eengine.name = "EXCEPTION_ENGINE_{}".format(i)
        eengine.start()
        print("{} started".format(eengine.name))

    # GATHERERS - MALWARE REPORTING
    GATHERERS_COUNT = 1

    for i in range(0, GATHERERS_COUNT):
        gath = Gatherer(GATHERING_OPTIONS, MALWARE_MQ, CONTAINERS, PROCESS_TREE)
        gath.name = "GATHERER_{}".format(i)
        gath.start()
        print("{} started".format(gath.name))

    # WAIT FOR GUI END
    gp.join()

    # NO NICE EXIT FOR PROCESSESS :/ FOR NOW

if __name__ == '__main__':
    main()