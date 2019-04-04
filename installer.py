import sys
import os

# INSTALLER CODE -------------------------------------------------------------------------------------------

# PYTHON 2 EXIT
if (sys.version_info.major == 2):
    sys.stdout.write("This software is designed to run with Python 3. Your version is 2\n")
    sys.stdout.write("Best version will be Python 3.6 (x64)\n")
    os.system("pause")
    sys.exit(0)

import argparse
import shutil
import subprocess
from urllib import request
import zipfile
import mmap
import contextlib


try:
    import win32com.client
except ImportError:
    print("Perform first:")
    print("pip install -U -r requirements.txt")
    sys.exit(0)

#MODE
MODE_ED = 1
MODE_MALWARE = 2

#PATHS
INSTALLER_DIRECTORY = os.path.dirname(os.path.abspath(__file__)).replace("/", "\\")
ATTACK_MONITOR_PACKAGE_BASE = INSTALLER_DIRECTORY + "\\" + "attackmonitor"
ATTACK_MONITOR_PROGRAM_FILES = "C:\\Program Files\\Attack Monitor\\"
ATTACK_MONITOR_PROGRAM_FILES_MAIN_SCRIPT = ATTACK_MONITOR_PROGRAM_FILES + "madvr.py"
ATTACK_MONITOR_PROGRAM_FILES_SHORTCUT = ATTACK_MONITOR_PROGRAM_FILES + "Attack Monitor.lnk"
ATTACK_MONITOR_PROGRAM_FILES_EXCEPTIONS = ATTACK_MONITOR_PROGRAM_FILES + "config\\exceptions\\"

EXTRA_FILES = INSTALLER_DIRECTORY + "\\" + "extra_files" + "\\"
CURRENT_USER = os.getlogin()
CURRENT_USER_STARTUP_DIR = "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\".format(CURRENT_USER)
EXCEPTIONS_PREDEFINED_FILE = EXTRA_FILES + "exceptions\\win10.json"
POWERSHELL_ENHANCED_AUDIT_REG_FILE = EXTRA_FILES + "powershell\\powershell_audit.reg"

# SHORTCUTS
MENU_START_ALL_USERS_AM = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Attack Monitor" + "\\"
PYTHON3_FULL_PATH =  sys.executable
ICON_FILE = "C:\\Program Files\\Attack Monitor\\icon\\attack_156413_1280_aMk_icon.ico"

#SYSMON
SYSMON_BASE_DIR = EXTRA_FILES + "sysmon" + "\\"
SYSMON_ZIP_URL = "https://download.sysinternals.com/files/Sysmon.zip"
SYSMON_EXTRACTED_DIR = SYSMON_BASE_DIR + "extracted\\"
SYSMON_ZIP_DOWNLOADED = SYSMON_EXTRACTED_DIR + "Sysmon.zip"
SYSMON_64 = SYSMON_EXTRACTED_DIR + "Sysmon64.exe"
SYSMON_32 = SYSMON_EXTRACTED_DIR + "Sysmon.exe"
SYSMON_FAKE_NAME = SYSMON_EXTRACTED_DIR + "amg.exe"
SYSMON_DRIVER = "amg"
SYSMON_ED_CONFIG = SYSMON_BASE_DIR + "ed_sysmon.cfg"
SYSMON_MALWARE_CONFIG = SYSMON_BASE_DIR + "ed_sysmon.cfg"

# SCHEDULED TASK NAME
SCHEDULED_TASK_NAME = "Attack Monitor - Autostart"
XML_TEMPLATE_TASK_FILE = EXTRA_FILES + "task\\am_autostart_task.xml"
XML_FINAL_TASK_FILE = EXTRA_FILES + "task\\am_autostart_task_final.xml"
XML_FINAL_TASK_RELATIVE = "extra_files\\task\\am_autostart_task_final.xml"


def create_shortcut(lnk_out_path, target, parameters, working_dir, description, icon=None, run_as_admin=False, minimized=False):
    shell = win32com.client.Dispatch("WScript.Shell")
    shortcut = shell.CreateShortCut(lnk_out_path)
    shortcut.Targetpath = target
    shortcut.Arguments = '"{}"'.format(parameters)
    shortcut.Description = description
    shortcut.WorkingDirectory = working_dir
    if not icon is None:
        shortcut.IconLocation = icon
    if minimized:# 7 - Minimized, 3 - Maximized, 1 - Normal
        shortcut.WindowStyle = 7
    else:
        shortcut.WindowStyle = 1
    shortcut.save()

    if run_as_admin:
        with open(lnk_out_path, "r+b") as f:
            with contextlib.closing(mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE)) as m:
                m[0x15] = m[0x15] | 0x20 # Enable 6th bit = Responsible for Run As Admin
                #m.flush()

def is_os_64_bit():
    return os.path.exists("C:\\Program Files (x86)")

def ask_question(question):
    print(question + " [Yes/y/no/n]?")
    yes = {'yes', 'y', 'ye', ''}
    no = {'no', 'n'}

    while True:
        choice = input().lower()

        if choice in yes:
            return True
        elif choice in no:
            return False
        else:
            sys.stdout.write("Please respond with 'yes' or 'no'")

def ask_mode():
    print("Program mode: [1 or 2]" + "?")

    choice_dict = {
        1 : "Endpoint Detection (ED)",
        2 : "Malware analysis VM",
    }

    for key, val in choice_dict.items():
        print("{}) {}".format(key,val))

    while True:
        choice = input().lower()

        if choice == "1":
            return MODE_ED
        elif choice == "2":
            return MODE_MALWARE
        else:
            sys.stdout.write("Please respond with 1 or 2")

'''def ask_wifi_interface():
    print("On which network interface your tshark instance should capture for DNS requests?")

    NICE_NAMES = list()
    NICE_NAMES.append("any")

    while True:
        print("Interfaces availiable:")
        for i in range(0, len(NICE_NAMES)):
            print("{} {}".format(i, NICE_NAMES[i]))

        choice = input()
        try:
            interface_number = int(choice)
            return NICE_NAMES[interface_number]
        except:
            sys.stdout.write("Please respond with number of interface")'''

def action_install():
    print("Installing Attack Monitor")
    if not os.path.exists(ATTACK_MONITOR_PACKAGE_BASE):
        print("attackmonitor\\ package not found in script directory")
        sys.exit(-1)

    if os.path.isdir(ATTACK_MONITOR_PROGRAM_FILES):
        if len(os.listdir(ATTACK_MONITOR_PROGRAM_FILES)) > 0:
            print("Attack monitor is already installed in: {}".format(ATTACK_MONITOR_PROGRAM_FILES))
            sys.exit(0)

    try:
        print("Installing in: {} ...".format(ATTACK_MONITOR_PROGRAM_FILES))
        shutil.copytree(ATTACK_MONITOR_PACKAGE_BASE, ATTACK_MONITOR_PROGRAM_FILES)
    except PermissionError:
        print("Are you running with Administrator privileges? Only Administrator can write to Program Files.")
        sys.exit(0)

    print("Files copied sucessfully.")

    mode = ask_mode()

    NET_INTERFACE = "first"
    if mode == MODE_MALWARE:
        print("Your network interface in configuration file was set to 'any'")
        print("Change it later to appropiate interface based on extact names from [Control Panel\\Network and Internet\\Network Connections]")
        os.system("pause")

    print("Applying config file")
    CONFIG_LINES = []
    with open("C:\\Program Files\\Attack Monitor\\config\\attack_monitor.cfg", "r", encoding="utf-8") as f:
        CONFIG_LINES = f.readlines()

    with open("C:\\Program Files\\Attack Monitor\\config\\attack_monitor.cfg", "w", encoding="utf-8") as f:
        for line in CONFIG_LINES:
            #ED
            if mode == MODE_ED:
                line = line.replace("PLACEHOLDER1", "False")
                line = line.replace("PLACEHOLDER2", 'Only relevant for malware mode')
            #MALWARE
            else:
                line = line.replace("PLACEHOLDER1", "True")
                line = line.replace("PLACEHOLDER2", NET_INTERFACE)

            f.write(line)

    print("Creating shortcut in Attack Monitor directory")
    create_shortcut(ATTACK_MONITOR_PROGRAM_FILES_SHORTCUT, PYTHON3_FULL_PATH, ATTACK_MONITOR_PROGRAM_FILES_MAIN_SCRIPT, ATTACK_MONITOR_PROGRAM_FILES, "Attack Monitor", ICON_FILE, run_as_admin=True, minimized=False)

    menu_start_shortcut_create = ask_question("Do you want to create shortcut in menu start for all users?")
    if menu_start_shortcut_create:
        print("Creating shortcut in menu start (for all users) ...")
        os.makedirs(MENU_START_ALL_USERS_AM, exist_ok=True)
        shutil.copy(ATTACK_MONITOR_PROGRAM_FILES_SHORTCUT, MENU_START_ALL_USERS_AM)

    start_with_windows = ask_question("Do you want to automatically lanuch Attack Monitor on logon of current user (via Scheduled Task) ({}) ?".format(CURRENT_USER))
    if start_with_windows:
        print("Adding autostart entry to Menu Start Startup folder")

        # DETERMINE WHO I AM?
        result = subprocess.run(["whoami"], stdout=subprocess.PIPE, encoding=sys.getdefaultencoding(), errors="ignore")
        if result.returncode == 0:
            whoami = result.stdout.replace("\r", "").replace("\n", "")
            if len(whoami) > 1:
                # Read template
                with open(XML_TEMPLATE_TASK_FILE, "r", encoding='utf-16') as template:
                    TEMPLATE_LINES = template.readlines()

                # Write modified template
                with open(XML_FINAL_TASK_FILE, "w", encoding='utf-16') as final:
                    for line in TEMPLATE_LINES:
                        final.write(line.replace("WHOAMIII", whoami))

                print("Adding scheduled task ...")
                args = ["schtasks.exe", '/create', "/xml", XML_FINAL_TASK_RELATIVE, "/tn", SCHEDULED_TASK_NAME]
                subprocess.run(args)
            else:
                print("Error when getting current user")

        else:
            print("Error when getting current user")

        '''LEVEL1:
        cmd.exe /s /c "start /min calc.exe ^& exit"
        
        LEVEL2:
        cmd.exe /s /K "title Attack Monitor & "C:\Program Files\Attack Monitor\Attack Monitor.lnk""
        
        LEVEL 1 -2 COMBINED:
        cmd.exe /s /c "start /min cmd.exe /s /K "title Attack Monitor & "C:\Program Files\Attack Monitor\Attack Monitor.lnk""
         ^& exit"'''

    print("Installation finished.")

def action_sysmon():
    install_sysmon = ask_question("Do you want to install/download pre-configured Sysmon?")

    if install_sysmon:
        # SYSMON NEEDS TO BE DOWNLOADED
        if not os.path.isfile(SYSMON_ZIP_DOWNLOADED):

            try:
                print("Downloading Sysmon ...")
                sysmon_zip_content = request.urlopen(SYSMON_ZIP_URL)
                if not sysmon_zip_content.getcode() == 200:
                    raise AssertionError
                with open(SYSMON_ZIP_DOWNLOADED, "wb") as smon:
                    print("Saving Sysmon.zip")
                    smon.write(sysmon_zip_content.read())

            except Exception as e:
                print(e)
                print("Cannot download Sysmon from URL: {}".format(SYSMON_ZIP_URL))
                print("Download Sysmon.zip manually and put in: {}".format(SYSMON_EXTRACTED_DIR))
                print("Then re-run installer.")

        if os.path.isfile(SYSMON_ZIP_DOWNLOADED):
            # EXTRACT ZIP
            if not os.path.exists(SYSMON_32) or os.path.exists(SYSMON_64):
                print("Extracting Sysmon.zip ...")
                zip_ref = zipfile.ZipFile(SYSMON_ZIP_DOWNLOADED, 'r')
                zip_ref.extractall(SYSMON_EXTRACTED_DIR)
                zip_ref.close()

            # ALREADY EXTRACTED
            if os.path.exists(SYSMON_32) and os.path.exists(SYSMON_64):
                SYSMON_TAKEN = ""

                if is_os_64_bit():
                    SYSMON_TAKEN = SYSMON_64
                else:
                    SYSMON_TAKEN = SYSMON_32

                # FAKE NAME - DOESN'T WORK
                #shutil.copy(SYSMON_TAKEN, SYSMON_FAKE_NAME)

                mode = ask_mode()
                SYSMON_CONFIG = ""
                if mode == MODE_ED:
                    SYSMON_CONFIG = SYSMON_ED_CONFIG
                else:
                    SYSMON_CONFIG = SYSMON_MALWARE_CONFIG
                print("Config choosen: {}".format(os.path.basename(SYSMON_CONFIG)))

                args = [SYSMON_TAKEN, ]
                args += "-accepteula -n -d {} -i".format(SYSMON_DRIVER).split(" ")
                args.append(SYSMON_CONFIG)

                print("Installing Sysmon (Service: {} | Driver: {})".format(os.path.basename(SYSMON_64), SYSMON_DRIVER))
                subprocess.run(args)

            else:
                print("Sysmon.zip extraction error. Extract manually")
        else:
            print("Sysmon.zip not present")

def action_change_audit():

    policies_list = [("Account Management - Security Group Management", '/set /subcategory:{0CCE9235-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Account Management - User Account Management",  '/set /subcategory:{0CCE9235-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Detailed Tracking - DPAPI Activity", '/set /subcategory:{0CCE922D-69AE-11D9-BED3-505054503030} /success:enable /failure:enable' ),
                         ("Logon/Logoff - Account Lockout", '/set /subcategory:{0CCE9217-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Logon/Logoff - Logon", '/set /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Logon/Logoff - Other Logon/Logoff Events", '/set /subcategory:{0CCE921C-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Account Management - User Account Management", '/set /subcategory:{0CCE9235-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Object Access - Filtering Platform Packet Drop", '/set /subcategory:{0CCE9225-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Object Access - Filtering Platform Connection", '/set /subcategory:{0CCE9226-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Object Access - Detailed File Share", '/set /subcategory:{0CCE9244-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Object Access - File Share", '/set /subcategory:{0CCE9224-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Object Access - Other Object Access Events", '/set /subcategory:{0CCE9227-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ]

    print("For following policies:")
    for policy_name, policy_cmd in policies_list:
        print("* {} : to audit success and failures".format(policy_name))

    change_policies = ask_question("Do you agree to change audit for them?")
    if change_policies:
        for policy_name, policy_cmd in policies_list:
            print("-> Changing: {}".format(policy_name))
            args = ["auditpol.exe"]
            args += policy_cmd.split(" ")
            subprocess.run(args, shell=True)
            print("")

def action_exceptions():
    if not os.path.isdir(ATTACK_MONITOR_PROGRAM_FILES_EXCEPTIONS):
            print("First install Attack monitor with command:")
            print("python installer.py install")
            sys.exit(0)
    else:
            print("Copying predefined exceptions (created based on Win 10 common events) ...")
            shutil.copy(EXCEPTIONS_PREDEFINED_FILE, ATTACK_MONITOR_PROGRAM_FILES_EXCEPTIONS + "exceptions.json")
            print(" => Done")

def action_psaudit():
    print("You need Powershell 5 at least to enhance audit.")
    print("Your current version of PowerShell won't be checked. Assuming you had PowerShell 5.")
    print("")
    import_ps = ask_question("For Powershell 5 do you want to enable:\n* ModuleLogging\n* ScriptBlockLogging\n* Transcription to C:\\pslog")

    if import_ps:
        print("Import registry file with new settings ...")
        subprocess.run(["reg.exe", "import", POWERSHELL_ENHANCED_AUDIT_REG_FILE])
        print("=> Done")
    else:
        print("=> Skip")



def help():
    print("Attack Monitor - installer")
    print("Usage: python installer.py <action>")
    print("")
    print("Possible actions:")
    print("  install - Install Attack Monitor to C:\\Program Files\\Attack Monitor")
    print("  sysmon - Install (and download) Sysmon with predefined configuration file")
    print("  auditpol - Enable more events of Windows Audit (Evtx) with auditpol.exe")
    print("  exceptions - Install predefined exceptions - so initial learning is done")
    print("  psaudit - (Require PowerShell 5) Enhance audit by enabling: ModuleLogging, ScriptBlockLogging and Transcription")

def main():
    parser = argparse.ArgumentParser(description='Attack Monitor installer')
    parser.add_argument('action', nargs='*', help="")
    args = parser.parse_args()
    actions_list = args.action

    #Default action install
    if len(actions_list) == 0:
        help()
    else:
        action = actions_list[0]
        if action == "install" or action == "instal":
            action_install()
        elif action == "sysmon":
            action_sysmon()
        elif action == "auditpol":
            action_change_audit()
        elif action == "exceptions":
            action_exceptions()
        elif action == "psaudit":
            action_psaudit()
        else:
            parser.error("Unknown action: {}".format(action))


if __name__ == "__main__":
   main()