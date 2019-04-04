import sys
import os
import zipfile
import json
import re

STONE_ENGINE_BASEDIR = os.path.dirname(sys.modules['stone_engine'].__file__)

class EvtxDescriptionManager():
    DESCRIPTIONS_DB_ARCHIVE = os.path.join(STONE_ENGINE_BASEDIR, "json", "db.zip")

    #@profile
    def __init__(self):
        self.database_loaded_flag = False
        self.providers = None

        #DEBUG
        #print("First time initalization of EvtxDescriptionManager ...")

        if os.path.exists(EvtxDescriptionManager.DESCRIPTIONS_DB_ARCHIVE):
            db_zip = zipfile.ZipFile(EvtxDescriptionManager.DESCRIPTIONS_DB_ARCHIVE, mode='r')

            #NO CRC32 ERRORS
            if db_zip.testzip() is None:
                namelist = db_zip.namelist()

                # PROPER FILES PRESENT
                if "files.json" in namelist and "providers.json" in namelist:
                    try:
                        self.providers = json.loads(db_zip.read("providers.json"), encoding='utf-8-sig')
                        # 4 TIMES SIZE IN MEMORY :/
                        self.files = json.loads(db_zip.read("files.json"), encoding='utf-8-sig')

                        if len(self.providers.keys()) > 0 and len(self.files.keys()) > 0:
                            self.database_loaded_flag = True
                    except json.decoder.JSONDecodeError:
                        pass
            db_zip.close()

    def is_database_loaded(self):
        return self.database_loaded_flag

    def provider_empty_change(self, prov_guid):
        if prov_guid == None:
            return "00000000-0000-0000-0000-000000000000"
        else:
            return prov_guid


    def resolve_double_percentage(self, value, provider_name, provider_guid, os_version, eid_list, version):
        if value is None:
            return ""

        # DETECTION OF %%
        if value.find('%%') != -1:
            prov_ids = self.__find_provider_ids(provider_name, provider_guid, os_version)


            regex = r"%%\d{1,7}"
            for match in re.finditer(regex, value[:], re.MULTILINE | re.IGNORECASE):
                matched_full = match.group()
                matched_nr = matched_full.lstrip("%")

                raw_parameter = self.__find_message_in_files(prov_ids['p'], [matched_nr,], version, os_version)

                #DIRTY
                try:
                    if not value is None:
                        value = value.replace(matched_full, raw_parameter.replace("\\r\\n", ""), 1)
                except:
                    return None



        return value

    def __yield_os_in_similarity_order(self, source_os):

        # 7/2008
        if source_os == 7:
            return [2008,8,2012,10,2016]
        elif source_os == 2008:
            return [7, 2012, 8, 2016, 10]
        # 8/2012
        elif source_os == 8:
            return [2012,7,2008,2016,10]
        elif source_os == 2012:
            return [8,2008,7,2016,10]
        # 10/2016
        elif source_os == 10:
            return [2016,2012,8,2008,7]
        elif source_os == 2016:
            return [10,2012,8,2008,7]

    def __determine_best_os(self, desired_os, possibilities_list):

        if desired_os in possibilities_list:
            return desired_os
        elif len(possibilities_list) == 1:
            return possibilities_list[0]
        else:
            for os_keys in possibilities_list:
                if desired_os in [int(x) for x in os_keys.split("_")]:
                    return os_keys

            # SIMILIAR OS
            for os_keys in possibilities_list:
                for next_os in self.__yield_os_in_similarity_order(desired_os):
                    if next_os in [int(x) for x in os_keys.split("_")]:
                        return os_keys

            # LAST CHANCE
            #raise AssertionError
            return possibilities_list[0]


    def __find_provider_ids(self, provider_name, provider_guid, os_version):
        out = {'m': [], 'p': []}

        if provider_guid is None:
            provider_guid = '00000000-0000-0000-0000-000000000000'

        prov_found = None
        for prov_name_iter in self.providers.keys():
            if provider_name.lower() == prov_name_iter.lower():
                prov_found = self.providers[prov_name_iter]
                break

        if prov_found:

            prov_guid_strip = provider_guid.strip("{}").lower()
            for prov_guid_iter in prov_found.keys():
                if prov_guid_iter.lower() == prov_guid_strip:
                    files_found = prov_found[prov_guid_strip]

                    if len(files_found['message_files_list']) > 0:
                        if len(files_found['message_files_list']) == 1:
                            first_key_name = list(files_found['message_files_list'].keys())[0]
                            out['m'] = files_found['message_files_list'][first_key_name]
                        else:
                            possibilities_list = list(files_found['message_files_list'].keys())
                            os_pick = self.__determine_best_os(os_version, possibilities_list)
                            out['m'] = files_found['message_files_list'][os_pick]

                    if len(files_found['params_files_list']) > 0:
                        if len(files_found['params_files_list']) == 1:
                            first_key_name = list(files_found['params_files_list'].keys())[0]
                            out['p'] = files_found['params_files_list'][first_key_name]
                        else:
                            possibilities_list = list(files_found['params_files_list'].keys())
                            os_pick = self.__determine_best_os(os_version, possibilities_list)
                            out['p'] = files_found['params_files_list'][os_pick]

                    break

        return out

    def __find_message_in_files(self, files_list, eid_list, version, os_version):

        for file_id in files_list:
            for eid in eid_list:

                #SPECIAL CASE
                if eid.find(";") != -1:
                    (type, value) = eid.split(";")
                    value = int(value)
                    if type == "lower_word":
                        matching_lower = list()
                        x = self.files[str(file_id)]['events_params']
                        for key in self.files[str(file_id)]['events_params'].keys():
                            if key == "range":
                                for r_double in self.files[str(file_id)]['events_params']["range"].keys():
                                    (r_start, r_end) = r_double.split("_")
                                    if value >= int(r_start) and value <= int(r_end):
                                        return self.files[str(file_id)]['events_params']["range"][r_double]

                            else:
                                lower_calc_eid = int(key) & 0x0000FFFF
                                if lower_calc_eid == value:
                                    matching_lower.append(key)

                        if len(matching_lower) == 1:
                            all_versions = self.files[str(file_id)]['events_params'][str(matching_lower[0])]
                            #pp.pprint(all_versions)

                            all_msg = dict()
                            # PICK BASED ON OS
                            if len(all_versions.keys()) > 1:
                                for ver in all_versions.keys():
                                    for os_key in all_versions[ver].keys():
                                        pass
                                        #if os

                            else:
                                if version in all_versions.keys():
                                    all_msg = all_versions[version]
                                else:
                                    all_msg = all_versions['0']

                            possibilities_list = list(all_msg.keys())
                            if len(possibilities_list) == 0:
                                x = 900
                            pick_os = self.__determine_best_os(os_version, possibilities_list)
                            return all_msg[pick_os]
                        elif len(matching_lower) == 0:
                            return None
                        else:
                            return None
                    else:
                        raise AssertionError

                else:
                    if str(eid) in self.files[str(file_id)]['events_params'].keys():
                        x = self.files[str(file_id)]['events_params'][str(eid)]
                        all_versions = self.files[str(file_id)]['events_params'][str(eid)]
                        #pp.pprint(all_versions)
                        all_msg = dict()
                        # PICK BASED ON OS
                        if len(all_versions.keys()) > 1:
                            for ver in all_versions.keys():
                                for os_key in all_versions[ver].keys():
                                    if str(os_version) in os_key.split("_"):
                                        all_msg = all_versions[ver][os_key]
                                        return all_msg

                        #FALLBACK
                        if version in all_versions.keys():
                            all_msg = all_versions[version]
                        else:
                            all_msg = all_versions['0']

                        possibilities_list = list(all_msg.keys())
                        pick_os = self.__determine_best_os(os_version, possibilities_list)
                        return all_msg[pick_os]
        return None


    def __find_positions_of_all_percent_with_number(self, raw_message):
        regex = r"(?<!%)%(\d{1,2})(![^!]*!)?"
        positions = list()

        for match in re.finditer(regex, raw_message, re.IGNORECASE):
            x = match
            positions.append(tuple([match.start(), match.group(), match.groups()[0], match.groups()[1]]))
        return sorted(positions, key= lambda x: x[0])

    def __expand_variable(self, variable):

        #SHRINK HEX
        if variable.startswith("0x"):
            manip_part = variable[2:]
            if len(manip_part.lstrip("0")) == 0:
                manip_part = "0"
            else:
                manip_part = manip_part.lstrip("0")
            variable = "0x{}".format(manip_part)

        return variable

    def __format_variable(self, variable, options):
        variable = self.__expand_variable(variable)

        # STRIP !xxxx!
        if type(options) is str:
            options = options.strip("!")

        if options is None:
            return variable
        elif options == "s":
            return variable
        elif options == "S":
            return variable
        else:
            raise AssertionError

    def __replace_variables(self, raw_message, variables):
        #TYPE_FIELD_CHARS = ['c', 'C', 'd', 'i', 'o', 'u', 'x', 'X', 'e', 'E', 'f', 'g', 'G', 'a', 'A', 'n', 'p', 's', 'S', 'Z']

        # SPECIAL CASE
        if raw_message.find("%") != -1:
            positions = self.__find_positions_of_all_percent_with_number(raw_message)
            #pp.pprint(positions)

            for info in positions:
                (start, matched_val, nr, options) = info
                try:
                    var_nr = list(variables.values())[int(nr)-1]
                    raw_message = raw_message.replace(matched_val, self.__format_variable(var_nr, options), 1)
                except IndexError:
                    raw_message = raw_message.replace(matched_val, "", 1)

        return raw_message

    def __preprocess_special_characters(self, raw_message):
        raw_message = raw_message.replace("%n", "\r\n")
        raw_message = raw_message.replace("%t", "\t")
        raw_message = raw_message.replace("%r", "\r")
        raw_message = raw_message.replace("\\n", "\n")
        raw_message = raw_message.replace("\\r", "\r")
        raw_message = raw_message.replace('\\"', '"')
        raw_message = raw_message.replace('\\\\', '\\')
        raw_message = raw_message.replace('%0', '')

        return raw_message


    def get_event_description(self, provider_name, provider_guid, os_version, variables, eid_list, version):
        (is_processed, variables) = variables
        prov_ids = self.__find_provider_ids(provider_name, provider_guid, os_version)
        raw_message = self.__find_message_in_files(prov_ids['m'], eid_list, version, os_version)
        #print("RAW MESSAGE: {}".format(raw_message))
        if raw_message is None:
            return raw_message

        raw_message = self.__preprocess_special_characters(raw_message)

        if is_processed:
            raw_message = self.__replace_variables(raw_message, variables)

        return raw_message
