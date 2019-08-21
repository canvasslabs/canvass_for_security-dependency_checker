#############################################################################
# Copyright 2019 Jae Woo Park                                               #
#                                                                           #
# Licensed under the Apache License, Version 2.0 (the "License");           #
# you may not use this file except in compliance with the License.          #
# You may obtain a copy of the License at                                   #
#                                                                           #
# http://www.apache.org/licenses/LICENSE-2.0                                #
#                                                                           #
# Unless required by applicable law or agreed to in writing, software       #
# distributed under the License is distributed on an "AS IS" BASIS,         #
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  #
# See the License for the specific language governing permissions and       #
# limitations under the License.                                            #
#############################################################################

from utils import get_datetime
import datetime
import os
from collections import OrderedDict, defaultdict
from exit_handler import build_output


def get_report_id(outputs):
    '''
    Generates report id using timestamp and package manager name
    This id is used in a report and in output file name
    '''

    timestamp = outputs[0].get("start_time")
    package_managers = "_".join([output.get("package_manager") for output in outputs])

    st = datetime.datetime.fromtimestamp(timestamp).strftime('%Y%m%d_%H%M%S')
    report_id = "_".join([package_managers.lower(), "dependency_checker", st])
    return report_id


def make_summary_report(output):
    '''
    Generates a summary report for console output
    '''
    package_path = output.get("package_path")
    duration = output.get("duration")
    package_manager = output.get("package_manager")
    start_time = output.get("start_time")

    rows = ""
    title = "Dependency checker summary report:\n"
    rows += title
    rows += "{}\t{}\n".format("Date & Time:", get_datetime(start_time))
    rows += "{}\t{}\n".format("Duration:", duration)
    rows += "{}\t{}\n".format("Input path:", package_path)
    rows += "{}\t{}\n".format("Package manager used to find dependencies:", package_manager)

    rows += "\n"
    return rows


def make_library_report(output):
    '''
    Generates a library report for console output
    '''
    vulns = output.get("vulns")
    dbcoordinates = output.get("dbcoordinates")
    if dbcoordinates:
        lib_cnt = len(dbcoordinates)
    else:
        lib_cnt = 0

    rows = ""
    rows += "{}\t{}\n".format("Total # of dependencies (direct or transitive):", lib_cnt)
    rows += "{}\t{}\n".format("Total # of dependencies (direct or transitive) with vulnerabilities:",
                              get_num_of_vuln_packages(vulns))
    return rows


def make_vuln_report(output):
    '''
    Generates a vulnerability report for console output
    '''
    vulns = output.get("vulns")
    cves = output.get("cves")
    package_manager = output.get("package_manager")
    package_manager = package_manager.lower()

    rows = ""
    title = "Total # of vulnerabilities found in dependencies (direct or transitive):"

    if vulns is None or len(vulns) == 0:
        rows += "{}\t{}\n".format(title, str(0))
        return rows

    if cves is None or len(cves) == 0:
        rows += "{}\t{}\n".format(title, str(0))
        return rows

    if package_manager in ["maven", "gradle"]:
        header = "{}\t{}\t{}\n".format("CVE-ID", "Severity(CVSS V2)", "Vulnerable dependency")
    elif package_manager in ["npm", "bower", "yarn"]:
        header = "{}\t{}\t{}\n".format("CVE-ID", "Severity(CVSS V2)", "Vulnerable dependency")
    else:
        header = "{}\t{}\t{}\n".format("CVE-ID", "Severity(CVSS V2)", "Vulnerable dependency")

    merged = merge_vulns_and_cves(vulns, cves)
    rows += "{}\t{}\n".format(title, str(len(list(cves.keys()))))
    rows += "\n"

    rows += "List of vulnerabilities found in dependencies (direct or transitive):\n\n"
    rows += header

    # There could be case when cvss2 base score does not exists. Then use 0 for cvss2_base_score.
    for doc in sorted(merged, key=lambda x: float(x.get('cvss2_base_score', -1)), reverse=True):
        coord_full = doc.get("coord_full")
        coordinate = format_coord_full_for_report(coord_full, package_manager)
        cvss2_severity = doc.get("cvss2_severity", "")
        cve_id = doc.get("cve_id")

        row = "{}\t{}\t{}\n".format(cve_id, cvss2_severity, coordinate)
        rows += row

    rows += "\n"
    return rows


def get_warnings_from_outputs(outputs):
    '''
    Generates warning reports from outputs
    '''
    prefix_idx = 3
    text_report = ""

    for idx, output in enumerate(outputs, 1):
        warning_message = output.get("warning_message")
        error_message = output.get("error_message")
        package_manager = output.get("package_manager")

        error_flag = False
        if error_message:
            error_flag = True

        if warning_message and error_message:
            messages = warning_message + "\n" + error_message
        elif warning_message and not error_message:
            messages = warning_message
        elif not warning_message and error_message:
            messages = error_message
        else:
            messages = None

        if messages:
            text_report += "{}.{}. Warning or error messages from {} dependency checker:\n".format(prefix_idx, idx, package_manager)

            if error_flag:
                text_report += "Due to the following error, {} dependecy checker could not run.\n\n".format(package_manager)
            else:
                text_report += "\n"

            text_report += "{}.{}.1. {}\n\n".format(prefix_idx, idx, messages)
        else:
            text_report += "{}.{}. No warning or error messages from {} dependecy checker\n\n".format(prefix_idx, idx, package_manager)
    return text_report


def make_text_report_from_output(outputs):
    '''
    Using dependency checker output, generate a text report to write to a file
    '''
    text_report = ""

    text_report += "Canvass for dependency checker\n\n"
    text_report += "Date and time:\t{}\n\n\n".format(get_datetime(outputs[0].get("start_time")))

    text_report += "Table of Contents:\n"
    text_report += "1. Description of input\n"
    text_report += "2. Package manager used to find dependencies (direct or transitive)\n"
    text_report += "3. Warnings or errors encountered\n"
    text_report += "4. Summary of dependencies (direct or transitive) and their vulnerabilities\n"
    text_report += "5. Details of dependencies (direct or transitive) with vulnerabilities\n"
    text_report += "6. Details of vulnerabilities found in dependencies (direct or transitive)\n"
    text_report += "7. Details of dependencies (direct or transitive)\n"
    text_report += "\n\n"

    text_report += "1. Description of input:\n\n"
    text_report += "1.1. input directory path:\t{}\n".format(outputs[0].get("package_path"))
    text_report += "\n\n"

    text_report += "2. Package manager used to find dependencies (direct or transitive):\t{}\n".format(
        ",\t".join([output.get("package_manager") for output in outputs if output.get('package_manager') is not None]))
    text_report += "\n\n"

    text_report += "3. Warnings or errors encountered\n\n"
    text_report += get_warnings_from_outputs(outputs)
    text_report += "\n"

    text_report += "4. Summary of dependencies (direct or transitive) and their vulnerabilities:\n"
    text_report += make_summary_report_for_text_report(outputs)
    text_report += "\n"

    text_report += "5. Details of dependencies (direct or transitive) with vulnerabilities\n"
    text_report += make_vulnerable_libraries_and_versions_text_report(outputs)
    text_report += "\n"

    text_report += "6. Details of vulnerabilities found in dependencies (direct or transitive)\n"
    text_report += make_detailed_vuln_report_text_report(outputs)
    text_report += "\n"

    text_report += "7. Details of dependencies (direct or transitive)\n"
    text_report += make_libraries_found_text_report(outputs)
    return text_report


def count_all_vuln_dependencies_in_outputs(outputs):
    all_vuln_coordfull = set()
    for output in outputs:
        vulns = output.get("vulns")
        if vulns:
            for doc_id, vuln in vulns.items():
                vuln_coordfull = vuln.get("coord_full")
                all_vuln_coordfull = all_vuln_coordfull.union(set([vuln_coordfull]))

    vuln_lib_cnt = len(all_vuln_coordfull)
    return vuln_lib_cnt


def count_all_cves_in_outputs(outputs):
    all_cve_ids = set()
    for output in outputs:
        cves = output.get("cves")
        if cves:
            for doc_id, cve in cves.items():
                cve_id = cve.get('cve_id')
                all_cve_ids = all_cve_ids.union(set([cve_id]))

    cves_cnt = len(all_cve_ids)
    return cves_cnt


def count_all_dependencies_in_outputs(outputs):
    all_dbcoordinates = set()
    for output in outputs:
        dbcoordinates = output.get("dbcoordinates")
        if dbcoordinates:
            all_dbcoordinates = all_dbcoordinates.union(set(dbcoordinates))

    lib_cnt = len(all_dbcoordinates)
    return lib_cnt


def make_summary_report_for_text_report(outputs):
    '''
    Generates a summary report for text report
    '''

    outputs = get_outputs_with_pass_code(outputs)

    if len(outputs) == 0:
        return "No result available due to error(s) mentioned in section 3\n"

    lib_cnt = count_all_dependencies_in_outputs(outputs)
    cves_cnt = count_all_cves_in_outputs(outputs)
    vuln_lib_cnt = count_all_vuln_dependencies_in_outputs(outputs)

    text_report = "\n"
    text_report += "{} {}\t{}\n".format("4.1.",
                                        "Total number of dependencies (direct or transitive):",
                                        str(lib_cnt))
    text_report += "{}\n\n".format("Please see section 7 for more details.")

    text_report += "{} {}\t{}\n".format("4.2.",
                                        "Total number of dependencies (direct or transitive) with vulnerabilities:",
                                        str(vuln_lib_cnt))
    text_report += "{}\n\n".format("Please see section 5 for more details.")

    text_report += "{} {}\t{}\n".format("4.3.",
                                        "Total number of vulnerabilities found in dependencies (direct or transitive):",
                                        str(cves_cnt))
    text_report += "{}\n\n".format("Please see section 6 for more details.")

    return text_report


def make_vulnerable_libraries_and_versions_text_report(outputs):
    '''
    Report on vulnerable libraries and versions
    '''
    # Get only outputs with pass code
    outputs = get_outputs_with_pass_code(outputs)

    # Case when all outputs have fail pass code
    if len(outputs) == 0:
        return "No result available due to error(s) mentioned in section 3\n"

    # Case when there is any output with pass code
    all_coordfulls = set()
    for output in outputs:
        vulns = output.get("vulns")
        coordfulls = get_coord_fulls_from_vulns(vulns)
        all_coordfulls = all_coordfulls.union(coordfulls)

    # Make report text
    report = "\n"
    prefix_index = "5"
    report += "{}.1. Total number of dependencies (direct or transitive) with vulnerabilities:\t{}\n\n".format(
        prefix_index, str(len(all_coordfulls)))

    for idx_output, output in enumerate(outputs, 1):
        vulns = output.get("vulns")
        pkgmanager_name = output.get("package_manager")

        coord_fulls = get_coord_fulls_from_vulns(vulns)

        report += "{}.1.{}. Total number of dependencies (direct or transitive) with vulnerabilities from {}:\t{}\n\n".format(
            prefix_index, idx_output, pkgmanager_name, len(coord_fulls))
        report += "{}.1.{}.1. List of dependencies (direct or transitive) with vulnerabilities from {}:\n\n".format(prefix_index, idx_output, pkgmanager_name)

        for idx_coord, coord_full in enumerate(coord_fulls, 1):

            coordinate = format_coord_full_for_report(coord_full, pkgmanager_name)
            report += "{}.1.{}.1.{}. {}\n".format(prefix_index, idx_output, idx_coord, coordinate)

        if not coord_fulls:
            report += "{}.1.{}.1.1. No vulnerable dependencies found from {}\n".format(prefix_index, idx_output, pkgmanager_name)

        report += "\n"
    return report


def get_outputs_with_pass_code(outputs):
    '''
    Discard any output with error code 4
    and keep only the passing outputs
    '''
    passing_outputs = []
    for output in outputs:
        code = output.get('code')

        # code 4 is critical error that dependency checker couldn't comlete scanning
        if code == 4:
            continue
        else:
            passing_outputs.append(output)
    return passing_outputs


def get_coord_fulls_from_vulns(vulns):
    coordfulls = set()
    if vulns:
        for key, vuln in vulns.items():
            coordfull = vuln.get("coord_full")
            coordfulls.add(coordfull)
    else:
        return set()

    return coordfulls


# def get_all_pkgmanager_names_from_coord_fulls(coord_fulls):
#     '''
#     Get unique package manager names from all full coordinate strings
#     '''
#     return sorted(list(set([coord_full.split(":")[0] for coord_full in coord_fulls])))


# def filter_coordinates_by_pkgmanager_name(coord_fulls, pkgmanager_name):
#     '''
#     Filter full coordinate string by package manager name
#     '''
#     return sorted(list(filter(lambda x: (x.split(":")[0]) == pkgmanager_name, coord_fulls)))


# def maven_library_format_description():
#     return "Each library is in a format of \"GroupID:ArtifactID:Version\"."


# def npm_library_format_description():
#     return "Each library is in a format of \"PackageName:Version\"."


def make_detailed_vuln_report_text_report(outputs):
    '''
    Converts detailed vuln report in dict format to text
    '''

    all_cves_cnt = count_all_cves_in_outputs(outputs)

    outputs = get_outputs_with_pass_code(outputs)

    if len(outputs) == 0:
        return "No result available due to error(s) mentioned in section 3\n"

    text_report = "\n"
    prefix_index = "6"
    text_report += "{}.1. Total number of vulnerabilities found in dependencies (direct or transitive):\t{}\n\n".format(prefix_index, all_cves_cnt)

    for idx_output, output in enumerate(outputs, 1):

        pkgmanager_name = output.get("package_manager")
        index = 1
        cves = output.get("cves")

        if cves is None:
            cves_cnt = 0
            text_report += "{}.1.{}. Total number of vulnerabilities found in dependencies (direct or transitive) from {}:\t{}\n\n".format(
                prefix_index, idx_output, pkgmanager_name, cves_cnt)
            text_report += "{}.1.{}.1. List of vulnerabilities found in dependencies (direct or transitive) from {}:\n\n".format(
                prefix_index, idx_output, pkgmanager_name)
            text_report += "{}.1.{}.1.1. No vulnerabilities found from {}\n\n".format(prefix_index, idx_output, pkgmanager_name)
            continue

        cves_cnt = len(cves.keys())
        coord_based_merged = make_coord_based_merged_vulns_and_cves(output)

        text_report += "{}.1.{}. Total number of vulnerabilities found in dependencies (direct or transitive) from {}:\t{}\n\n".format(
            prefix_index, idx_output, pkgmanager_name, cves_cnt)
        text_report += "{}.1.{}.1. List of vulnerabilities found in dependencies (direct or transitive) from {}:\n\n".format(
            prefix_index, idx_output, pkgmanager_name)


        # Sorts using coord_full
        for coord_full, docs in sorted(coord_based_merged.items(), key=lambda x: x[0]):

            coordinate = format_coord_full_for_report(coord_full, pkgmanager_name)
            if coordinate is None:
                continue

            sub_index = 1
            text_report += "{}.1.{}.1.{}. Number of vulnerabilities in dependency, {}:\t{}\n\n".format(
                prefix_index, idx_output, index, coordinate, str(len(docs)))

            for doc in sorted(docs, key=lambda x: float(x.get("cvss2_base_score", -1)), reverse=True):
                cve_id = doc.get("cve_id")

                cvss2_severity = doc.get('cvss2_severity')
                cvss2_base_score = doc.get("cvss2_base_score")
                if (cvss2_severity is not None) and (cvss2_base_score is not None):
                    text_report += "{}.1.{}.1.{}.{}. {}\nCVSS2 severity:\t{}\nCVSS2 score:\t{}\n".format(
                        prefix_index, idx_output, index, sub_index, cve_id, cvss2_severity, cvss2_base_score)

                text_report += "Description:\t"
                description = doc.get('description')
                if description is not None and len(description) > 0:
                    text_report += description[0] + "\n"

                cve_url = doc.get("cve_url")
                if cve_url is not None and len(cve_url) > 0:
                    text_report += "URL:\t"
                    text_report += cve_url + "\n"

                text_report += "\n"
                sub_index += 1

            index += 1

    return text_report


def format_coord_full_for_report(coord_full, pkgmanager_name):
    comps = coord_full.split(":")

    if len(comps) > 4:
        if pkgmanager_name.lower() in ["maven", "gradle"]:
            names = "group:\t\"{}\"\tname:\t\"{}\"\tversion:\t\"{}\"".format(comps[1], comps[2], comps[3])
            return names

        elif pkgmanager_name.lower() in ['npm', 'bower', 'yarn']:
            names = "name:\t\"{}\"\tversion:\t\"{}\"".format(comps[1], comps[3])
            return names
        else:
            return None
    else:
        return None


def make_detailed_vuln_report_data(vulns, cves):
    '''
    Collect data to display on text report
    '''
    if vulns is None or len(vulns) == 0:
        return None

    if cves is None or len(cves) == 0:
        return None

    output = OrderedDict()
    merged = merge_vulns_and_cves(vulns, cves)

    # There could be case when cvss2 base score does not exists. Then use 0 for cvss2_base_score.
    for doc in sorted(merged, key=lambda x: float(x.get('cvss2_base_score', -1)), reverse=True):
        cve_url = doc.get("cve_url")
        pkgversion_name = doc.get("pkgversion_name")
        cvss2_severity = doc.get("cvss2_severity")
        cvss2_base_score = doc.get("cvss2_base_score")
        description = doc.get("description")
        cve_id = doc.get("cve_id")

        if cve_id not in output:
            output[cve_id] = {"cve_id": cve_id,
                              "pkgversion_name": set([pkgversion_name]),
                              "cvss2_severity": cvss2_severity,
                              "cvss2_base_score": cvss2_base_score,
                              "description": description,
                              "cve_url": cve_url}
        else:
            doc = output.get(cve_id)
            doc["pkgversion_name"].add(pkgversion_name)

    return output


def make_libraries_found_text_report(outputs):
    '''
    Report on a list of libraries found from scanning (coordinates within the scope)
    '''

    prefix_index = "7"
    all_dependencies_cnt = count_all_dependencies_in_outputs(outputs)

    outputs = get_outputs_with_pass_code(outputs)

    if len(outputs) == 0:
        return "No result available due to error(s) mentioned in section 3\n"

    report = "\n"
    report += "{}.1. Total number of dependencies (direct or transitive):\t{}\n\n".format(prefix_index, str(all_dependencies_cnt))

    for idx_output, output in enumerate(outputs, 1):
        dbcoordinates = output.get("dbcoordinates")
        pkgmanager_name = output.get("package_manager")

        scanned_coordinates = set()

        if dbcoordinates:
            for dbcoordinate in dbcoordinates:
                coordinate = format_coord_full_for_report(dbcoordinate, pkgmanager_name)
                scanned_coordinates.add(coordinate)

        report += "{}.1.{}. Total number of dependencies (direct or transitive) from {}:\t{}\n\n".format(
            prefix_index, idx_output, pkgmanager_name, str(len(scanned_coordinates)))
        report += "{}.1.{}.1. List of dependencies (direct or transitive) from {}:\n".format(prefix_index, idx_output, pkgmanager_name)

        if not dbcoordinates:
            report += "\n"
            report += "{}.1.{}.1.1. No dependencies found\n".format(prefix_index, idx_output)
            continue

        if pkgmanager_name.lower() == "maven":
            scopes_excluded = output.get("scopes_excluded", ["Error: Excluded scope names missing"])
            maven_configurations = ", ".join(sorted(scopes_excluded))
            report += "Dependency checker looks for vulnerabilities in dependencies from all scopes except \"{}\" scope for maven projects.\n".format(
                maven_configurations)
        elif pkgmanager_name.lower() == "gradle":
            scopes_included = output.get("scopes_included")
            gradle_configurations = ", ".join(sorted(scopes_included))
            report += "Dependency checker looks for vulnerabilities in dependencies that are in following scopes for gradle projects: \"{}\".\n".format(
                gradle_configurations)
        elif pkgmanager_name.lower() in ["npm", "bower", "yarn"]:
            report += "Dependency checker looks for vulnerabilities in dependencies that are in following scopes for {} projects: \"{}\".\n".format(
                pkgmanager_name, "production (dependencies), development (devDependencies)")

        report += "\n"
        for idx, coordinate in enumerate(scanned_coordinates, 1):
            report += "{}.1.{}.1.{}. {}\n".format(prefix_index, idx_output, idx, coordinate)

        report += "\n"
    return report


def merge_vulns_and_cves(vulns, cves):
    '''
    Merge some of vulnerability data and all cve data into one dictionary
    '''
    output = []

    for solr_id, vuln in vulns.items():
        cve_id = get_cve_id_from_vuln(vuln)
        cve = cves.get(cve_id)

        # If cve does not exists for this vuln, skip it.
        if cve is None:
            continue

        doc = {}
        doc = cve.copy()
        doc['pkgversion_name'] = vuln.get("pkgversion_name")
        doc['coord_full'] = vuln.get("coord_full")

        # maybe create a formatted coordinate here
        output.append(doc)

    return output


def make_coord_based_merged_vulns_and_cves(output):

    vulns = output.get("vulns")
    cves = output.get("cves")

    if vulns is None or len(vulns) == 0:
        return None

    if cves is None or len(cves) == 0:
        return None

    output = defaultdict(list)
    for solr_id, vuln in vulns.items():
        cve_id = get_cve_id_from_vuln(vuln)
        cve = cves.get(cve_id)

        # If cve does not exists for this vuln, skip it.
        if cve is None:
            continue

        doc = {}
        doc = cve.copy()
        doc['pkgversion_name'] = vuln.get("pkgversion_name")
        coord_full =  vuln.get("coord_full")

        if coord_full is not None:
            doc['coord_full'] = coord_full
            output[coord_full].append(doc)

    return output


def get_path_to_reports_folder():
    '''
    Create reports dir where this report.py module is.
    Returns the path to the reports dir.
    '''
    current_module_dir = os.path.dirname(os.path.abspath(__file__))
    reports_dir_path = os.path.join(current_module_dir, "reports")
    if not os.path.exists(reports_dir_path):
        os.makedirs(reports_dir_path)
    return reports_dir_path


def get_path_to_report_file(report_id, report_dir_path):
    '''
    Create path to report file using report id and report dir path
    '''
    filename = report_id + ".txt"
    output_filepath = os.path.join(report_dir_path, filename)
    return output_filepath


def write_report_to_file(output_filepath, contents):
    '''
    Writes text report to reports folder
    '''
    with open(output_filepath, 'w') as f:
        f.write(contents)
        return output_filepath


# def report_for_testing(vulns):
#     """ Generates a report_for_testing"""

#     print("[Report - Testing purpose only. To be removed.]")

#     if vulns is None:
#         return ""

#     rows = ""
#     for solr_id, vuln in vulns.items():
#         cve_id = get_cve_id_from_vuln(vuln)
#         title = get_title_from_vuln(vuln)
#         row = "{:<40}{:<70}{}\n".format(cve_id, title, get_pkgversion_name_from_vuln(vuln))
#         rows += row
#     return rows


def get_num_of_vuln_packages(vulns):
    '''
    Counts number of unique full coords from vulns.
    '''
    if vulns is None or len(vulns) == 0:
        return 0

    unique_vuln_packages = set()
    for solr_id, vuln in vulns.items():
        full_coord = vuln.get("coord_full")
        if full_coord is not None:
            unique_vuln_packages.add(full_coord)
    return len(unique_vuln_packages)


# def get_total_num_of_libraries(dependencies):
#     '''
#     Input: For maven, dependencies excluding provided or test scope
#     output: Number of unique dependencies excluding provided or test scope
#     and package itself
#     '''
#     if dependencies is None or len(dependencies) == 0:
#         return 0
#     else:
#         return len(dependencies)


def get_cve_id_from_vuln(vuln):
    """
    Returns CVE ID from vulnerability document
    When there is no CVE, returns "No-CVE" string

    """
    return vuln.get('cve_id', "No-CVE")


def get_title_from_vuln(vuln):
    """
    Returns CVE ID from vulnerability document
    When there is no title, returns "No-title" string

    """
    return vuln.get('title', "No-Title")


def get_pkgversion_name_from_vuln(vuln):
    """
    Returns package name with version name
    """
    return vuln.get('pkgversion_name', 'Version info not available')


# def get_cvss_severity_from_cve(cve):
#     '''
#     Returns cvss severity.
#     if cvss3 and cvss2 both exists, return cvss3.
#     If only one of them exists, return the existing one.
#     if none of them exists, return a empty string
#     '''
#     cvss2 = cve.get("cvss2_severity")
#     cvss3 = cve.get("cvss3_severity")

#     if cvss2 is None and cvss3 is None:
#         return ""
#     elif cvss2 is None and cvss3 is not None:
#         return cvss3 + " (V3)"
#     elif cvss2 is not None and cvss3 is None:
#         return cvss2 + " (V2)"
#     else:
#         # return cvss2 + " (V2) " + cvss3 + " (V3)"
#         return cvss3 + " (V3)"


# def get_cvss_score_and_severity_from_cve(cve):
#     '''
#     Returns cvss severity and base score.
#     if cvss3 and cvss2 both exists, return cvss3.
#     If only one of them exists, return the existing one.
#     if none of them exists, return a empty string
#     '''

#     output = ""

#     cvss2 = cve.get("cvss2_severity")
#     cvss2_score = cve.get("cvss2_base_score")

#     cvss3 = cve.get("cvss3_severity")
#     cvss3_score = cve.get("cvss3_base_score")

#     if cvss2 is not None and cvss2_score is not None:
#         output += "CVSS v2.0 Base Score: "
#         output += "{} ({})\n".format(str(cvss2_score), cvss2)

#     if cvss3 is not None and cvss3_score is not None:
#         output += "CVSS v3.0 Base Score: "
#         output += "{} ({})\n".format(str(cvss3_score), cvss3)

#     return output


# def get_cve_url_from_cve(cve):
#     return cve.get("cve_url", "")


def generate_reports(output):
    # Generate reports
    summary_report = make_summary_report(output)
    library_report = make_library_report(output)
    vuln_report = make_vuln_report(output)
    reports = summary_report + library_report + vuln_report
    build_output(output, reports=reports)
    return output
