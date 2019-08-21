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

import argparse
import os
import subprocess
import uuid
import time
import datetime
import requests
from solr import (search_cve_database, search_vuln_using_versionrange)
from utils import _get_lines_from_file, file_exists, is_valid_folder_path
from report import (make_vuln_report, make_summary_report, make_library_report)
from exit_handler import build_output
import re


def get_current_module_dir():
    '''
    Get directory path to current module
    '''
    return os.path.dirname(os.path.abspath(__file__))


def get_temp_dir():
    '''
    Create data directory where the current module is if it does not exist
    If exists, returns path to temp directory
    '''
    data_dir_path = os.path.join(get_current_module_dir(), "temp")
    if not os.path.exists(data_dir_path):
        os.makedirs(data_dir_path)
    return data_dir_path


def run_mvn_version():
    '''
    Runs mvn --version command.
    Returns stdout if ran successfully. Otherwise, returns False
    '''
    r = subprocess.run(['mvn', '--version'], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)

    stdout_str = r.stdout.decode("utf-8")
    stderr_str = r.stderr.decode("utf-8")

    if r.returncode == 0:
        return (True, stdout_str, stderr_str)
    else:
        return (False, stdout_str, stderr_str)


def get_mvn_version(stdout):
    # Parses stdout from mvn --version command and returns version info
    # If version can't be found, returns None

    lines = stdout.splitlines()

    for line in lines:
        if "Apache Maven" in line:
            comps = line.split(" ")

            if (len(comps) > 2) and ("Apache" in comps[0]) and ("Maven" in comps[1]):
                return get_mvn_version_with_regex(comps[2])
            else:
                return None


def get_mvn_version_with_regex(version_string):
    """
    Find version string by discarding any characters that
    aren't related to the version string such as bold charcter and etc
    If no match, return the original version string as is
    """

    # Matches cases like "3.5.0-alpha-1", "3.0-beta-1"
    pattern_1 = "([\d.]+\-+\w+\-+\d+)"
    r = re.search(pattern_1, version_string)
    if r is not None:
        return r.group(0)

    # Matches cases like "1.1-RC-1"
    pattern_2 = "([\d.]+\-+\w+)"
    r = re.search(pattern_2, version_string)
    if r is not None:
        return r.group(0)

    # Matches cases like "3", "2.2.1", and partial of "3.0-beta-3" which is "3.0"
    pattern_3 = "([\d.]+)"
    r = re.search(pattern_3, version_string)
    if r is not None:
        return r.group(0)

    # Return the version as it was found
    return version_string


# def check_mvn_version(version):
#     # mvn dependency:tree plugin is supported since maven version, 2.0-alpha-5.
#     # http://maven.apache.org/plugins/maven-dependency-plugin/tree-mojo.html
#     # This function checks if user's maven version is greater or equal to 2.0

#     # Split version string into version part and tag part
#     ver_and_tag = version.split("-")
#     if len(ver_and_tag) > 1:
#         ver = ver_and_tag[0]
#         tag = True
#     else:
#         ver = version
#         tag = False

#     # Split version part into major, minor, and patch
#     comps = ver.split(".")
#     # Check if version at least has major and minor
#     if len(comps) > 1:
#         try:
#             major = int(comps[0])
#             minor = int(comps[1])

#             if len(comps) > 2:
#                 patch = int(comps[2])
#             else:
#                 patch = 0

#         except ValueError:
#             return False
#         else:
#             # Don't include any version with tag 3.0-XXXX (ex: 3.0-alpha-xxx)
#             if major == 3 and minor == 0 and patch == 0 and tag is True:
#                 return False

#             # Any version with major greater than 3 and minor greater than 0
#             if major >= 3 and minor >= 0 and patch >= 0:
#                 return True
#             else:
#                 return False
#     else:
#         # When version only has major or no value. Incorrectly formatted version.
#         return False


def get_mvn_dependency_tree_filepath(run_id):
    '''
    Create file path for mvn dependency file
    '''
    return os.path.join(get_temp_dir(), run_id + "_mvn_dependencies.txt")


def delete_dependency_file(filepath):
    '''
    Deletes dependency file
    '''
    os.remove(filepath)


def pom_xml_exists(package_path):
    '''
    From a given package path, searches for "pom.xml" file.
    Returns True if exists. Otherwise, returns False

    '''
    return file_exists(package_path, "pom.xml")


def generate_dependency_tree_file(package_path, outputFile):
    '''
    Runs a command on shell to generate a dependency tree file.
    Returns True if ran successfully. Otherwise, returns False.
    '''
    cwd = os.getcwd()
    os.chdir(package_path)

    r = subprocess.run(['mvn', '-q',
                        'org.apache.maven.plugins:maven-dependency-plugin:3.1.1:tree',
                        '-DappendOutput',
                        '-DoutputFile=' + outputFile],
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
    os.chdir(cwd)

    stdout_str = r.stdout.decode("utf-8")
    stderr_str = r.stderr.decode("utf-8")

    if r.returncode == 0:
        return (True, stdout_str, stderr_str)
    else:
        return (False, stdout_str, stderr_str)


def _get_optional_coordinates_excluding_constraint(lines):
    """
    Finds mvn coordinates that have optional parameter
    excluding coordinates with version selected from constraints
    """
    coordinates = []
    for line in lines:

        if "(optional)" in line and "(version selected from constraint" not in line:
            line = line.replace("(optional)", "")
            line = line.rstrip()
            line = line.split(" ")[-1]

            if _check_coordinate_length(line):
                coordinates.append(line)
    return coordinates


def _get_optional_and_version_constraints_coordinates(lines):
    '''
    Finds coordinates that have optional and version constraint
    (ex)|  |  \\- com.nimbusds:lang-tag:jar:1.4.4:compile (version selected from constraint [1.4.3,))
    '''
    coordinates = []
    for line in lines:

        if "(optional)" in line and "(version selected from constraint" in line:
            line = line.replace("(optional)", "")
            line = line.rstrip()

            # Finds substring to remove
            substring_idx = line.find("(version selected from constraint")

            # Make sure the substring to remove is found
            if substring_idx > 0:
                line = line[:substring_idx]
                line = line.rstrip()
                line = line.split(" ")[-1]

            if _check_coordinate_length(line):
                coordinates.append(line)
    return coordinates


def _get_coordinates_no_optional_and_no_parenthesis(lines):
    """
    Finds mvn coordinates that doesn't have optional parameter
    nor parenthesis parameter
    """
    coordinates = []
    for line in lines:
        # skip coordinates that have any parenthesis
        if ("(optional)" not in line) and ("(" not in line):
            line = line.split(" ")[-1]

            if _check_coordinate_length(line):
                coordinates.append(line)
    return coordinates


def _get_coordinates_with_no_optional_and_parenthesis(lines):
    """
    Finds mvn coordinates that doesn't have parenthesis parameter
    """
    coordinates = []
    for line in lines:
        # Skip coordinates that are optional but find ones with parenthesis parameter
        if ("(optional)" not in line) and ("(" in line):
            start = line.find("(")
            line = line[:start-1]
            line = line.rstrip()
            line = line.split(" ")[-1]

            if _check_coordinate_length(line):
                coordinates.append(line)
    return coordinates


def _check_coordinate_length(line):
    '''
    Makes sure that the coordinate length is at least 4 to
    include group, artifact, type, and version name
    '''
    if len(line.split(":")) < 4:
        return False
    else:
        return True


# Remove error check for debugging
def get_all_coordinates(lines):
    '''
    Get all mvn coordinates including ones with optional and parenthesis parameter
    '''
    all_coords = []
    coords_with_no_optional_and_no_parenthesis = _get_coordinates_no_optional_and_no_parenthesis(lines)
    coords_with_no_optional_and_parenthesis = _get_coordinates_with_no_optional_and_parenthesis(lines)
    coords_with_optional_and_no_constraint = _get_optional_coordinates_excluding_constraint(lines)
    coords_with_optional_and_constraint = _get_optional_and_version_constraints_coordinates(lines)

    all_coords.extend(coords_with_no_optional_and_no_parenthesis)
    all_coords.extend(coords_with_no_optional_and_parenthesis)
    all_coords.extend(coords_with_optional_and_no_constraint)
    all_coords.extend(coords_with_optional_and_constraint)

    return all_coords


def filter_coordinates_by_scope(coordinates, scopes_to_exclude):
    '''
    Filter maven coordinates based on scope
    '''
    filtered_coordinates = []
    for coordinate in coordinates:
        components = coordinate.split(":")

        # include any coordinates without scope (group/artifact/type/version)
        # if len(components) < 5:
        if len(components) == 4:
            filtered_coordinates.append(coordinate)

        # include any coordinate with scope that is not in exclude list (group/artifact/type/version/scope)
        if len(components) > 4 and components[4] not in scopes_to_exclude:
            filtered_coordinates.append(coordinate)
    return filtered_coordinates


def convert_coordinates_to_dbcoordinates(coordinates):
    '''
    Converts mvn coordinates to db coordinates and
    removes any duplicated db coordinates
    '''
    dbcoordinates = set()
    for coordinate in coordinates:
        dbcoordinate = convert_coordinate_to_dbcoordinate(coordinate)
        if dbcoordinate is not None:
            dbcoordinates.add(dbcoordinate)
    return list(dbcoordinates)


def convert_coordinate_to_dbcoordinate(coordinate):
    """
    Converts mvn coordinate to db coordinate
    """
    components = coordinate.split(":")
    temp = [components[0], components[1], components[3]]

    dbCoordinate = ":".join(temp)
    dbCoordinate = "maven:" + dbCoordinate
    dbCoordinate = dbCoordinate + ":"
    return dbCoordinate


def _parse_args():
    '''
    ArgumentParser
    Takes path to a mvn package as an input
    '''
    parser = argparse.ArgumentParser(
        description='Finds vulnerabilities in a Maven package')
    parser.add_argument("package_path",
                        help="Path to a Maven package to scan")
    parser.add_argument("--outputDir",
                        help="Path to a directory where scan report to be saved")
    parser.add_argument("--outputFile",
                        help="Path to a file where scan report to be saved")

    return parser.parse_args()


def main(input_path):
    '''
    Performs scanning on a given directory and returns vulnerability report and error messages that encountered
    '''

    # This output dictionary will collect all the reports, stdouts, warning, and error messages for the final output
    output = {}
    # Setup basic parameters to create a report
    start_time = time.time()
    package_manager = "Maven"
    build_output(output, package_manager=package_manager, start_time=start_time)

    # Check if input path is valid. If not valid, exit with error message
    package_path = os.path.abspath(input_path)
    if is_valid_folder_path(package_path) is False:
        error_message = ("ERROR: Invalid path entered for scan path. Please check the path before proceeding.\n")
        return build_output(output, code=4, error_message=error_message, package_path=package_path)
    build_output(output, package_path=package_path)

    # Makes sure maven is installed
    try:
        mvn_version_run_result, mvn_version_stdout, mvn_version_stderr = run_mvn_version()
    except FileNotFoundError:
        error_message = "ERROR: Maven not found in your system. Please install it before proceeding."
        return build_output(output, code=4, error_message=error_message)

    if mvn_version_run_result is False:
        error_message = "ERROR: Maven not found in your system. Please install it before proceeding."
        return build_output(output, code=4, error_message=error_message)

    message = package_manager + " dependency checker started."
    print(message) # print only the line above
    #message += "\n"
    message += "Scanning \"{}\" directory.".format(package_path)
    build_output(output, message=message)

    # Get maven version and check if the version is higher than 2.0 to support dependency:tree plugin
    # If maven version info cannot be found. proceed to the next step regardless.
    # If maven version doesn't support dependency:tree, exit.
    mvn_version = get_mvn_version(mvn_version_stdout)
    if mvn_version is not None:
        message = "Found Maven version: {}".format(mvn_version)
        build_output(output, message=message)
        build_output(output, pkgmanager_version=mvn_version)
        print(message)

        # if check_mvn_version(mvn_version) is False:
        #     error_message = "ERROR: Dependency checker requires Maven version 3 or later. "
        #     error_message += "Your current Maven version is " + mvn_version + ". "
        #     error_message += "Please update your Maven before proceeding."
        #     return build_output(output, code=1, error_message=error_message)

    else:
        # maven version was not found.
        warning_message = "WARNING: Could not verify installed version of Maven. "
        warning_message += "Dependency checker will attempt to scan anyway."
        build_output(output, warning_message=warning_message)
        print(warning_message)

    # Makes sure pom.xml exists on input package's root
    if pom_xml_exists(package_path) is False:
        error_message = "ERROR: pom.xml file not found. pom.xml file is required for scanning."
        return build_output(output, code=4, error_message=error_message)

    # Create a unique ID for each instance to generate unique dependency file
    scan_id = uuid.uuid4().hex
    dependency_tree_filepath = get_mvn_dependency_tree_filepath(scan_id)

    message = "Generating a dependency tree file for your project..."
    build_output(output, message=message)

    generate_result, generate_stdout, generate_stderr = \
        generate_dependency_tree_file(package_path, dependency_tree_filepath)

    if generate_result is False:
        error_message = ("ERROR: Dependency checker encountered an error while generating a dependency tree file for your project using \"mvn dependency:tree\" command. "
                         "Please see the error message from Maven below:\n\n")
        error_message += generate_stdout # When mvn dependency:tree fails, the output is directed to stdout (not stderr)
        return build_output(output, code=4, error_message=error_message)

    message = "Dependency tree file is generated at {}".format(dependency_tree_filepath)
    #print(message)
    build_output(output, message=message)

    lines = _get_lines_from_file(dependency_tree_filepath)

    coordinates = get_all_coordinates(lines)
    scopes_to_exclude = ["test"]
    coordinates_test_scope_excluded =\
        filter_coordinates_by_scope(coordinates, scopes_to_exclude)
    dbcoordinates =\
        convert_coordinates_to_dbcoordinates(coordinates_test_scope_excluded)
    build_output(output, dbcoordinates=dbcoordinates, scopes_excluded=scopes_to_exclude)

    try:
        vulns = search_vuln_using_versionrange(dbcoordinates)
        cves = search_cve_database(vulns)
    except KeyError as e:
        error_message = str(e)
        return build_output(output, code=4, error_message=error_message)
    except NameError as e:
        error_message = str(e)
        return build_output(output, code=4, error_message=error_message)
    except requests.exceptions.RequestException as e:
        error_message = "ERROR: Dependency checker could not connect to vulnerability database.\n"
        return build_output(output, code=4, error_message=error_message)

    if vulns is not None:
        build_output(output, vulns=vulns)
    if cves is not None:
        build_output(output, cves=cves)

    end_time = time.time()
    duration = (str(datetime.timedelta(seconds=(end_time - start_time))).split(".")[0]) + " (hr:min:sec)"
    message = "Dependency checker scanning completed.\n"
    build_output(output, message=message, duration=duration)
    print(message)

    # Deletes generated dependency tree file in temp folder
    try:
        delete_dependency_file(dependency_tree_filepath)
    except OSError:
        pass
    else:
        message = "Dependency tree file at {} is removed.\n".format(
            dependency_tree_filepath)
        build_output(output, message=message)
        #print(message)

    # Generate reports
    summary_report = make_summary_report(output)
    library_report = make_library_report(output)
    vuln_report = make_vuln_report(output)
    reports = summary_report + library_report + vuln_report
    build_output(output, code=0, reports=reports)
    print(reports)
    return output


if __name__ == "__main__":
    args = _parse_args()
