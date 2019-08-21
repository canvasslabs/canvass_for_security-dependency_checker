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

import os
import time
import datetime
import subprocess
import argparse
from solr import search_cve_database, search_vuln_using_versionrange
from utils import file_exists, is_valid_folder_path
from report import (make_summary_report, make_vuln_report,
                    make_library_report)
from exit_handler import build_output
import requests


def run_gradle_version(package_path, gradle_wrapper_file_exists):
    '''
    Runs gradle --version command.
    '''
    cwd = os.getcwd()

    cl_name = "gradle"
    if gradle_wrapper_file_exists is True:
        os.chdir(package_path)
        cl_name = "./gradlew"

    r = subprocess.run([cl_name, '--version'],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    stdout_str = r.stdout.decode("utf-8")
    stderr_str = r.stderr.decode("utf-8")

    os.chdir(cwd)

    if r.returncode == 0:
        return (True, stdout_str, stderr_str)
    else:
        return (False, stdout_str, stderr_str)


def get_gradle_version(gradle_ver_run_stdout):
    '''
    Parses stdout from gradle --version and returns version name
    '''
    lines = gradle_ver_run_stdout.splitlines()
    for line in lines:
        if "Gradle" in line:
            comps = line.split(" ")
            if len(comps) > 1 and comps[0] == "Gradle":
                return comps[1]


def build_gradle_file_exists(package_path):
    '''
    From a given package path, searches for "build.gradle" file (groovy) or
    "build.kts" file (kotlin).
    Returns True if exists, Otherwise, returns False

    '''
    if file_exists(package_path, "build.gradle") is True:
        return True
    elif file_exists(package_path, "build.gradle.kts") is True:
        return True
    else:
        return False


def gradlew_file_exists(package_path):
    '''
    From a given package path, searches for "gradlew" file.
    Returns True if exists. Otherwise, returns False

    '''
    return file_exists(package_path, "gradlew")


def get_gradle_projects_unprocessed(package_path, gradlew_file_exists):
    '''
    Runs "gradle projects" command on shell.
    Returns stdout if ran successfully. Otherwise, returns False
    '''
    cwd = os.getcwd()
    os.chdir(package_path)

    cl_name = "gradle"
    if gradlew_file_exists:
        cl_name = "./gradlew"

    r = subprocess.run([cl_name, '-q', 'projects'],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    os.chdir(cwd)

    stdout_str = r.stdout.decode("utf-8")
    stderr_str = r.stderr.decode("utf-8")

    if r.returncode == 0:
        return (True, stdout_str, stderr_str)
    else:
        return (False, stdout_str, stderr_str)


def parse_and_get_all_projects(stdout):
    '''
    Parses stdout from gradle projects command and returns list of projects
    '''
    projects = []
    lines = stdout.splitlines()

    subprojects = []

    for line in lines:
        # Find root project
        if "Root project '" in line:
            components = line.split("'")
            if len(components) > 2:
                projects.append(components[1])

        # Find subprojects
        elif line.startswith(("+", "\\", "|")):
            components = line.split("'")
            if len(components) > 2:
                projects.append(components[-2])

                # collect subproject names to print
                subproject_name_comps = components[1].split(":")
                if len(subproject_name_comps) > 0:
                    subproject_name = subproject_name_comps[1]
                    subprojects.append(subproject_name)

    return projects


def get_raw_dependency_project_level_data_from_projects(package_path,
                                                        projects,
                                                        gradlew_file_exists):
    '''
    Gathers dependencies for each projects
    Outputs a mapping from project name to stdout dependency data
    (ex) map[project_name] = stdout from gradle dependencies command

    '''
    result = {}

    for project in projects:
        # Get dependencies from subprojects

        if project.startswith(":"):
            run_result, stdout, stderr =\
                get_raw_dependency_project_level_data_from_project(
                    package_path, project, gradlew_file_exists)

            if run_result is True:
                result[project] = stdout
            else:
                error_message = ("ERROR: Dependency checker encountered an error while generating a dependency tree from a "
                                 "subproject, {} using \"gradle <project_name>:dependencies\" command. Please see the error message from gradle below.\n".format(project))
                error_message += stderr
                raise ValueError(error_message)

        else:
            # Get dependencies from root project
            run_result, stdout, stderr =\
                get_raw_dependency_project_level_data_from_project(
                    package_path, "", gradlew_file_exists)

            if run_result is True:
                result[project] = stdout
            else:
                error_message = ("ERROR: Dependency checker encountered an error while generating a dependency tree from a "
                                 "root project, {} using \"gradle <project_name>:dependencies\" command. Please see the error message from gradle below.\n".format(project))
                error_message += stderr
                raise ValueError(error_message)

    return result


def get_raw_dependency_project_level_data_from_project(package_path,
                                                       project,
                                                       gradlew_file_exists):
    '''
    Subroutine of get_raw_dependency_project_level_data_from_projects function
    Runs gradle dependencies command on a project
    Returns stdout of dependencies data if return code is zero
    Returns False if subprocess return code is non-zero

    '''
    cwd = os.getcwd()
    os.chdir(package_path)

    # Uses ./gradlew if gradle wrapper exists
    cl_name = "gradle"
    if gradlew_file_exists:
        cl_name = "./gradlew"

    r = subprocess.run([cl_name, '-q', project + ':dependencies'],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    os.chdir(cwd)

    stdout_str = r.stdout.decode("utf-8")
    stderr_str = r.stderr.decode("utf-8")

    if r.returncode == 0:
        return (True, stdout_str, stderr_str)
    else:
        return (False, stdout_str, stderr_str)


def get_raw_dependency_config_level_data(dep_project):
    '''
    Using a mapping from project name to sdout dependency data,
    build a mapping from project name to configuration name to coordinates
    (ex) map[project_name][config_name] = coordinates
    '''
    result_project = {}
    for project, raw_dep_text in dep_project.items():

        # Split lines by two new lines
        paragraphs = raw_dep_text.split("\n\n")
        result_config = {}

        for lines in paragraphs:
            single_lines = lines.split("\n")

            # These lines don't contain dependency so skip.
            if len(single_lines) < 2:
                # next paragraph
                continue
            # These lines may contain dependency
            else:
                # Skip likes with no dependency
                #if single_lines[1].startswith("No dependencies"):
                if "No dependencies" in single_lines[1]:
                    # Next paragraph
                    continue
                # Get dependency
                elif single_lines[1].startswith(("+", "|", "\\")):
                    # Get configuration name from 1st line

                    config = single_lines[0].split(" ")[0]

                    # pass only coordinates to get_all_coordinates function
                    coordinates = get_all_coordinates(single_lines[1:])

                    # Check for empty list of coordinates
                    if coordinates and len(coordinates) > 0:
                        result_config[config] = coordinates

                    result_project[project] = result_config
    return result_project


def _get_coordinates_with_parenthesis(lines):
    """
    Finds coordinates that are omitted (listed previously)
    """
    coordinates = []
    for line in lines:
        # dependency omitted case. exclude conflict resolved case
        if ("(*)" in line) and (" -> " not in line):

            line = line.replace("(*)", "")
            line = line.rstrip()
            line = line.split(" ")[-1]

            if _check_coordinate_length(line):
                coordinates.append(line)

        # config not meant to be resolved case. exclude conflict resolved case
        elif ("(n)" in line) and (" -> " not in line):

            line = line.replace("(n)", "")
            line = line.rstrip()
            line = line.split(" ")[-1]

            if _check_coordinate_length(line):
                coordinates.append(line)
    return coordinates


def _get_conflict_resolved_coordinate(lines):
    '''
    Finds coordinates with conflict and turn them into a resolved coordinates
    exclude "(n)" and "(*)" case
    '''
    coordinates = []
    for line in lines:
        if (" -> " in line) and ("(n)" not in line) and ("(*)" not in line):
            coord_in_conflict = line.split(" -> ")
            # Make sure there are at least two components, requested and resolved
            if len(coord_in_conflict) > 1:
                requested_coord = coord_in_conflict[0].split(" ")[-1]
                resolved_version = coord_in_conflict[1]

                requested_coord_comps = requested_coord.split(":")
                # Make sure requested coordinate contains at least group and artifact
                if len(requested_coord_comps) > 1:
                    resolved_coord = ":".join([requested_coord_comps[0],
                                               requested_coord_comps[1],
                                               resolved_version])

                    if _check_coordinate_length(resolved_coord):
                        coordinates.append(resolved_coord)
    return coordinates


def _get_conflict_resolved_and_parenthesis_coordinate(lines):
    '''
    Finds coordinates with conflict and with parentheses, then turn them into a resolved coordinates
    (example inputs)
    "+--- org.apache.commons:commons-compress:1.14 -> 7.0 (n)"
    "+--- org.apache.commons:commons-compress:1.14 -> 7.0 (n)"
    '''
    coordinates = []
    for line in lines:
        if (" -> " in line) and ("(n)" in line):
            # Remove n first
            line = line.replace("(n)", "")
            line = line.rstrip()
            coord_in_conflict = line.split(" -> ")
            # Make sure there are at least two components, requested and resolved
            if len(coord_in_conflict) > 1:
                requested_coord = coord_in_conflict[0].split(" ")[-1]
                resolved_version = coord_in_conflict[1]

                requested_coord_comps = requested_coord.split(":")
                # Make sure requested coordinate contains at least group and artifact
                if len(requested_coord_comps) > 1:
                    resolved_coord = ":".join([requested_coord_comps[0],
                                               requested_coord_comps[1],
                                               resolved_version])

                    if _check_coordinate_length(resolved_coord):
                        coordinates.append(resolved_coord)

        elif (" -> " in line) and ("(*)" in line):
            # Remove asterisk first
            line = line.replace("(*)", "")
            line = line.rstrip()
            coord_in_conflict = line.split(" -> ")
            # Make sure there are at least two components, requested and resolved
            if len(coord_in_conflict) > 1:
                requested_coord = coord_in_conflict[0].split(" ")[-1]
                resolved_version = coord_in_conflict[1]

                requested_coord_comps = requested_coord.split(":")
                # Make sure requested coordinate contains at least group and artifact
                if len(requested_coord_comps) > 1:
                    resolved_coord = ":".join([requested_coord_comps[0],
                                               requested_coord_comps[1],
                                               resolved_version])

                    if _check_coordinate_length(resolved_coord):
                        coordinates.append(resolved_coord)
    return coordinates


def _get_coordinates(lines):
    """
    Finds coordinates that don't have conflict resolution or omitted
    """
    coordinates = []
    for line in lines:
        if ("(*)" not in line) and (" -> " not in line) and ("(n)" not in line):
            line = line.split(" ")[-1]

            if _check_coordinate_length(line):
                coordinates.append(line)
    return coordinates


def get_all_coordinates(lines):
    '''
    Get all coordinates including conflict resolved and omitted (asterisk)
    '''
    all_coordinates = []
    all_coordinates.extend(_get_coordinates(lines))
    all_coordinates.extend(_get_coordinates_with_parenthesis(lines))
    all_coordinates.extend(_get_conflict_resolved_coordinate(lines))
    all_coordinates.extend(_get_conflict_resolved_and_parenthesis_coordinate(lines))
    return all_coordinates


def _check_coordinate_length(coordinate):
    '''
    Makes sure that the coordinate length is at least 4 to
    include group, artifact, and version name
    '''
    if len(coordinate.split(":")) < 3:
        return False
    else:
        return True


def filter_coordinates_by_scope_exclusive(dep_project_config,
                                          scopes_to_exclude):
    '''
    Filter coordinates based on configuration (scope)
    '''
    filtered_coordinates = []
    for project, config in dep_project_config.items():
        for config_name, coordinates in config.items():
            # Filter out any test scope or any additional user defined scopes to exclude
            if config_name.startswith("test") or config_name in scopes_to_exclude:
                continue
            else:
                filtered_coordinates.extend(coordinates)
    return list(set(filtered_coordinates))


def filter_coordinates_by_scope_inclusive(dep_project_config,
                                          scopes_to_include):
    '''
    Filter coordinates based on configuration (scope)
    '''
    filtered_coordinates = []
    for project, config in dep_project_config.items():
        for config_name, coordinates in config.items():
            # Collect coordinates from only specified scope
            if config_name in scopes_to_include:
                filtered_coordinates.extend(coordinates)
    return list(set(filtered_coordinates))


def convert_coordinates_to_dbcoordinates(coordinates):
    dbcoordinates = set()
    for coordinate in coordinates:
        dbcoordinates.add(convert_coordinate_to_dbcoordinate(coordinate))
    return list(dbcoordinates)


def convert_coordinate_to_dbcoordinate(coordinate):
    """
    Converts mvn coordinate to db coordinate
    """
    dbCoordinate = "maven:" + coordinate
    dbCoordinate = dbCoordinate + ":"
    return dbCoordinate


def _parse_args():
    '''
    ArgumentParser
    Takes path to a mvn package as an input
    '''
    parser = argparse.ArgumentParser(description='Finds vulnerabilities using information from MVN tree')
    parser.add_argument("package_path",
                        help="File path to MVN tree output file")
    parser.add_argument("--outputDir",
                        help="Path to a directory where scan report to be saved")
    parser.add_argument("--outputFile",
                        help="Path to a file where scan report to be saved")
    return parser.parse_args()


def main(input_path):
    """

    """
    # This output dictionary will collect all the reports, stdouts, warning, and error messages for the final output
    output = {}

    # Checks if input path is valid. If not valid, exits with error message
    package_path = os.path.abspath(input_path)
    if is_valid_folder_path(package_path) is False:
        error_message = ("ERROR: Invalid path entered for scan path. Please check the path before proceeding.")
        return build_output(output, code=4, error_message=error_message)

    package_manager = "Gradle"
    message = "{} dependency checker started.".format(package_manager)
    print(message)
    message += "Scanning \"{}\" directory.".format(package_path)
    start_time = time.time()
    build_output(output, message=message, start_time=start_time,
                 package_manager=package_manager, package_path=package_path)

    gradle_wrapper_file_exists = False
    # Makes sure gradle.build exists on input package's root
    if not build_gradle_file_exists(package_path):
        error_message = ("ERROR: build.gradle file not found. build.gradle file is required for scanning.")
        return build_output(output, code=4, error_message=error_message)

    # Check if gradle wrapper file exists in the package directory
    if gradlew_file_exists(package_path):
        gradle_wrapper_file_exists = True
        message = "Found gradle wrapper in your project. Dependency checker will use the wrapper to scan your project."
        print(message)
        build_output(output, message=message)

    # Checks if gradle is installed. Exits with error message if not installed
    # Important: If gradle wrapper exists, ./gradlew --version will be used and will get the version from gradle wrapper
    try:
        gradle_version_run_result, gradle_version_run_stdout, gradle_version_run_stderr =\
            run_gradle_version(package_path, gradle_wrapper_file_exists)
    except PermissionError:
        if gradle_wrapper_file_exists is True:
            error_message = "Dependency checker does not have permission to execute gradlew file. Please make gradlew file executable before proceeding."
            return build_output(output, code=4, error_message=error_message)
        else:
            # This case may not occur.
            error_message = "Dependency checker does not have permission to execute gradle command. Please check if gradle is executable before proceeding."
            return build_output(output, code=4, error_message=error_message)
    except FileNotFoundError:
        error_message = "ERROR: Gradle not found in your system. Please install it before proceeding."
        return build_output(output, code=4, error_message=error_message)

    if gradle_version_run_result is False:
        error_message = "ERROR: Gradle not found in your system. Please install it before proceeding."
        return build_output(output, code=4, error_message=error_message)

    # Display gradle version
    gradle_version = get_gradle_version(gradle_version_run_stdout)
    if gradle_version is not None:
        message = "Found Gradle version: {}".format(gradle_version)
        print(message)
        build_output(output, message=message)

    message = "Gathering subproject information from your project..."
    #print(message)
    build_output(output, message=message)

    gradle_projects_run_result, gradle_projects_stdout, gradle_projects_stderr =\
        get_gradle_projects_unprocessed(package_path, gradlew_file_exists(package_path))
    if gradle_projects_run_result is False:
        error_message = ("ERROR: Dependency checker encountered an error while gathering subproject information using "
                         "'gradle projects' command. "
                         "Please see the error message from Gradle below.\n\n")
        error_message += gradle_projects_stderr
        return build_output(output, code=4, error_message=error_message)

    projects = parse_and_get_all_projects(gradle_projects_stdout)
    if len(projects) > 0:
        message = "Found following {} projects:\n".format(len(projects))
        message += ", ".join(projects)
        #print(message)
        build_output(output, message=message)

    message = "Generating dependency trees from each project..."
    #print(message)
    build_output(output, message=message)

    # For each project (or subproject), get dependencies
    try:
        project_and_dependencies_stdout_map =\
            get_raw_dependency_project_level_data_from_projects(
                package_path, projects, gradle_wrapper_file_exists)
    except ValueError as e:
        return build_output(output, code=4, error_message=str(e))

    project_dependencies_configs_map =\
        get_raw_dependency_config_level_data(
            project_and_dependencies_stdout_map)

    # To use this scopes_to_exclude, may need to update text report generating funcs
    # scopes_to_exclude = ("")
    # filtered_coordinates = filter_coordinates_by_scope_exclusive(
    #     project_dependencies_configs_map, scopes_to_exclude)

    scopes_to_include = ("compile", "implementation", "compileOnly",
                         "compileClasspath", "runtime", "runtimeOnly",
                         "runtimeClasspath", "default")
    filtered_coordinates = filter_coordinates_by_scope_inclusive(
        project_dependencies_configs_map, scopes_to_include)

    dbcoordinates = convert_coordinates_to_dbcoordinates(filtered_coordinates)
    build_output(output, dbcoordinates=dbcoordinates, scopes_included=scopes_to_include)

    try:
        vulns = search_vuln_using_versionrange(dbcoordinates)

        cves = search_cve_database(vulns)
    except KeyError as e:
        # login id or password not available from environment
        error_message = str(e)
        return build_output(output, code=4, error_message=error_message)

    except NameError as e:
        # login id or password is empty
        error_message = str(e)
        return build_output(output, code=4, error_message=error_message)

    except requests.exceptions.RequestException as e:
        error_message = "ERROR: Dependency checker could not connect to vulnerability database.\n"
        #error_message += str(e)
        return build_output(output, code=4, error_message=error_message)

    if vulns is not None:
        build_output(output, vulns=vulns)
    if cves is not None:
        build_output(output, cves=cves)

    end_time = time.time()
    duration = (str(datetime.timedelta(seconds=(end_time - start_time))).split(".")[0]) + " (hr:min:sec)"

    message = "Dependency checker scanning completed.\n"
    print(message)
    build_output(output, message=message, duration=duration)

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
