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
import time
import uuid
import subprocess
import datetime
from solr import search_cve_database, search_vuln_using_versionrange
from utils import file_exists, is_valid_folder_path
from report import (make_summary_report, make_vuln_report, make_library_report)
from exit_handler import build_output
import json
import requests


def yarn_lock_exists(package_path):
    '''
    From a given package path, searches for "package.json" file.
    Returns True if exists, Otherwise, returns False

    '''
    return file_exists(package_path, "yarn.lock")


def get_yarn_lock_filepath(package_path):
    '''
    Returns abs path to yarn.lock file
    '''
    if yarn_lock_exists(package_path) is True:
        return os.path.abspath(os.path.join(package_path, "yarn.lock"))
    else:
        return None


def run_yarn_install(package_path):
    '''
    Run "yarn install" command on shell.
    Returns True if ran successfully. Otherwise, returns False
    '''
    cwd = os.getcwd()
    os.chdir(package_path)

    r = subprocess.run(['yarn', 'install', '--frozen-lockfile'],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    os.chdir(cwd)

    stdout_str = r.stdout.decode("utf-8")
    stderr_str = r.stderr.decode("utf-8")

    if r.returncode == 0:
        return (True, stdout_str, stderr_str)
    else:
        return (False, stdout_str, stderr_str)


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


def convert_yarnlock_file_to_json(yarn_lock_filepath, run_id):
    '''
    Run yarnlock_parser.js file using node and generate dependency tree file
    '''

    output_filename = "_".join([run_id, "yarn_dependencies.json"])
    output_path = os.path.abspath(os.path.join(get_temp_dir(), output_filename))

    r = subprocess.run(['node', 'yarnlock_parser.js', yarn_lock_filepath, output_path],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    stdout_str = r.stdout.decode("utf-8")
    stderr_str = r.stderr.decode("utf-8")

    if r.returncode == 0:
        return (True, output_path, stderr_str)
    else:
        return (False, stdout_str, stderr_str)


def load_yarnlock_jsonfile(dependency_tree_filepath):
    '''
    Loads and returns dependency tree json file
    '''
    with open(dependency_tree_filepath, 'r') as f:
        dependecy_tree_file = json.load(f)
    return dependecy_tree_file


def _parse_args():
    '''
    argument parser
    Input: path to a NPM package to scan

    '''
    parser = argparse.ArgumentParser(
        description='Finds vulnerabilities in Yarn package')
    parser.add_argument("package_path", help="Path to a NPM package to scan")
    parser.add_argument("--outputDir",
                        help="Path to a directory where scan report to be saved")
    parser.add_argument("--outputFile",
                        help="Path to a file where scan report to be saved")
    return parser.parse_args()


def make_pkgcoordinates_and_dbcoordinates_from_yarnlock_json(yarnlock_json):
    '''
    Parse and collect dependencies (pkgcoordinates) from yarn lock json file
    '''

    pkgcoordinates = set()
    dbcoordinates = set()
    yarnlock_obj = yarnlock_json.get('object')

    for pkgname_version, doc in yarnlock_obj.items():
        pkgname = get_pkgname_from_pkgname_version(pkgname_version)
        resolved_version = doc.get('version')

        if pkgname is None:
            continue

        if resolved_version is None:
            continue

        pkgcoordinates.add(":".join([pkgname, resolved_version]))
        dbcoordinates.add(":".join(["npm", pkgname, "", resolved_version, ""]))

    return (list(sorted(pkgcoordinates)), list(sorted(dbcoordinates)))


def get_pkgname_from_pkgname_version(pkgname_version):
    '''
    Parse pkgname from pkgname version from yarn.lock json file
    '''
    if pkgname_version.startswith('@'):
        comps = pkgname_version.split('@')
        if len(comps) > 0:
            return "@" + comps[1]
    else:
        comps = pkgname_version.split('@')
        if len(comps) > 0:
            return comps[0]


def convert_pkgcoordinates_to_dbcoordinates(pkgcoordinates):
    '''
    Converts pkgcoordinates to dbcoordinates by prepending "npm:" and
    appending ":" at the end
    '''
    dbcoordinates = set()
    for pkgcoordinate in pkgcoordinates:
        dbcoordinate = "npm:" + pkgcoordinate + "::"
        dbcoordinates.add(dbcoordinate)
    return list(sorted(dbcoordinates))


def convert_pkgcoordinate_to_dbcoordinate(pkgcoordinate):

    if pkgcoordinate.startswith('@'):
        comps = pkgcoordinate.split('@')
        if len(comps) > 0:
            return "npm:@" + comps[1] + ":" + comps[2] + ":"
    else:
        comps = pkgcoordinate.split('@')
        if len(comps) > 0:
            return comps[0]


def get_yarn_version():
    '''
    Get yarn version
    '''
    r = subprocess.run(['yarn', '--version'], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)

    stdout_str = r.stdout.decode("utf-8")

    if r.returncode == 0:
        return stdout_str.strip()
    else:
        return None


def get_node_version():
    '''
    Get node version
    '''
    r = subprocess.run(['node', '--version'], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)

    stdout_str = r.stdout.decode("utf-8")

    if r.returncode == 0:
        return stdout_str.strip()
    else:
        return None


def main(input_path):
    '''
    '''
    output = {}
    package_manager = "Yarn"
    start_time = time.time()
    build_output(output, package_manager=package_manager, start_time=start_time)

    # Check if input path is valid. If not valid, exit with error message
    package_path = os.path.abspath(input_path)
    if is_valid_folder_path(package_path) is False:
        error_message = ("ERROR: Invalid path entered for scan path. Please check the path before proceeding.\n")
        return build_output(output, code=4, error_message=error_message,
                            package_path=package_path)
    build_output(output, package_path=package_path)

    # Check yarn is installed
    try:
        yarn_version = get_yarn_version()
    except FileNotFoundError:
        error_message = "ERROR: Yarn not found in your system. Please install it before proceeding."
        return build_output(output, code=4, error_message=error_message)

    # Check node is installed
    try:
        node_version = get_node_version()
    except FileNotFoundError:
        error_message = "ERROR: Node.js not found in your system. Please install it before proceeding."
        return build_output(output, code=4, error_message=error_message)

    message = package_manager + " dependency checker started."
    print(message)
    message += "Scanning \"{}\" directory.".format(package_path)
    build_output(output, message=message, start_time=start_time,
                 package_manager=package_manager,
                 package_path=package_path)

    if yarn_version is not None:
        message = "Found Yarn version: {}".format(yarn_version)
        build_output(output, message=message, pkgmanager_version=yarn_version)
        print(message)

    else:
        # yarn version was not found.
        warning_message = "WARNING: Could not verify installed version of Yarn. "
        warning_message += "Dependency checker will attempt to scan anyway."
        build_output(output, warning_message=warning_message)
        print(warning_message)

    if node_version is not None:
        message = "Found Node version: {}".format(node_version)
        build_output(output, message=message)
        #print(message)

    else:
        # node version was not found.
        warning_message = "WARNING: Could not verify installed version of node.js. "
        warning_message += "Dependency checker will attempt to scan anyway."
        build_output(output, warning_message=warning_message)
        #print(warning_message)


    # Check yarn.lock exists on input package's root
    if yarn_lock_exists(package_path) is False:
        error_message = "ERROR: yarn.lock file not found. yarn.lock file is required for scanning."
        return build_output(output, code=4, error_message=error_message)


    # Test if package can be installed
    message = "Dependency checker is installing your project's dependencies by running \"yarn install --frozen-lockfile\" command..."
    print(message)
    build_output(output, message=message)
    install_result, install_output, install_error = run_yarn_install(package_path)
    if install_result is False:
        # yarn install failed. display error message and exit
        error_message = ("ERROR: Dependency checker encountered an error while installing your project's "
                         "dependencies using \"yarn install --frozen-lockfile\" command. "
                         "Please see the error message from yarn below:\n\n")
        error_message += install_error
        return build_output(output, code=4, error_message=error_message)

    run_id = uuid.uuid4().hex
    yarn_lock_filepath = get_yarn_lock_filepath(package_path)
    run_result, run_stdout, run_stderr =\
        convert_yarnlock_file_to_json(yarn_lock_filepath, run_id)
    if run_result is True:
        dependency_tree_filepath = run_stdout
    else:
        error_message = ("ERROR: Dependency checker encountered an error while gathering dependencies.\n\n")
        error_message += run_stderr
        return build_output(output, code=4, error_message=error_message)

    yarnlock_json = load_yarnlock_jsonfile(dependency_tree_filepath)
    pkgcoordinates, dbcoordinates =\
        make_pkgcoordinates_and_dbcoordinates_from_yarnlock_json(yarnlock_json)
    build_output(output, dbcoordinates=dbcoordinates)

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
        #error_message += str(e)
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
        os.remove(dependency_tree_filepath)
    except OSError:
        pass
    else:
        message = "Dependency tree file at {} is removed.\n".format(
            dependency_tree_filepath)
        build_output(output, message=message)
        # print(message)

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
