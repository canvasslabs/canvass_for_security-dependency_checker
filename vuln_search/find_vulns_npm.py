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
import subprocess
import datetime
from solr import search_cve_database, search_vuln_using_versionrange
from utils import file_exists, is_valid_folder_path
from report import (make_summary_report, make_vuln_report, make_library_report)
from exit_handler import build_output
import requests


def run_npm_version():
    '''
    Runs npm --version command.
    '''
    r = subprocess.run(['npm', '--version'],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    stdout_str = r.stdout.decode("utf-8")
    stderr_str = r.stderr.decode("utf-8")

    if r.returncode == 0:
        return (True, stdout_str, stderr_str)
    else:
        return (False, stdout_str, stderr_str)


def get_npm_version(npm_run_stdout):
    '''
    Parses npm version from npm run stdout
    '''
    lines = npm_run_stdout.splitlines()
    if len(lines) > 0:
        return lines[0]


def package_json_exists(package_path):
    '''
    From a given package path, searches for "package.json" file.
    Returns True if exists, Otherwise, returns False

    '''
    return file_exists(package_path, "package.json")


def package_lock_json_exists(package_path):
    '''
    From a given package path, searches for "package-lock.json" file.
    Returns True if exists, Otherwise, returns False

    '''
    return file_exists(package_path, "package-lock.json")


def npm_shrinkwrap_json_exists(package_path):
    '''
    From a given package path, searches for "npm-shrinkwrap.json" file.
    Returns True if exists, Otherwise, returns False

    '''
    return file_exists(package_path, "npm-shrinkwrap.json")


def run_npm_install(package_path):
    '''
    Run "npm install" command on shell.
    Returns True if ran successfully. Otherwise, returns False
    '''
    cwd = os.getcwd()
    os.chdir(package_path)

    r = subprocess.run(['npm', 'install'],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    os.chdir(cwd)

    stdout_str = r.stdout.decode("utf-8")
    stderr_str = r.stderr.decode("utf-8")

    if r.returncode == 0:
        return (True, stdout_str, stderr_str)
    else:
        return (False, stdout_str, stderr_str)


def run_npm_ci(package_path):
    '''
    Run "npm ci" command on shell.
    Returns True if ran successfully. Otherwise, returns False
    '''
    cwd = os.getcwd()
    os.chdir(package_path)

    r = subprocess.run(['npm', 'ci'],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    os.chdir(cwd)

    stdout_str = r.stdout.decode("utf-8")
    stderr_str = r.stderr.decode("utf-8")

    if r.returncode == 0:
        return (True, stdout_str, stderr_str)
    else:
        return (False, stdout_str, stderr_str)


def get_dependency_tree_npm(package_path):
    '''
    Run "npm ls --parseable --long" command on shell.
    Returns a list of dependencies info if ran successfully.
    Otherwise, returns None
    '''
    cwd = os.getcwd()
    os.chdir(package_path)

    r = subprocess.run(['npm', 'ls', '--parseable', '--long'],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    os.chdir(cwd)

    stdout_str = r.stdout.decode("utf-8")
    stderr_str = r.stderr.decode("utf-8")

    if r.returncode == 0:
        return (True, stdout_str, stderr_str)
    else:
        return (False, stdout_str, stderr_str)


def make_dbcoordinates(dependencies):
    '''
    Parses each line of dependency info and generates a full coordinates for
    database query

    Input: lines of dependency info

    Output: a list of full coordinates
    Example: node-js@1.0.0 converted to npm:node-js::1.0.0
    '''
    dbcoordinates = set()
    for dependency in dependencies:

        try:
            if is_invalid_missing_dependency(dependency) is True:
                # handle missing dependnecies
                continue

            # if is_peerinvalid_missing_dependency(dependency) is True:
            #     handle peerinvalid missing dependencies
            #     continue

            npm_pkgCoordinate = _make_npm_pkgCoordinate(dependency)
        except IndexError:
            continue
        else:
            dbcoordinates.add(npm_pkgCoordinate)
    return list(dbcoordinates)


def is_invalid_missing_dependency(line):
    '''
    Checks if dependency contains INVALID and MISSING.
    '''

    if len(line) > 3:
        comps = line.split(":")
        if (comps[2] == "INVALID") and (comps[3] == "MISSING"):
            return True
        else:
            return False
    return False


def is_peerinvalid_missing_dependency(line):
    '''
    Checks if dependency contains undefined, PEERINVALID and MISSING.
    '''

    if len(line) > 4:
        comps = line.split(":")
        if (comps[3] == "PEERINVALID") and (comps[4] == "MISSING"):
            return True
        else:
            return False
    return False


def _make_npm_pkgCoordinate(line):
    '''
    Generates full package coordinate for vulnerability search
    '''
    return ":".join(["npm", _npm_pkg_name(line), "", _npm_version_name(line), ""])


def _npm_pkgversion_name(line):
    '''
    From dependency info, parses package name with version info
    '''
    return line.split(':')[1]


def _npm_pkg_name(line):
    '''
    From dependency info, parses package name
    '''
    npm_pkgversion_name = _npm_pkgversion_name(line)

    if npm_pkgversion_name.startswith("@"):
        idx = npm_pkgversion_name.find("@", 1)
        return npm_pkgversion_name[:idx]
    else:
        idx = npm_pkgversion_name.find("@")
        return npm_pkgversion_name[:idx]


def _npm_version_name(line):
    '''
    From dependency info, parses version name
    '''
    npm_pkgversion_name = _npm_pkgversion_name(line)

    if npm_pkgversion_name.startswith("@"):
        idx = npm_pkgversion_name.find("@", 1)
        return npm_pkgversion_name[idx+1:]
    else:
        idx = npm_pkgversion_name.find("@")
        return npm_pkgversion_name[idx+1:]


def _parse_args():
    '''
    argument parser
    Input: path to a NPM package to scan

    '''
    parser = argparse.ArgumentParser(
        description='Finds vulnerabilities in NPM package')
    parser.add_argument("package_path", help="Path to a NPM package to scan")
    parser.add_argument("--outputDir",
                        help="Path to a directory where scan report to be saved")
    parser.add_argument("--outputFile",
                        help="Path to a file where scan report to be saved")
    return parser.parse_args()


def analyze_and_report(package_manager, package_path, dep_tree_output,
                       start_time, output):

    dependencies = dep_tree_output.splitlines()
    dbcoordinates = make_dbcoordinates(dependencies)
    build_output(output, dbcoordinates=dbcoordinates)

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
    build_output(output, message=message, duration=duration)
    print(message)

    # Generate reports
    summary_report = make_summary_report(output)
    library_report = make_library_report(output)  # num of total lib = # of unique full coords (exclude missing for now)
    vuln_report = make_vuln_report(output)
    reports = summary_report + library_report + vuln_report
    build_output(output, code=0, reports=reports)

    print(reports)
    return output


def main(input_path):
    '''
    From a given NPM package path, installs npm dependency packages,
    generates dependency tree, generates full package coordinates using from dependency tree,
    then searches vulnerability database for any matching vulnerabilities
    '''

    # This output dictionary will collect all the reports, stdouts, warning, and error messages for the final output
    output = {}
    package_manager = "NPM"
    start_time = time.time()
    build_output(output, package_manager=package_manager, start_time=start_time)

    # Check if input path is valid. If not valid, exit with error message
    package_path = os.path.abspath(input_path)
    if is_valid_folder_path(package_path) is False:
        error_message = ("ERROR: Invalid path entered for scan path. Please check the path before proceeding.")
        return build_output(output, code=4, error_message=error_message, package_path=package_path)
    build_output(output, package_path=package_path)

    # Checks if npm is installed. If not installed, exit with error message
    try:
        npm_ver_run_result, npm_ver_stdout, npm_err_stderr = run_npm_version()
    except FileNotFoundError:
        error_message = "ERROR: NPM not found in your system. Please install it before proceeding."
        return build_output(output, code=4, error_message=error_message)

    if npm_ver_run_result is False:
        error_message = "ERROR: NPM not found in your system. Please install it before proceeding."
        return build_output(output, code=4, error_message=error_message)

    message = "{} dependency checker started.".format(package_manager)
    print(message)
    message += "Scanning \"{}\" directory.".format(package_path)
    build_output(output, message=message, start_time=start_time,
                 package_manager=package_manager, package_path=package_path)

    npm_version = get_npm_version(npm_ver_stdout)
    if npm_version is not None:
        print("Found NPM version: {}".format(npm_version))

    # Quit if package.json file does not exist
    if not package_json_exists(package_path):
        error_message = ("ERROR: package.json file not found. package.json file is required for scanning.")
        return build_output(output, code=4, error_message=error_message)

    # Lockfile exists.
    if package_lock_json_exists(package_path) or npm_shrinkwrap_json_exists(package_path):
        message = "Dependency checker is installing your project's dependencies by running \"npm ci\" command..."
        print(message)
        build_output(output, message=message)

        ci_run_result, ci_output, ci_error = run_npm_ci(package_path)
        if ci_run_result is True:
            dep_tree_run_result, dep_tree_output, dep_tree_error = get_dependency_tree_npm(package_path)

            if dep_tree_run_result is True:
                output = analyze_and_report(package_manager, package_path, dep_tree_output, start_time, output)
                return output
            else:
                warning_message = ("WARNING: Dependency checker encountered an error while gathering dependencies using \"npm list\" command. "
                                   "Dependency checker does not look for vulnerabilities in missing dependencies. Please resolve any missing dependencies. "
                                   "Please see the error message from npm below:\n\n")
                warning_message += dep_tree_error
                build_output(output, warning_message=warning_message)
                print(warning_message)
                output = analyze_and_report(package_manager, package_path, dep_tree_output, start_time, output)
                return output
        else:
            # npm ci failed
            error_message = ("ERROR: Dependency checker encountered an error while installing dependnecies "
                             "using \"npm ci\" command. "
                             "Please see the error message from npm below:\n\n")
            error_message += ci_error
            return build_output(output, code=4, error_message=error_message)


    # Lockfile does not exists
    message = "Dependency checker is installing your project's dependencies by running \"npm install\" command..."
    print(message)
    build_output(output, message=message)

    # Run npm install
    install_run_result, install_output, install_error = run_npm_install(package_path)
    if install_run_result is True:
        # Get dependencies after npm install
        dep_tree_run_result, dep_tree_output, dep_tree_error =\
            get_dependency_tree_npm(package_path)

        if dep_tree_run_result is True:
            output = analyze_and_report(package_manager, package_path, dep_tree_output, start_time, output)
            return output
        else:
            warning_message = ("WARNING: Dependency checker encountered an error while gathering dependencies using \"npm list\" command. "
                               "Dependency checker does not look for vulnerabilities in missing dependencies. Plese resolve any missing dependencies. "
                               "Please see the error message from npm below:\n\n")
            warning_message += dep_tree_error
            build_output(output, warning_message=warning_message)
            print(warning_message)
            output = analyze_and_report(package_manager, package_path, dep_tree_output, start_time, output)
            return output
    else:
        # npm install failed. display error message
        error_message = ("ERROR: Dependency checker encountered an error while installing dependencies using \"npm install\" command. "
                         "Please see the error message from npm below:\n\n")
        error_message += install_error
        return build_output(output, code=4, error_message=error_message)


if __name__ == "__main__":
    args = _parse_args()
