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
import json
from utils import file_exists, is_valid_folder_path
from report import generate_reports
from find_vulns import find_vulns
from exit_handler import build_output


def bower_json_exists(package_path):
    '''
    From a given package path, searches for "bower.json" file.
    Returns True if exists, Otherwise, returns False

    '''
    return file_exists(package_path, "bower.json")


def run_bower_version():
    '''
    Runs bower --version command.
    Returns stdout if ran successfully. Otherwise, returns False
    '''
    r = subprocess.run(['bower', '--version'], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)

    stdout_str = r.stdout.decode("utf-8")
    stderr_str = r.stderr.decode("utf-8")

    if r.returncode == 0:
        return (True, stdout_str, stderr_str)
    else:
        return (False, stdout_str, stderr_str)


def get_bower_version(bower_version_stdout):
    return bower_version_stdout.rstrip()


def run_bower_install(package_path):
    '''
    Run "bower install" command on shell.
    Returns True if ran successfully. Otherwise, returns False
    '''
    cwd = os.getcwd()
    os.chdir(package_path)

    r = subprocess.run(['bower', 'install'],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    os.chdir(cwd)

    stdout_str = r.stdout.decode("utf-8")
    stderr_str = r.stderr.decode("utf-8")

    if r.returncode == 0:
        return (True, stdout_str, stderr_str)
    else:
        return (False, stdout_str, stderr_str)


def get_dependency_tree_bower(package_path):
    '''
    Run command on shell to get dependency tree.
    Returns a list of dependencies info if ran successfully.
    Otherwise, returns None
    '''
    cwd = os.getcwd()
    os.chdir(package_path)

    r = subprocess.run(['bower', 'list', '--json'],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    os.chdir(cwd)

    stdout_str = r.stdout.decode("utf-8")
    stderr_str = r.stderr.decode("utf-8")

    if r.returncode == 0:
        return (True, stdout_str, stderr_str)
    else:
        return (False, stdout_str, stderr_str)


def traverse_and_collect_dependencies_and_versions(node, results):
    '''
    Traverse dependency tree and collection package name and resolved version
    '''
    try:
        pkgname = node['pkgMeta']['name']
        version = node['pkgMeta']['version']
        dependency_names = node['dependencies']
    except (KeyError, TypeError):
        return None

    results.append((pkgname, version))
    for dependency_name in dependency_names:
        try:
            next_node = node['dependencies'][dependency_name]
        except KeyError:
            continue

        traverse_and_collect_dependencies_and_versions(next_node, results)
    return results


def make_dbcoordinates(coordinates):
    '''
    Parses each line of coordinate info and generates a full coordinates for
    database query

    Input: lines of coordinate info

    Output: a list of full coordinates
    Example: node-js@1.0.0 converted to npm:node-js::1.0.0
    '''
    dbcoordinates = []
    for coordinate in coordinates:
        dbcoordinates.append(_make_dbcoordinate(coordinate))
    return list(set(dbcoordinates))


def _make_dbcoordinate(coordinate):
    '''
    Generates full package coordinate for vulnerability search
    '''
    return ":".join(["bower", coordinate[0], "", coordinate[1], ""])


def _parse_args():
    '''
    argument parser
    Input: path to a NPM package to scan

    '''
    parser = argparse.ArgumentParser(
        description='Finds vulnerabilities in Bower package')
    parser.add_argument("package_path", help="Path to a NPM package to scan")
    parser.add_argument("--outputDir",
                        help="Path to a directory where scan report to be saved")
    parser.add_argument("--outputFile",
                        help="Path to a file where scan report to be saved")
    return parser.parse_args()


def main(input_path):
    '''
    From a given Bower package path, installs dependent packages,
    generates dependency tree, generates full package coordinates using from dependency tree,
    then searches vulnerability database for any vulnerabilities
    '''
    output = {}
    package_manager = "Bower"
    start_time = time.time()
    build_output(output, start_time=start_time,
                 package_manager=package_manager)

    # Check if input path is valid. If not valid, exit with error message
    package_path = os.path.abspath(input_path)
    if is_valid_folder_path(package_path) is False:
        error_message = ("ERROR: Invalid path entered for scan path. Please check the path before proceeding.")
        return build_output(output, code=4, error_message=error_message, package_path=package_path)
    build_output(output, package_path=package_path)

    # Check if bower is installed
    try:
        bower_version_result, bower_version_stdout, bower_version_stderr =\
            run_bower_version()
    except FileNotFoundError:
        error_message = "ERROR: Bower not found in your system. Please install it before proceeding."
        return build_output(output, code=4, error_message=error_message)

    message = "{} dependency checker started.".format(package_manager)
    print(message)
    message += "Scanning \"{}\" directory.".format(package_path)
    build_output(output, message=message, start_time=start_time,
                 package_manager=package_manager, package_path=package_path)

    # Check bower version
    bower_version = get_bower_version(bower_version_stdout)
    message = "Found Bower version: {}".format(bower_version)
    build_output(output, message=message)
    build_output(output, pkgmanager_version=bower_version)
    print(message)

    if not bower_json_exists(package_path):
        error_message = ("ERROR: bower.json file not found. bower.json file is required for scanning.")
        return build_output(output, code=4, error_message=error_message)

    # Makes sure bower install command is ran successfully
    install_result, install_stdout, install_stderr = run_bower_install(package_path)
    if install_result is False:
        error_message = ("ERROR: Dependency checker encountered an error while "
                         "installing dependencies using \"bower install\" command. "
                         "Please see the error message from bower below:\n\n")
        error_message += install_stderr
        return build_output(output, code=4, error_message=error_message)

    dep_tree_result, dep_tree_stdout, dep_tree_stderr =\
        get_dependency_tree_bower(package_path)
    if dep_tree_result is True:
        dep_tree = json.loads(dep_tree_stdout)
        build_output(output, dep_tree=dep_tree)
    else:
        error_message = ("ERROR: Dependency checker encountered an error while "
                         "generating a dependency tree for your project using "
                         "\"bower list --json\" command. "
                         "Please see the error message from Bower below:\n\n")
        error_message += dep_tree_stderr
        return build_output(output, code=4, error_message=error_message)

    coordinates = []
    traverse_and_collect_dependencies_and_versions(dep_tree, coordinates)
    coordinates_without_parent_project = coordinates[1:]
    dbcoordinates = make_dbcoordinates(coordinates_without_parent_project)
    build_output(output, dbcoordinates=dbcoordinates)

    output = find_vulns(output)

    # Process the output
    code = output.get('code')
    # If error, exit with error message
    if code > 0:
        return output

    output = generate_reports(output)
    print(output.get('reports', ""))
    build_output(output)
    return output


if __name__ == "__main__":
    args = _parse_args()
