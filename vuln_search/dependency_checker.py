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

import find_vulns_gradle
import find_vulns_maven
import find_vulns_npm
import find_vulns_bower
import find_vulns_yarn
import find_vulns
import argparse
import os
from utils import is_valid_folder_path
from pkgmanager_detector import PkgManagerDetector
from exit_handler import handle_exit_by_code


class DependencyChecker():
    def __init__(self, package_path, pkgmanager, args=None):
        self.package_path = package_path
        self.pkgmanager = pkgmanager.lower()
        self.args = args

    def run(self):
        main_func = self.get_main_func()

        if not main_func:
            raise TypeError("Unable to detect any package manager that dependency checker supports.")
        return main_func(self.package_path)

    def get_main_func(self):
        if self.pkgmanager == "maven":
            return find_vulns_maven.main
        elif self.pkgmanager == "gradle":
            return find_vulns_gradle.main
        elif self.pkgmanager == "yarn":
            return find_vulns_yarn.main
        elif self.pkgmanager == "npm":
            return find_vulns_npm.main
        elif self.pkgmanager == "bower":
            return find_vulns_bower.main
        else:
            return None


def _parse_args():
    '''
    ArgumentParser
    Takes path to a mvn package as an input
    '''
    parser = argparse.ArgumentParser(description='Dependency checker')
    parser.add_argument("package_path",
                        help="Path to a project to scan")
    parser.add_argument("--outputDir",
                        help="set report file directory path")
    parser.add_argument("--outputFile",
                        help="set report file path")
    parser.add_argument("--pkgmanager",
                        help="")
    parser.add_argument("--pkgmanager-skip",
                        help="")
    return parser.parse_args()


def main(args):
    # Check if package path is valid
    package_path = os.path.abspath(args.package_path)
    if is_valid_folder_path(package_path) is False:
        error_message = ("ERROR: Invalid path entered for package_path value. Please check the path before proceeding. ")
        handle_exit_by_code(code=1, msg=error_message)

    # Check if output report directory path is valid
    output_dirpath = None
    if args.outputDir is not None:
        output_dirpath = os.path.abspath(args.outputDir)
        if is_valid_folder_path(output_dirpath) is False:
            error_message = ("ERROR: Invalid path entered for outputDir value. Please check the path before proceeding. ")
            handle_exit_by_code(code=1, msg=error_message)

    # Find package managers in input project
    pm_detector = PkgManagerDetector(package_path, args)
    pkgmanagers = pm_detector.find_all()

    print("Found {} package manager(s).".format(", ".join(pkgmanagers)))

    # Exit if no package manager is found
    if not pkgmanagers:
        error_message = ("ERROR: Unable to detect any package manager that dependency checker supports in your project. "
                         "Dependency checker currently supports scanning on Maven, Gradle, Yarn, Bower, and NPM projects.")
        handle_exit_by_code(code=1, msg=error_message)

    # Find vulnerabilities in input package using all the package managers
    outputs = []
    for pkgmanager in pkgmanagers:
        dependency_checker = DependencyChecker(package_path, pkgmanager, args)
        output = dependency_checker.run()

        code = output.get("code")

        if code == 0:
            outputs.append(output)
        elif code == 1:
            error_message = output.get('error_message')
            if error_message is not None:
                print(error_message)

            outputs.append(output)
        else:
            error_message = output.get('error_message')
            if error_message is not None:
                print(error_message)

            outputs.append(output)

    # Generate report using the outputs
    find_vulns.postprocess(outputs, package_path, args)


if __name__ == "__main__":
    args = _parse_args()
    main(args)
