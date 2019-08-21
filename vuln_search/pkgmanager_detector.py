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


class PkgManagerDetector():
    def __init__(self, package_path, args=None):
        self.package_path = package_path
        self.args = args
        self.supported_pkgmanagers = ("maven", "gradle", "npm", "yarn", "bower")
        self.find_pkgmanager_files()

    def find_pkgmanager_files(self):
        '''
        Find all package manager manifest files in a package
        '''
        supported_files = ("pom.xml", "package.json", "yarn.lock", "build.gradle", "build.gradle.kts", "bower.json")
        pkgmanager_files = []
        for filename in self.get_filenames():
            if filename in supported_files:
                pkgmanager_files.append(filename)
        self.pkgmanager_files = pkgmanager_files
        return self.pkgmanager_files

    def find_all(self):

        self.find_all_pkgmanagers()

        if self.args:

            pkgmanager_include = self.args.pkgmanager
            pkgmanager_exclude = self.args.pkgmanager_skip

            includes = self.cleanup_and_parse_user_args(pkgmanager_include)
            excludes = self.cleanup_and_parse_user_args(pkgmanager_exclude)
        else:
            includes = None
            excludes = None

        if includes and (excludes is None):
            # user defined package manager to scan
            return includes.intersection(self.all_pkgmanagers)

        elif excludes and (includes is None):
            # user defined package manager to skip
            # default but except excludes
            pkgmanagers = self.all_pkgmanagers - excludes
            return pkgmanagers

        elif (includes is None) and (excludes is None):
            # default - no includes nor excludes
            return self.all_pkgmanagers

        else:
            # includes and excludes both have values
            return (includes - excludes)

    def cleanup_and_parse_user_args(self, userinput):
        '''
        Clean up user input and parse package manager name
        '''

        if userinput is None:
            return None

        pkgmanagers = set()
        comps = userinput.split(",")
        for comp in comps:
            pkgmanager = (comp.strip()).lower()
            if pkgmanager in self.supported_pkgmanagers:
                pkgmanagers.add(pkgmanager)
        return pkgmanagers

    def find_all_pkgmanagers(self):

        pkgmanagers = set()
        if self.is_maven():
            pkgmanagers.add("maven")
        if self.is_gradle():
            pkgmanagers.add("gradle")
        if self.is_yarn():
            pkgmanagers.add("yarn")
        if self.is_npm():
            pkgmanagers.add("npm")
        if self.is_bower():
            pkgmanagers.add("bower")

        self.all_pkgmanagers = pkgmanagers
        return self.all_pkgmanagers

    def is_maven(self):
        if "pom.xml" in self.pkgmanager_files:
            return True
        else:
            return False

    def is_gradle(self):
        if ("build.gradle" in self.pkgmanager_files) or ("build.gradle.kts" in self.pkgmanager_files):
            return True
        else:
            return False

    def is_yarn(self):
        if ("yarn.lock" in self.pkgmanager_files):
            return True
        else:
            return False

    def is_npm(self):
        if ("yarn.lock" not in self.pkgmanager_files) and ("package.json" in self.pkgmanager_files):
            return True
        else:
            return False

    def is_bower(self):
        if ("bower.json" in self.pkgmanager_files):
            return True
        else:
            return False

    def get_filenames(self):
        '''
        Get filenames from package folder
        '''
        return [filename for filename in os.listdir(self.package_path)
                if os.path.isfile(os.path.join(self.package_path, filename))]
