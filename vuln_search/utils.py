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
import datetime


def _get_lines_from_file(filepath):
    """ Reads dependency:tree command output file
    """
    if os.path.isfile(filepath) is not True:
        return None

    rstripped_lines = []
    with open(filepath, 'r') as f:
        lines = f.readlines()
        for line in lines:
            rstripped_lines.append(line.rstrip())
    return rstripped_lines


def is_valid_folder_path(package_path):
    '''
    Checks that the path exists and that it is a directory
    If not, returns False
    '''

    if (os.path.exists(package_path) is True) and (os.path.isdir(package_path) is True):
        return True
    else:
        return False


def get_datetime(ts):
    return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')


def file_exists(folderpath, filename):
    '''
    From a given folder path, searches for a given filename.
    Returns True if exists, Otherwise, returns false

    '''
    for fname in os.listdir(folderpath):
        if os.path.isfile(os.path.join(folderpath, filename)):
            if fname == filename:
                return True
    return False
