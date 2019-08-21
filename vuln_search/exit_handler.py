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

import sys


def handle_exit(output):
    '''
    handles exit based on dependency checker error code

    kwargs parameters:
    code: 0 (PASS), anything greater than 0 (FAIL)
    code 1: package manager related error but can still continue
    code 4: critical error that unable to continue
    msg: error message string
    '''

    code = output.get('code')
    if code == 0:
        sys.exit(0)
    else:
        error_message = output.get('error_message')
        if error_message is not None:
            print(error_message)
        sys.exit(1)


def handle_exit_by_code(**kwargs):
    '''
    handles exit based on dependency checker error code

    kwargs parameters:
    code: 0 (PASS), 1 (FAIL)
    msg: error message string
    '''

    code = kwargs.get('code')
    if code == 0:
        sys.exit(0)
    else:
        message = kwargs.get('msg')
        if message:
            print(message)
        sys.exit(1)


def build_output(result, **kwargs):
    '''
    Main function uses this function to build output for the final output
    '''

    if "start_time" in kwargs:
        result['start_time'] = kwargs.get('start_time')

    if "package_manager" in kwargs:
        result['package_manager'] = kwargs.get('package_manager')

    if "pkgmanager_version" in kwargs:
        result['pkgmanager_version'] = kwargs.get("pkgmanager_version")

    if "duration" in kwargs:
        result['duration'] = kwargs.get('duration')

    if "package_path" in kwargs:
        result['package_path'] = kwargs.get('package_path')

    if "code" in kwargs:
        code = kwargs.get('code')
        result['code'] = code

    if "error_message" in kwargs:
        error_message = kwargs.get('error_message')
        result['error_message'] = error_message

    if "warning_message" in kwargs:
        warning_message = kwargs.get('warning_message')

        # Collect warning messages
        existing_warning = result.get('warning_message')
        if existing_warning is None:
            result['warning_message'] = warning_message
        else:
            new_warning = existing_warning + "\n" + warning_message
            result['warning_message'] = new_warning

    if "message" in kwargs:
        message = kwargs.get("message")

        # Collect messages
        messages = result.get("messages")
        if messages is None:
            result['messages'] = [message]
        else:
            messages.append(message)

    if "reports" in kwargs:
        reports = kwargs.get('reports')
        result['reports'] = reports

    if "vulns" in kwargs:
        result['vulns'] = kwargs.get('vulns')

    if "cves" in kwargs:
        result['cves'] = kwargs.get('cves')

    if "dbcoordinates" in kwargs:
        result['dbcoordinates'] = kwargs.get('dbcoordinates')

    if "scopes_included" in kwargs:
        result["scopes_included"] = kwargs.get("scopes_included")

    if "scopes_excluded" in kwargs:
        result["scopes_excluded"] = kwargs.get("scopes_excluded")

    if "dep_tree" in kwargs:
        result["dep_tree"] = kwargs.get("dep_tree")

    return result
