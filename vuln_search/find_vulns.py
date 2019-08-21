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

import time
import datetime
from solr import search_cve_database, search_vuln_using_versionrange
from exit_handler import build_output
from report import (write_report_to_file, get_report_id,
                    make_text_report_from_output, get_path_to_report_file,
                    get_path_to_reports_folder)
import requests


def postprocess(outputs, package_paths, args):
    '''
    Generates a report using dependency checker output
    '''
    output_dirpath = args.outputDir
    output_filepath = args.outputFile

    # Generates a text report file
    report_id = get_report_id(outputs)
    text_report = make_text_report_from_output(outputs)

    if (output_dirpath is None) and (output_filepath is None):
        # if user didn't supply output dir path nor file path, use reports dir.
        reports_dir_path = get_path_to_reports_folder()
        report_file_path = get_path_to_report_file(report_id, reports_dir_path)

    elif (output_dirpath is not None) and (output_filepath is None):
        # Use user supplied path to output dir
        reports_dir_path = output_dirpath
        report_file_path = get_path_to_report_file(report_id, reports_dir_path)

    elif (output_filepath is not None) and (output_dirpath is None):
        # Use user supplied file path
        report_file_path = output_filepath

    else:
        # If user supplies both outputDir and outputFile, use outputFile
        report_file_path = output_filepath

    write_report_to_file(report_file_path, text_report)
    message = "A scan report file is generated and can be found at {} ".format(
        report_file_path)
    print(message)


def find_vulns(output):

    start_time = output.get("start_time")
    dbcoordinates = output.get("dbcoordinates")

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
    build_output(output, code=0, message=message, duration=duration)
    print(message)
    return output
