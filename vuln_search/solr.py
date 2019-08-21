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

import requests
import os
from requests.auth import HTTPBasicAuth
from version_handler_rel import Version, VersionRangeParser


def _vuln_db_versionrange_base_url():
    """ Base URL to a solr collection with vulnerability with version range data
    """
    return "http://localhost:8983/solr/pkgname_vrange_cve_merged/select?q="


def _pem_path():
    '''
    Path to solr pem file for ssl
    '''
    pem_path = os.path.join(os.path.dirname(__file__), "solr-ssl.pem")
    if not os.path.exists(pem_path):
        raise NameError("ERROR: Required certificate file to connect to vulnerability database is missing.")
    return pem_path


def _cve_db_base_url():
    """ Base URL to vulnerability solr collection
    """
    return "http://localhost:8983/solr/cves/select?q="


def _fullcoordinate_field_name():
    """ Key name for a solr field that contains package coordinates
    """
    return "coord_full"


def _cve_id_field_name():
    """ Key name for a solr field that contains cve_id
    """
    return "cve_id"


def get_login_info_from_env():
    '''
    Gets username and password from environment
    '''
    try:
        user_name = os.getenv('CL_USERNAME')
        password = os.getenv('CL_PASSWORD')
        if user_name is None:
            raise NameError("ERROR: An environment value, $CL_USERNAME is not set. Please set the value before proceeding.")
        if password is None:
            raise NameError("ERROR: An environment value, $CL_PASSWORD is not set. Please set the value before proceeding.")
    except KeyError:
        print("ERROR: Environment values $CL_USERNAME and/or $CL_PASSWORD not found. Please set these values before proceeding ")

    return user_name, password


def _build_query_url(baseUrl, q, params, cursorMark):
    """ Builds query url using base url and param (package coordinate(s))
    """
    queryUrl = baseUrl[:]
    params['cursorMark'] = cursorMark

    for key, value in q.items():
        if ":" in value:
            q_str = key + ":" + '"{}"&'.format(value)
            queryUrl += q_str
        else:
            q_str = key + ":" + '{}&'.format(value)
            queryUrl += q_str

    for key, value in params.items():
        param_str = key + "=" + value + "&"
        queryUrl +=  param_str

    queryUrl = queryUrl[:-1]  # Removes last &
    return queryUrl


def add_initial_params_for_pagination(params):
    '''
    Add initial params for pagination
    '''
    params['start'] = "0"
    params['sort'] = "id asc"
    params['rows'] = "50"
    return params


def query(baseUrl, q, params=None):
    """ Sends query to solr and gets result
    """

    results = []

    if params is None:
        params = {}

    # Set values for deep pagination
    params = add_initial_params_for_pagination(params)
    cursorMark = "*"
    nextCursorMark = None
    # Gets username and password from environment then query
    user_name, password = get_login_info_from_env()
    #pem_path = _pem_path()

    while cursorMark != nextCursorMark:

        if nextCursorMark is None:
            nextCursorMark = cursorMark

        queryUrl = _build_query_url(baseUrl, q, params, nextCursorMark)
        # response = requests.get(queryUrl, auth=HTTPBasicAuth(user_name, password), verify=pem_path)
        response = requests.get(queryUrl, auth=HTTPBasicAuth(user_name, password))
        response.raise_for_status()

        if _response_data_exists(response) is False:
            return None

        else:
            response_json = response.json()

            if int(response_json['response']['numFound']) > 0:
                results.extend(response_json['response']['docs'])
            else:
                continue

            cursorMark = nextCursorMark
            nextCursorMark = response_json.get("nextCursorMark")

    return results


def _response_data_exists(response):
    if response.json().get('response'):
        return True
    else:
        return False


def search_vuln_database(coordinates):
    """ Queries vulnerability database with coordinates
    """

    if coordinates is None or len(coordinates) == 0:
        return None
    results = {}
    for coordinate in coordinates:
        q = {_fullcoordinate_field_name(): coordinate}
        responses = query(_vuln_db_base_url(), q)

        if responses is not None:
            for response in responses:
                solr_id = response.get('id')
                if solr_id is not None and solr_id not in results:
                    results[solr_id] = response
    if len(results) < 1:
        return None
    else:
        return results


def search_cve_database(vulns):
    '''
    Queries cve database with cve ids
    '''
    if vulns is None or len(vulns) == 0:
        return None

    results = {}
    for solr_id, vuln in vulns.items():
        cve_id = vuln.get("cve_id")

        if cve_id is not None:
            q = {_cve_id_field_name(): cve_id}
            responses = query(_cve_db_base_url(), q)

            if responses is not None:
                for response in responses:
                    if cve_id not in results:
                        results[cve_id] = response

    if len(results) < 1:
        return None
    else:
        return results


def search_vuln_using_versionrange(dbcoordinates):
    '''
    query for vuln using version range
    '''

    results = {}
    dbcoord_coord_and_version_groups = []
    for dbcoordinate in dbcoordinates:
        dbcoord_coord_and_version =\
            convert_dbcoordinate_to_dbcoord_coord_and_version(dbcoordinate)

        if dbcoord_coord_and_version is not None:
            dbcoord_coord_and_version_groups.append(dbcoord_coord_and_version)

    for dbcoordinate, coord, version in dbcoord_coord_and_version_groups:

        q = {"coord": coord}
        responses = query(_vuln_db_versionrange_base_url(), q)

        if responses is not None:
            for response in responses:

                vrange = response.get("vrange")

                if is_in_versionRange(version, vrange):
                    # many dbcoordinate can have the same solr id
                    # some data gets lost when using only solr id so
                    # here, I'm using doc_id
                    cve_id = response.get('cve_id')
                    doc_id = "-".join([cve_id, dbcoordinate])

                    if doc_id is not None and doc_id not in results:
                        # Insert full coordinate and version for report generation
                        response['coord_full'] = dbcoordinate
                        response['version'] = version

                        results[doc_id] = response
                else:
                    # Skip ones that aren't in the version range
                    # Skip ones that version handler can't parse
                    pass

    if len(results) < 1:
        return None
    else:
        return results


def is_in_versionRange(version_str, versionRange_str):
    '''
    Checks if version is in the version range
    '''
    version = Version(version_str)
    vrp = VersionRangeParser()

    try:
        versionRanges = vrp.parse_text(versionRange_str)
    except ValueError:
        return False

    for versionRange in versionRanges:
        if version in versionRange:
            return True
    return False


def convert_dbcoordinate_to_dbcoord_coord_and_version(dbcoordinate):
    '''
    Convert dbcoordinate into 3 components, dbcoordinate, coordinate (w/o version and
    package manager) and version
    '''
    comps = dbcoordinate.split(":")
    package_manager = comps[0]

    if package_manager in ["maven"]:
        coord = ":".join([comps[1], comps[2]])
        version = comps[3]
        return (dbcoordinate, coord, version)

    elif package_manager in ["npm", "bower"]:
        coord = comps[1]
        version = comps[3]
        return (dbcoordinate, coord, version)

    else:
        return None
