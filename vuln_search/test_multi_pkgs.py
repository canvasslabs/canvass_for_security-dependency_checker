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
import subprocess
from collections import defaultdict
import time
import datetime
from utils import get_datetime
import json
import pickle
#import find_vulns_yarn as fvyarn
from solr import search_vuln_database, search_vuln_using_versionrange


def test_compare_versionrange_and_coordinate(dbcoordinates):
    '''
    Test function to compare results obtained from using version range and coordinate
    '''
    vulns_coord_full = search_vuln_database(dbcoordinates)
    vulns = search_vuln_using_versionrange(dbcoordinates)

    if vulns_coord_full is None:
        vulns_coord_full = {}

    if vulns is None:
        vulns = {}

    vulns_coord_full = [vc['coord_full'] for i, vc in vulns_coord_full.items()]
    vulns_vrange_full = [vc['coord_full'] for i, vc in vulns.items()]

    only_coord = set(vulns_coord_full) - set(vulns_vrange_full)
    only_vrange =  set(vulns_vrange_full) - set(vulns_coord_full)
    diff = set(vulns_coord_full).symmetric_difference(vulns_vrange_full)

    if len(diff) > 0:
        print("only in coord", only_coord)
        print("only in vrange", only_vrange)
        import pdb; pdb.set_trace()
        raise AssertionError("vulns are different b/w vulns ver range and vulns coord")
    else:
        return vulns


def get_package_folder_paths(root_folder_paths):
    '''
    Scans given root folders and returns paths to package directories
    '''
    pkg_folder_paths = []
    for path in root_folder_paths:
        for item in os.listdir(path):
            if os.path.isdir(os.path.join(path, item)):
                pkg_folder_paths.append(os.path.join(path, item))
    return pkg_folder_paths


def run(pkgfolder_path):
    '''
    Runs dependency_checker and returns (run result, stdout, stderr)
    '''
    r = subprocess.run(['python3', 'dependency_checker.py', pkgfolder_path],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if r.returncode == 0:
        return (True, r.stdout.decode('utf-8'), r.stderr.decode('utf-8'))
    else:
        return (False, r.stdout.decode('utf-8'), r.stderr.decode('utf-8'))


def get_pkgmanager_name_from_stdout(stdout):
    '''
    Parses first line of stdout and gets the package manager name
    '''
    lines = stdout.splitlines()

    try:
        pkgmanger_name = lines[0].split(" ")[0]
    except IndexError:
        pkgmanger_name = None
    return pkgmanger_name


def main_test_module(root_folder_paths=None, package_paths=None, limit=None, test_name=None):

    start_time = time.time()
    reports = defaultdict(list)
    pass_cnt = 0
    fail_cnt = 0
    scanned_pkg_paths = []

    if root_folder_paths is None and package_paths is None:
        print("ERROR: Need package paths to scan")
        raise AssertionError

    # If user enters root folder of packages, scan for the paths then run
    if package_paths is None:
        pkgfolder_paths = get_package_folder_paths(root_folder_paths)
    else:
        # If user enters, direct paths to packages, use that instead.
        pkgfolder_paths = package_paths


    for pkgfolder_path in pkgfolder_paths:
        print("working on... ", pkgfolder_path)
        report = {}
        run_result, stdout, stderr = run(pkgfolder_path)

        report['result'] = run_result
        report['stdout'] = stdout
        report['stderr'] = stderr
        report['path'] = pkgfolder_path
        report['package_name'] = os.path.basename(pkgfolder_path)
        report['pkgmanager_name'] = get_pkgmanager_name_from_stdout(stdout)


        if run_result:
            pass_cnt += 1
            reports['pass'].append(report)
        else:
            fail_cnt += 1
            reports['fail'].append(report)

        print("report added")
        scanned_pkg_paths.append(pkgfolder_path)

        #import pdb; pdb.set_trace()
        if limit is not None and len(scanned_pkg_paths) == limit:
            break

    end_time = time.time()
    duration = str(datetime.timedelta(seconds=(end_time - start_time))) + " (hr:min:sec)"
    ts = get_datetime(time.time())
    reports['summary'] = {"duration": duration,
                          "root_folder_paths": root_folder_paths,
                          "timestamp": ts,
                          "pass_cnt": pass_cnt,
                          "fail_cnt": fail_cnt,
                          "scanned_pkg_cnt": len(scanned_pkg_paths),
                          "scanned_pkg_paths": scanned_pkg_paths}

    json.dump(reports, open("./test_report_" + test_name + "_" + ts + ".json", 'w'))
    return reports



def main_test_function(main_func, root_folder_paths=None, package_paths=None,
                       limit=None, test_name=None):

    start_time = time.time()
    reports = defaultdict(list)
    pass_cnt = 0
    fail_cnt = 0
    scanned_pkg_paths = []

    if root_folder_paths is None and package_paths is None:
        print("ERROR: Need package paths to scan")
        raise AssertionError

    # If user enters root folder of packages, scan for the paths then run
    if package_paths is None:
        pkgfolder_paths = get_package_folder_paths(root_folder_paths)
    else:
        # If user enters, direct paths to packages, use that instead.
        pkgfolder_paths = package_paths

    cnt = 0
    comparsions = []
    for pkgfolder_path in pkgfolder_paths:
        vulns_pair = []
        for use_coord in [True, False]:
            report = run_main(main_func, pkgfolder_path, use_coord, reports, pass_cnt, fail_cnt)

            if report is None:
                import pdb; pdb.set_trace()

            vulns = set(report['vuln_coords'])
            if vulns is None:
                vulns = []
            vulns_pair.append(vulns)

        only_coord = set(vulns_pair[0]) - set(vulns_pair[1])
        only_vrange = set(vulns_pair[1]) - set(vulns_pair[2])


        diff = set(vulns_pair[0]).symmetric_difference(set(vulns_pair[1]))

        comp_result = {}
        if use_coord is True:
            comp_result[pkgfolder_path + "_use_coord"] = {"diff": diff, "only_coord": only_coord, "only_vrange": only_vrange}
        else:
            comp_result[pkgfolder_path + "_use_vrange"] = {"diff": diff, "only_coord": only_coord, "only_vrange": only_vrange}


        import pdb; pdb.set_trace()
        comparsions.append(comp_result)


        if len(diff) > 0:
            print("results are different between version range and coordinate based search")

        cnt += 1
        print("report added. {} finished.".format(str(cnt)))


        scanned_pkg_paths.append(pkgfolder_path)
        if limit is not None and len(scanned_pkg_paths) == limit:
            break


    end_time = time.time()
    duration = str(datetime.timedelta(seconds=(end_time - start_time))) + " (hr:min:sec)"
    ts = get_datetime(time.time())
    reports['summary'] = {"duration": duration,
                          "root_folder_paths": root_folder_paths,
                          "timestamp": ts,
                          "pass_cnt": pass_cnt,
                          "fail_cnt": fail_cnt,
                          "scanned_pkg_cnt": len(scanned_pkg_paths),
                          "scanned_pkg_paths": scanned_pkg_paths
    }
    reports['comparsions'] = comparsions

    #json.dump(reports, open("./test_report_" + test_name + "_" + ts + ".json", 'w'))
    return reports


def run_main(main_func, pkgfolder_path, use_fullcoord, reports, pass_cnt, fail_cnt):
    print("working on... ", pkgfolder_path)
    report = {}

    output = main_func(pkgfolder_path, use_fullcoord)

    run_result = False
    code = output.get('code')
    if code == 0:
        run_result = True

    report['result'] = run_result
    report['output'] = output
    vulns = output.get('vulns', {})
    report['vulns'] = vulns
    report['cves'] = output.get('cves')

    vuln_coords = [vc['coord_full'] for i, vc in vulns.items()]

    report['vuln_coords'] = vuln_coords
    report['path'] = output.get('package_path')
    report['pkgmanager_name'] = output.get("package_manager")

    if run_result is True:
        pass_cnt += 1
        reports['pass'].append(report)
    else:
        fail_cnt += 1
        reports['fail'].append(report)
    return report


def get_lines_from_text(fp):
    output = []
    with open(fp, 'r')as f:
        for line in f.readlines():
            output.append(line.rstrip())  #619 urls
    return output


def test_js():
    # list of js package path. Packages that have package.json. Includes npm, jquery, bower. #619 packages
    js_paths = set(get_lines_from_text("/home/jae/git/vuln_search/data/tests/path_to_js_packages_with_package_json.txt"))
    js_exclude = set(["/data01/package/srcclr/test/js/OpenframeProject_Openframe-glslViewer"]) # this pkg asks for sudo password.
    js_paths_good = js_paths - js_exclude

    # Generate report
    reports = main_test_module(root_folder_paths=None, package_paths=js_paths, limit=len(js_paths_good), test_name=str(len(js_paths_good)) + "_js_041419_always_do_npm_install")
    return reports


def test_maven():
    maven_and_gradle_paths = get_lines_from_text("/home/jae/git/vuln_search/data/tests/path_to_maven_pkgs.txt")
    gradle_paths = get_lines_from_text("/home/jae/git/vuln_search/data/tests/path_to_gradle_pkgs.txt") #57?
    maven_paths = list(set(maven_and_gradle_paths) - set(gradle_paths))  #369
    reports = main_test_module(root_folder_paths=None,
                   package_paths=maven_paths,
                   limit=len(maven_paths),
                   test_name=str(len(maven_paths)) + "_maven_041419_notify_user_add_deleting_dependency_file")
    return reports


def test_gradle():
    gradle_paths = get_lines_from_text("/home/jae/git/vuln_search/data/tests/path_to_gradle_pkgs.txt") #57?
    reports = main_test_module(root_folder_paths=None,
                   package_paths=gradle_paths,
                   limit=len(gradle_paths),
                   test_name=str(len(gradle_paths)) + "_gradle_041419")
    return reports


def test_gradle_from_top10k_java():
    gradle_paths = get_lines_from_text(
        "/home/jae/git/vuln_search/data/tests/path_to_gradle_pkgs_top10k_partial_04142019-1117.txt") #651 pkgs

    gradle_paths = gradle_paths[:50]
    print("# of gradle pkgs to scan", len(gradle_paths))
    reports = main_test_module(root_folder_paths=None,
                   package_paths=gradle_paths,
                   limit=len(gradle_paths),
                   test_name=str(len(gradle_paths)) + "_gradle_top10k_0-100_041419")
    return reports


def test_maven_from_top10k_java():
    gradle_paths = get_lines_from_text(
        "/home/jae/git/vuln_search/data/tests/path_to_gradle_pkgs_top10k_partial_04142019-1117.txt")

    maven_and_gradle_paths = get_lines_from_text("/home/jae/git/vuln_search/data/tests/path_to_maven_pkgs_top10k_partial_04142019-1117.txt")
    maven_and_gradle_paths = maven_and_gradle_paths[:100]
    maven_only_paths = set(maven_and_gradle_paths) - set(gradle_paths)

    print("# of maven pkgs to scan", len(maven_only_paths))
    reports = main_test_module(root_folder_paths=None,
                   package_paths=maven_only_paths,
                   limit=len(maven_only_paths),
                   test_name=str(len(maven_only_paths)) + "_maven_only_top10k_0-100_041419")
    return reports

def test_npm_from_top10k_js():
    npm_bower_yarn_paths = get_lines_from_text(
        "/home/jae/git/vuln_search/data/tests/path_to_npm_yarn_bower_has_package_json_file_top_10k_04142019-1117_partial.txt")

    bower_paths = get_lines_from_text("/home/jae/git/vuln_search/data/tests/path_to_bower_pkgs_top_10k_04142019-1117_partial.txt")
    yarn_paths = get_lines_from_text("/home/jae/git/vuln_search/data/tests/path_to_yarn_pkgs_top_10k_04142019-1117_partial.txt")

    npm_bower_yarn_paths = npm_bower_yarn_paths[:160]
    npm_only_paths = set(npm_bower_yarn_paths) - set(bower_paths) - set(yarn_paths)

    print("# of npm pkgs to scan", len(npm_only_paths))
    reports = main_test_module(root_folder_paths=None,
                   package_paths=npm_only_paths,
                   limit=len(npm_only_paths),
                   test_name=str(len(npm_only_paths)) + "_maven_only_top10k_0-100_041419")
    return reports



def test_yarn_from_top10k_js():
    # npm_bower_yarn_paths = get_lines_from_text(
    #     "/home/jae/git/vuln_search/data/tests/path_to_npm_yarn_bower_has_package_json_file_top_10k_04142019-1117_partial.txt")

    # bower_paths = get_lines_from_text("/home/jae/git/vuln_search/data/tests/path_to_bower_pkgs_top_10k_04142019-1117_partial.txt")
    #yarn_paths = get_lines_from_text("/home/jae/git/vuln_search/data/tests/path_to_yarn_pkgs_top_10k_04142019-1117_partial.txt")
    yarn_paths = get_lines_from_text("/home/jae/git/vuln_search/data/tests/path_to_yarn_pkgs_top10k_05032019.txt")

    yarn_paths = yarn_paths[:1]
    #npm_bower_yarn_paths = npm_bower_yarn_paths[:160]
    #npm_only_paths = set(npm_bower_yarn_paths) - set(bower_paths) - set(yarn_paths)

    print("# of yarn pkgs to scan", len(yarn_paths))
    reports = main_test_module(root_folder_paths=None,
                   package_paths=yarn_paths,
                   limit=len(yarn_paths),
                   test_name=str(len(yarn_paths)) + "_yarn_only_top10k_0-100_050319")
    return reports


def test_yarn_from_srcclr():
    yarn_paths = get_lines_from_text("/home/jae/git/vuln_search/data/tests/path_to_yarn_pkgs_srcclr_05032019.txt")
    #npm_bower_yarn_paths = npm_bower_yarn_paths[:160]
    #npm_only_paths = set(npm_bower_yarn_paths) - set(bower_paths) - set(yarn_paths)

    yarn_paths = yarn_paths[12:]
    print("# of yarn pkgs to scan", len(yarn_paths))
    reports = main_test_module(root_folder_paths=None,
                   package_paths=yarn_paths,
                   limit=len(yarn_paths),
                   test_name=str(len(yarn_paths)) + "_yarn_only_top10k_0-100_050319")
    return reports


def test_yarn_from_srcclr_for_comparsion_bw_coord_and_vrange():
    yarn_paths = get_lines_from_text("/home/jae/git/vuln_search/data/tests/path_to_yarn_pkgs_srcclr_05032019.txt")
    #npm_bower_yarn_paths = npm_bower_yarn_paths[:160]
    #npm_only_paths = set(npm_bower_yarn_paths) - set(bower_paths) - set(yarn_paths)

    yarn_paths = yarn_paths[8:10]
    print("# of yarn pkgs to scan", len(yarn_paths))

    reports = main_test_function(fvyarn.main, root_folder_paths=None, package_paths=yarn_paths,
                                 limit=len(yarn_paths), test_name=str(len(yarn_paths)) + "_yarn_only_top10k_0-100_050319")

    return reports


def test_bower_from_top10k_js(start_idx, end_idx):

    # npm_bower_yarn_paths = get_lines_from_text(
    #     "/home/jae/git/vuln_search/data/tests/path_to_npm_yarn_bower_has_package_json_file_top_10k_04142019-1117_partial.txt")

    # bower_paths = get_lines_from_text("/home/jae/git/vuln_search/data/tests/path_to_bower_pkgs_top_10k_04142019-1117_partial.txt")
    #yarn_paths = get_lines_from_text("/home/jae/git/vuln_search/data/tests/path_to_yarn_pkgs_top_10k_04142019-1117_partial.txt")
    bower_paths = get_lines_from_text("/home/jae/git/vuln_search/data/tests/path_to_bower_pkgs_top_10k_04142019-1117_partial.txt")
    yarn_paths = get_lines_from_text("/home/jae/git/vuln_search/data/tests/path_to_yarn_pkgs_top10k_05032019.txt")

    bower_paths = bower_paths[start_idx:end_idx]

    bower_paths = sorted(list(set(bower_paths) - set(yarn_paths)))

    print("# of bower pkgs to scan", len(bower_paths))
    reports = main_test_module(root_folder_paths=None,
                   package_paths=bower_paths,
                   limit=len(bower_paths),
                   test_name=str(len(bower_paths)) + "_bower_only_top10k_0-100_050319")
    return reports


if __name__ == "__main__":
    # root_folder_paths = ["/home/jae/git/vuln_search/data/java", "/home/jae/git/vuln_search/data/js"]
    root_folder_paths = ["/data01/package/srcclr/test/java"]
    root_folder_paths = ["/data01/package/srcclr/test/js"]

    # list of paths that I tested for the 1st time (java and js = 200 packages)
    #scanned_paths = pickle.load(open('/home/jae/git/vuln_search/vuln_search/scanned_paths.pickle', 'rb'))

    # reports = test_maven()
    # reports = test_gradle()
    # reports = test_js()
    # reports = test_maven_from_top10k_java()
    # reports = test_gradle_from_top10k_java()  # reduced to 50
    # reports = test_npm_from_top10k_js()
    # reports = test_yarn_from_top10k_js()
    # reports = test_yarn_from_srcclr()
    # reports = test_yarn_from_srcclr_for_comparsion_bw_coord_and_vrange()

    reports = test_bower_from_top10k_js(0, 60)
