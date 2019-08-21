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

import pytest
import find_vulns_npm as fvn

@pytest.fixture
def dependecyFileLines():
    return ["/pkg/finalhandler:finalhandler@0.4.1:undefined",
            "/pkg/unpipe:unpipe@1.0.0:undefined",
            "/pkg/fresh:fresh@0.3.0:undefined"]

@pytest.fixture
def dependecyFileLine():
    return "/package/node_modules/array-flatten:array-flatten@1.1.1:undefined"

def test_getting_pkgName(dependecyFileLine):
    assert fvn._npm_pkg_name(dependecyFileLine) == "array-flatten"

def test_getting_versionName(dependecyFileLine):
    assert fvn._npm_version_name(dependecyFileLine) == "1.1.1"

def test_getting_pkgVersionName(dependecyFileLine):
    assert fvn._npm_pkg_version_name(dependecyFileLine) == "array-flatten@1.1.1"

def test_making_pkgCoordinate(dependecyFileLine):
    assert fvn._make_npm_pkgCoordinate(dependecyFileLine) ==\
        "npm:array-flatten::1.1.1:"
