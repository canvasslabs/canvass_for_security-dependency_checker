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
import find_vulns_maven as fvm

@pytest.fixture
def depFileLines():
    return ["+- javax.enterprise:cdi-api:jar:1.0-SP4:provided",
            "+- org.easymock:easymock:jar:3.5.1:test",
            "+- org.apache.struts:struts-annotations:jar:1.0.6:compile (optional)",
            "org.apache.struts:struts2-cdi-plugin:jar:2.6-SNAPSHOT ",
            "|  \\- org.hamcrest:hamcrest-core:jar:1.3:compile (optional) "]


def test_getting_pkgName(dependecyFileLine):
    assert fvn._npmPkgName(dependecyFileLine) == "array-flatten"

def test_getting_versionName(dependecyFileLine):
    assert fvn._npmVersionName(dependecyFileLine) == "1.1.1"

def test_getting_pkgVersionName(dependecyFileLine):
    assert fvn._npmPkgVersionName(dependecyFileLine) == "array-flatten@1.1.1"

def test_making_pkgCoordinate(dependecyFileLine):
    assert fvn._make_npm_pkgCoordinate(dependecyFileLine) ==\
        "npm:array-flatten::1.1.1:"
