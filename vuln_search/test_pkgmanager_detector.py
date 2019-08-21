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
from pkgmanager_detector import PkgManagerDetector


def test_find_all_no_args():
    p = PkgManagerDetector("/data01/package/srcclr/test/java/apache_bigtop")
    pkgmanagers = p.find_all()
    assert pkgmanagers == set(("gradle", "maven"))


def test_include_1():
    fargs = FakeArgs(include="MAVEN, GRADLE, NPM")
    p = PkgManagerDetector("/data01/package/srcclr/test/java/apache_bigtop", args=fargs)
    pkgmanagers = p.find_all()
    assert pkgmanagers == set(("gradle", "maven"))


def test_include_2():
    fargs = FakeArgs(include="MAVEN,GRADLE,NPM")
    p = PkgManagerDetector("/data01/package/srcclr/test/java/apache_bigtop", args=fargs)
    pkgmanagers = p.find_all()
    assert pkgmanagers == set(("gradle", "maven"))


def test_exclude_1():
    fargs = FakeArgs(exclude="MAVEN,GRADLE,NPM")
    p = PkgManagerDetector("/data01/package/srcclr/test/java/apache_bigtop", args=fargs)
    pkgmanagers = p.find_all()
    assert pkgmanagers == set()


def test_include_exclude_1():
    fargs = FakeArgs(include="Maven", exclude="GRADLE,NPM")
    p = PkgManagerDetector("/data01/package/srcclr/test/java/apache_bigtop", args=fargs)
    pkgmanagers = p.find_all()
    assert pkgmanagers == set(("maven",))


class FakeArgs():
    def __init__(self, include=None, exclude=None):
        self.pkgmanager_include = include
        self.pkgmanager_exclude = exclude
