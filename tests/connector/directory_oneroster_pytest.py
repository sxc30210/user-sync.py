# Copyright (c) 2016-2017 Adobe Systems Incorporated.  All rights reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import requests
import json
import six

import pytest

from unittest import TestCase
from unittest.mock import patch, Mock


from user_sync.connector.directory_oneroster import *

import user_sync.config
import user_sync.connector.helper
import user_sync.helper
import user_sync.identity_type
from user_sync.error import AssertionException


# class TestOneRosterConnector(TestCase):
#
#     @patch.dict('caller_options', {'host': 'https://mockroster.io/', 'api_token_endpoint': 'https://mockroster.io/oauth/token', 'username': 'oruser', 'password': 'secret', 'country_code': 'US', 'user_identity_type': 'federatedID'})
#     def setUp(self):
#         self.connector = OneRosterConnector(caller_options='caller_options')
#
#     def test_load_users_and_groups(self, groups, extended_attributes, all_users):
#
#
#
#     def test_convert_user(self, user_record):
#
#
#
#     def test_parse_yml_groups(self, groups_list):
#
#
#
#
#
# class TestAuthenticator(TestCase):
#
#
#
#     def test_retrieve_api_token(self):
#
#
#
#
#
#
# class TestConnection(TestCase):
#
#
#
#     def test_get_user_list(self, group_filter, group_name, user_filter):
#
#
#     def test_get_sourced_id(self, group_filter, group_name):
#
#
#     def test_get_classlist_for_course(self, group_name):


class TestResultParser(TestCase):
    def setUp(self):
        self.result_parser = ResultParser()



    @patch('user_sync.connector.directory_oneroster.ResultParser.parse_results')
    def test_parse_results(self, result_set, extended_attributes, original_group):
        result_set = [{'userId': 'bc16d091-7017-4f2f-9109-250fd590ca6a',
                      'sourcedId': 'bc16d091-7017-4f2f-9109-250fd590ca6a',
                      'status': 'active', 'dateLastModified': '2018-04-01 21:05:50',
                      'metadata': '', 'enabledUser': '1', 'userIds': '',
                      'identifier': 'GbYh-2CV5-Dz19', 'schoolId': 'f5897384-9488-466f-b049-1992f7a53f15',
                      'givenName': 'Antonietta', 'familyName': 'Consterdine', 'middleName': 'Feliza',
                      'email': 'aconsterdine@woodland.perficientads.com', 'username': 'aconsterdine',
                      'phone': '354-733-0622', 'role': 'student', 'grades': '07', 'type': 'LDAP', 'password': 'secret'}]

        assert result_set == None

    def test_create_user_object(self):

        user = {'userId': 'bc16d091-7017-4f2f-9109-250fd590ca6a',
                      'sourcedId': 'bc16d091-7017-4f2f-9109-250fd590ca6a',
                      'status': 'active', 'dateLastModified': '2018-04-01 21:05:50',
                      'metadata': '', 'enabledUser': '1', 'userIds': '',
                      'identifier': 'GbYh-2CV5-Dz19', 'schoolId': 'f5897384-9488-466f-b049-1992f7a53f15',
                      'givenName': 'Antonietta', 'familyName': 'Consterdine', 'middleName': 'Feliza',
                      'email': 'aconsterdine@woodland.perficientads.com', 'username': 'aconsterdine',
                      'phone': '354-733-0622', 'role': 'student', 'grades': '07', 'type': 'LDAP', 'password': 'secret'}

        original_group = 'courses::Alg-102::students'

        created_user = self.result_parser.create_user_object(user, [], original_group)

        expected_user = {'domain': 'woodland.perficientads.com', 'firstname': 'Antonietta',
                         'lastname': 'Consterdine', 'email': 'aconsterdine@woodland.perficientads.com',
                         'groups': ['courses::Alg-102::students'],
                         'source_attributes': {'email': 'aconsterdine@woodland.perficientads.com',
                                               'username': 'aconsterdine', 'givenName': 'Antonietta',
                                               'familyName': 'Consterdine', 'domain': 'woodland.perficientads.com',
                                               'enabledUser': '1', 'grades': '07', 'identifier': 'GbYh-2CV5-Dz19',
                                               'metadata': '', 'middleName': 'Feliza', 'phone': '354-733-0622',
                                               'role': 'student', 'schoolId': 'f5897384-9488-466f-b049-1992f7a53f15',
                                               'sourcedId': 'bc16d091-7017-4f2f-9109-250fd590ca6a', 'status': 'active',
                                               'type': 'LDAP', 'userId': 'bc16d091-7017-4f2f-9109-250fd590ca6a', 'userIds': ''},
                         'username': 'aconsterdine@woodland.perficientads.com'}

        assert (created_user == expected_user)