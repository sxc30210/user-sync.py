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


class TestOneRosterConnector(TestCase):

    def setUp(self):
        caller_options = {'host': 'https://mockroster.io/', 'api_token_endpoint': 'https://mockroster.io/oauth/token', 'username': 'oruser', 'password': 'secret', 'country_code': 'US', 'user_identity_type': 'federatedID'}
        self.connector = OneRosterConnector(caller_options)
        self.result_parser = ResultParser()

    def test_parse_yml_groups(self):
        mock_adobe_user_group = {'courses::Alg-102::students'}

        return_dict_format = self.connector.parse_yml_groups(mock_adobe_user_group)

        expected_dict_format = {'courses': {'alg-102': 'students', 'original_group': 'courses::Alg-102::students'}}

        assert expected_dict_format == return_dict_format
        self.assertRaises(ValueError, lambda: self.connector.parse_yml_groups({'course::Alg-102::students'}))

    @patch('user_sync.connector.directory_oneroster.Authenticator.retrieve_api_token')
    def test_retrieve_api_token(self, MockCall):
        call = MockCall()
        call.posts.return_value = b'{"access_token":"2ad79b29-af22-42be-8c15-f777369eb726","token_type":"bearer","expires_in":25945966,"scope":"all"}'

        expected_token = '2ad79b29-af22-42be-8c15-f777369eb726'

        returned_token = json.loads(call.posts())['access_token']
        assert returned_token == expected_token

    def test_parse_results(self):
        result_set = [{'userId': 'bc16d091-7017-4f2f-9109-250fd590ca6a',
                       'sourcedId': 'bc16d091-7017-4f2f-9109-250fd590ca6a',
                       'status': 'active', 'dateLastModified': '2018-04-01 21:05:50', 'metadata': '', 'enabledUser': '1',
                        'userIds': '', 'identifier': 'GbYh-2CV5-Dz19', 'schoolId': 'f5897384-9488-466f-b049-1992f7a53f15',
                         'givenName': 'Antonietta', 'familyName': 'Consterdine', 'middleName': 'Feliza',
                        'email': 'aconsterdine@woodland.perficientads.com', 'username': 'aconsterdine', 'phone': '354-733-0622',
                        'role': 'student', 'grades': '07', 'type': 'LDAP', 'password': 'secret'},
                    {'userId': '18e27d22-49d9-407e-a38e-d5ad35577e53',
                     'sourcedId': '18e27d22-49d9-407e-a38e-d5ad35577e53',
                        'status': 'active', 'dateLastModified': '2018-02-13 12:37:53', 'metadata': '', 'enabledUser': '1',
                        'userIds': '', 'identifier': 'Ur9l-oYH3-VpQ5', 'schoolId': 'f5897384-9488-466f-b049-1992f7a53f15',
                    'givenName': 'Ariel', 'familyName': 'Rome', 'middleName': 'Edeline',
                    'email': 'arome@woodland.perficientads.com', 'username': 'arome', 'phone': '926-670-4557', 'role': 'student',
                    'grades': '07', 'type': 'LDAP', 'password': 'secret'}]

        original_group = 'classes::Art ii -Spring::students'

        returned_dict = self.result_parser.parse_results(result_set, [], original_group)

        expected_user_dict = {'bc16d091-7017-4f2f-9109-250fd590ca6a':
                                  {'domain': 'woodland.perficientads.com', 'firstname': 'Antonietta',
                                   'lastname': 'Consterdine', 'email': 'aconsterdine@woodland.perficientads.com',
                                   'groups': ['classes::Art ii -Spring::students'],
                                   'source_attributes':
                                       {'email': 'aconsterdine@woodland.perficientads.com',
                                        'username': 'aconsterdine', 'givenName': 'Antonietta',
                                        'familyName': 'Consterdine', 'domain': 'woodland.perficientads.com',
                                        'enabledUser': '1', 'grades': '07', 'identifier': 'GbYh-2CV5-Dz19',
                                        'metadata': '', 'middleName': 'Feliza', 'phone': '354-733-0622',
                                        'role': 'student', 'schoolId': 'f5897384-9488-466f-b049-1992f7a53f15',
                                        'sourcedId': 'bc16d091-7017-4f2f-9109-250fd590ca6a', 'status': 'active', 'type': 'LDAP',
                                        'userId': 'bc16d091-7017-4f2f-9109-250fd590ca6a', 'userIds': ''},
                                   'username': 'aconsterdine@woodland.perficientads.com'},
                              '18e27d22-49d9-407e-a38e-d5ad35577e53':
                                  {'domain': 'woodland.perficientads.com', 'firstname': 'Ariel', 'lastname': 'Rome',
                                   'email': 'arome@woodland.perficientads.com',
                                   'groups': ['classes::Art ii -Spring::students'],
                                   'source_attributes':
                                       {'email': 'arome@woodland.perficientads.com', 'username': 'arome',
                                        'givenName': 'Ariel', 'familyName': 'Rome', 'domain': 'woodland.perficientads.com',
                                        'enabledUser': '1', 'grades': '07', 'identifier': 'Ur9l-oYH3-VpQ5', 'metadata': '',
                                        'middleName': 'Edeline', 'phone': '926-670-4557', 'role': 'student',
                                        'schoolId': 'f5897384-9488-466f-b049-1992f7a53f15', 'sourcedId': '18e27d22-49d9-407e-a38e-d5ad35577e53',
                                        'status': 'active', 'type': 'LDAP', 'userId': '18e27d22-49d9-407e-a38e-d5ad35577e53', 'userIds': ''},
                                   'username': 'arome@woodland.perficientads.com'}}

        assert returned_dict == expected_user_dict

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

        assert created_user == expected_user



    # @patch('user_sync.connector.directory_oneroster.ResultParser')
    # @patch('user_sync.connector.directory_oneroster.Connection')
    # @patch('user_sync.connector.directory_oneroster.Authenticator')
    # def test_load_users_and_groups(self, MockAuth, MockConn, MockParse):
    #     auth = MockAuth()
    #     conn = MockConn()
    #     rp = MockParse
    #     mock_adobe_user_group = {'courses::Alg-102::students', 'classes::Algebra I - Fall::teachers'}
    #     #groups_from_yml = self.connector.parse_yml_groups(mock_adobe_user_group)
    #
    #     deliverable_user_list = self.connector.load_users_and_groups(mock_adobe_user_group, [], True)
    #
    #
    #     assert six.itervalues(users_result) != None
    #
    #     # def test_load_users_and_groups(self):
    #     #     mock_adobe_user_group = {'courses::Alg-102::students', 'classes::Algebra I - Fall::teachers'}
    #     #
    #     #     deliverable_user_list = self.connector.load_users_and_groups(mock_adobe_user_group, [], True)
    #     #
    #     #     print(deliverable_user_list)