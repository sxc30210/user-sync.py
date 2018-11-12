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
import string

from requests_oauthlib import OAuth1Session
from requests_oauthlib import OAuth2Session
from requests.auth import HTTPBasicAuth
from oauthlib.oauth2 import BackendApplicationClient


import user_sync.config
import user_sync.connector.helper
import user_sync.helper
import user_sync.identity_type
from user_sync.error import AssertionException


def connector_metadata():
    metadata = {
        'name': OneRosterConnector.name
    }
    return metadata


def connector_initialize(options):
    """
    :type options: dict
    """
    state = OneRosterConnector(options)
    return state


def connector_load_users_and_groups(state, groups=None, extended_attributes=None, all_users=True):
    """
    :type state: LDAPDirectoryConnector
    :type groups: Optional(list(str))
    :type extended_attributes: Optional(list(str))
    :type all_users: bool
    :rtype (bool, iterable(dict))
    """
    return state.load_users_and_groups(groups or [], extended_attributes or [], all_users)


class OneRosterConnector(object):
    name = 'oneroster'

    def __init__(self, caller_options):

        # Get the configuration information and apply data from YAML
        caller_config = user_sync.config.DictConfig('%s configuration' % self.name, caller_options)

        builder = user_sync.config.OptionsBuilder(caller_config)
        builder.set_string_value('user_identity_type', None)
        builder.set_string_value('logger_name', self.name)

        # Values from connector-oneroster.yml via builder
        self.options = builder.get_options()
        self.host = builder.require_string_value('host')
        self.api_token_endpoint = builder.require_string_value('api_token_endpoint')
        self.client_secret = builder.require_string_value('client_secret')
        self.client_id = builder.require_string_value('client_id')
        self.key_identifier = builder.require_string_value('key_identifier')
        self.country_code = builder.require_string_value('country_code')
        self.auth_specs = builder.require_value('authentication_type', type({}))
        self.user_identity_type = user_sync.identity_type.parse_identity_type(self.options['user_identity_type'])
        self.logger = user_sync.connector.helper.create_logger(self.options)
        self.apiconnector= self.load_connector(self.auth_specs)

        caller_config.report_unused_values(self.logger)

    def load_users_and_groups(self, groups, extended_attributes, all_users):
        """
        description: Leverages class components to return and send a user list to UMAPI
        :type groups: list(str)
        :type extended_attributes: list(str)
        :type all_users: bool
        :rtype (bool, iterable(dict))
        """
        conn = Connection(self.host, self.apiconnector)

        groups_from_yml = self.parse_yml_groups(groups)
        users_result = dict()
        rp = ResultParser()
        key_identifier = self.key_identifier

        for group_filter in groups_from_yml:
            inner_dict = groups_from_yml[group_filter]
            original_group = inner_dict['original_group']
            del inner_dict['original_group']
            for group_name in inner_dict:
                user_filter = inner_dict[group_name]
                users_list = conn.get_user_list(group_filter, group_name, user_filter, key_identifier)
                users_result.update(rp.parse_results(users_list, extended_attributes, original_group, key_identifier))

        for first_dict in users_result:
            values = users_result[first_dict]
            self.convert_user(values)

        return six.itervalues(users_result)

    def convert_user(self, user_record):
        """ description: Adds country code and identity_type from yml files to User Record """

        user_record['identity_type'] = self.user_identity_type
        user_record['country'] = self.country_code

    def parse_yml_groups(self, groups_list):
        """
        description: parses group options from user-sync.config file into a nested dict with Key: group_filter for the outter dict, Value: being the nested
        dict {Key: group_name, Value: user_filter}
        :type groups_list: set(str) from user-sync-config.yml
        :rtype: iterable(dict)
        """

        full_dict = dict()

        for text in groups_list:
            try:
                group_filter, group_name, user_filter = text.lower().split("::")
            except ValueError:
                raise ValueError("Incorrect MockRoster Group Syntax: " + text + " \nRequires values for group_filter, group_name, user_filter. With '::' separating each value")
            if group_filter not in ['classes', 'courses', 'schools']:
                raise ValueError("Incorrect group_filter: " + group_filter + " .... must be either: classes, courses, or schools")
            if user_filter not in ['students', 'teachers', 'users']:
                raise ValueError("Incorrect user_filter: " + user_filter + " .... must be either: students, teachers, or users")
            group_name = ''.join(group_name.split())
            if group_filter in full_dict:
                full_dict[group_filter][group_name] = user_filter
                full_dict[group_filter]['original_group'] = text
            else:
                full_dict[group_filter] = {group_name: user_filter}
                full_dict[group_filter]['original_group'] = text

        return full_dict

    def load_connector(self, auth_specs):
        """
        :description: Loads appropriate authentication protocol, using the Authentication specifications from connector-oneroster.yml.
        :type auth_specs: dict()
        :rtype: class(Proper Connector)
        """

        if auth_specs['auth_type'] == 'oauth2':
            type = OAuthConnector2(self.client_id, self.client_secret, auth_specs['basic_header'], self.api_token_endpoint)

        elif auth_specs['auth_type'] == 'oauth2_non_lib':
            type = OAuthConnector2_NON_LIB(self.client_id, self.client_secret, self.api_token_endpoint)

        else:
            type = OAuthConnector1(self.client_id, self.client_secret, self.api_token_endpoint)

        if type is None:
            raise TypeError("Unrecognized authentication type: " + auth_specs['auth_type'])
        return type


class OAuthConnector2_NON_LIB:

    def __init__(self, client_id=None, client_secret=None, token_endpoint=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_endpoint = token_endpoint
        self.req_headers = dict()

    def authenticate(self):
        payload = dict()
        header = dict()
        payload['grant_type'] = 'client_credentials'

        response = requests.post(self.token_endpoint, auth=(self.client_id, self.client_secret), headers=header, data=payload)

        if response.status_code != 200:
            raise ValueError('Token request failed:  ' + response.text)

        self.req_headers['Authorization'] = "Bearer" + json.loads(response.content)['access_token']

    def get(self, url=None):
        return requests.get(url, headers=self.req_headers)

class OAuthConnector2:

    """
    The OAuthLib provides multiple optional security measures when implementing OAuth2
    """

    #def __init__(self, client_id=None, client_secret=None, basic_header=False, token_endpoint=None):
    def __init__(self, client_id=None, client_secret=None, basic_header=None, token_endpoint=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.basic_header = basic_header
        self.token_endpoint = token_endpoint
        self.token = str()

    def authenticate(self):
        payload = dict()
        header = dict()

        client = BackendApplicationClient(client_id=self.client_id)
        oauth = OAuth2Session(client=client)

        if self.basic_header is True:
            auth = HTTPBasicAuth(self.client_id, self.client_secret)
            self.token = oauth.fetch_token(self.token_endpoint, auth=auth)

        else:
            self.token = oauth.fetch_token(token_url=self.token_endpoint, client_id=self.client_id,
                                       client_secret=self.client_secret)

    def get(self, url=None):
        client = OAuth2Session(self.client_id, token=self.token)

        return client.get(url, token=self.token)


class OAuthConnector1:

    def __init__(self, client_id=None, client_secret=None, host_name_oauth1=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.host_name_oauth1 = host_name_oauth1
        self.req_headers = dict()

    def authenticate(self):
        payload = dict()
        header = dict()
        host = self.host_name_oauth1
        key = self.client_id
        secret = self.client_secret
        oauth = OAuth1Session(key, secret)
        fetch_response = oauth.fetch_request_token(host + 'oauth/request_token')
        resource_owner_key = fetch_response.get('oauth_token')
        resource_owner_secret = fetch_response.get('oauth_token_secret')

        authorization_url = oauth.authorization_url(host + 'oauth/authorize')
        print('Please go here and authorize,', authorization_url)
        redirect_response = input('Paste the full redirect URL here: ')
        oauth_response = oauth.parse_authorization_response(redirect_response)
        verifier = oauth_response.get('oauth_verifier')

        oauth = OAuth1Session(key, secret, resource_owner_key, resource_owner_secret, verifier)

        oauth_tokens = oauth.fetch_access_token(host + 'oauth/access_token')

        resource_owner_key = oauth_tokens.get('oauth_token')
        resource_owner_secret = oauth_tokens.get('oauth_token_secret')

        protected_url = 'https://api.twitter.com/1/account/settings.json'
        oauth = OAuth1Session(key, secret, resource_owner_key, resource_owner_secret)
        r = requests.get(protected_url, oauth)

    def get(self, url=None):
        return "users"

class Connection:
    """ Starts connection and makes queries with One-Roster API"""

    def __init__(self, host_name=None, connector=None):
        self.host_name = host_name
        self.connector = connector
        self.connector.authenticate()


    def get_user_list(self, group_filter, group_name, user_filter, key_identifier):
        """
        description:
        :type group_filter: str()
        :type group_name: str()
        :type user_filter: str()
        :type key_identifier: str()
        :rtype parsed_json_list: list(str)
        """
        parsed_json_list = list()

        if group_filter == 'courses':
            class_list = self.get_classlist_for_course(group_name, key_identifier)
            for each_class in class_list:
                key_id = class_list[each_class]
                response = self.connector.get(self.host_name + 'classes' + '/' + key_id + '/' + user_filter)

                if response.ok is False:
                    raise ValueError('No ' + user_filter + ' Found for:' + " " + group_name + "\nError Response Message:" + " " +
                                     response.text)
                parsed_response = json.loads(response.content)
                parsed_json_list.extend(parsed_response)

        else:
            key_id = self.get_key_identifier(group_filter, group_name, key_identifier)
            response = self.connector.get(self.host_name + group_filter + '/' + key_id + '/' + user_filter)
            if response.ok is False:
                raise ValueError('No ' + user_filter + ' Found for: ' + group_name + "\nError Response Message:" + " " +
                                 response.text)
            parsed_json_list = json.loads(response.content)

        return parsed_json_list

    def get_key_identifier(self, group_filter, group_name, key_identifier):
        """
        description: Returns key_identifier (eg: sourcedID) for targeted group_name from One-Roster
        :type group_filter: str()
        :type group_name: str()
        :type key_identifier: str()
        :rtype sourced_id: str()
        """
        why = list()

        response = self.connector.get(self.host_name + group_filter)

        if response.ok is not True:
            raise ValueError('Non Successful Response'
                             + '  ' + 'status:' + str(response.status_code) + "\n" + response.text)

        parsed_json = json.loads(response.content)

        if group_filter == 'courses':
            esless = group_filter[:-1] + "Code"
        elif group_filter == 'classes':
            esless = group_filter[:-2] + "Code"
        else:
            esless = 'name'
        for x in parsed_json:
            if ''.join(x[esless].split()).lower() == group_name:
                try:
                    key_id = x[key_identifier]
                except:
                    raise ValueError('Key identifier: ' + key_identifier + ' not a valid identifier')
                why.append(key_id)
                break
        if why.__len__() != 1:
            raise ValueError('No Key Ids Found for:' + " " + group_filter + ":" + " " + group_name)

        return_value = why[0]
        return return_value

    def get_classlist_for_course(self, group_name, key_identifier):
        """
        description: returns list of sourceIds for classes of a course (group_name)
        :type group_name: str()
        :type key_identifier: str()
        :rtype class_list: list(str)
        """

        class_list = dict()

        key_id = self.get_key_identifier('courses', group_name, key_identifier)
        response = self.connector.get(self.host_name + 'courses' + '/' + key_id + '/' + 'classes')

        if response.ok is not True:
            status = response.status_code
            message = response.reason
            raise ValueError('Non Successful Response'
                             + '  ' + 'status:' + str(status) + '  ' + 'message:' + str(message))
        parsed_json = json.loads(response.content)

        for each_class in parsed_json:
            class_key_id = each_class[key_identifier]
            class_name = each_class['classCode']
            class_list[class_name] = class_key_id

        return class_list


class ResultParser:

    def parse_results(self, result_set, extended_attributes, original_group, key_identifier):
        """
        description: parses through user_list from API calls, to create final user objects
        :type result_set: list(dict())
        :type extended_attributes: list(str)
        :type original_group: str()
        :type key_identifier: str()
        :rtype users_dict: dict(constructed user objects)
        """
        users_dict = dict()
        for user in result_set:
            if user['status'] == 'active':
                returned_user = self.create_user_object(user, extended_attributes, original_group, key_identifier)
                users_dict[user[key_identifier]] = returned_user
        return users_dict

    def create_user_object(self, user, extended_attributes, original_group, key_identifier):
        """
        description: Using user's API information to construct final user objects
        :type user: dict()
        :type extended_attributes: list(str)
        :type original_group: str()
        :type key_identifier: str()
        :rtype: formatted_user: dict(user object)
        """
        formatted_user = dict()
        source_attributes = dict()
        groups = list()
        # member_groups = list() #May not need
        groups.append(original_group)

        x, user_domain = str(user['email']).split('@')

        #       User information available from One-Roster
        source_attributes['email'] = formatted_user['email'] = user['email']
        formatted_user['username'] = formatted_user['email']
        source_attributes['username'] = user['username']
        source_attributes['givenName'] = formatted_user['firstname'] = user['givenName']
        source_attributes['familyName'] = formatted_user['lastname'] = user['familyName']
        source_attributes['domain'] = formatted_user['domain'] = user_domain
        formatted_user['groups'] = groups
        source_attributes['enabledUser'] = user['enabledUser']
        source_attributes['grades'] = user['grades']
        source_attributes['identifier'] = user['identifier']
        source_attributes['metadata'] = user['metadata']
        source_attributes['middleName'] = user['middleName']
        source_attributes['phone'] = user['phone']
        source_attributes['role'] = user['role']
        source_attributes['schoolId'] = user['schoolId']
        source_attributes['sourcedId'] = user['sourcedId']
        source_attributes['status'] = user['status']
        source_attributes['type'] = user['type']
        source_attributes['userId'] = user['userId']
        source_attributes['userIds'] = user['userIds']
        source_attributes[key_identifier] = user[key_identifier]

        #       adds any extended_attribute values
        #       from the one-roster user information into the final user object utilized by the UST
        if extended_attributes is not None:
            for attribute in extended_attributes:
                formatted_user[attribute] = user[attribute]

        formatted_user['source_attributes'] = source_attributes

        return formatted_user


