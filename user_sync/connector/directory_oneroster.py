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

#       Get the configuration information and apply data from YAML
        caller_config = user_sync.config.DictConfig('%s configuration' % self.name, caller_options)
        builder = user_sync.config.OptionsBuilder(caller_config)
        options = builder.get_options()
        self.options = options
        builder.set_string_value('user_identity_type', None)
        builder.set_string_value('logger_name', self.name)

#       Values from connector-oneroster.yml, required for communication with One-Roster API
        self.host = builder.require_string_value('host')
        self.api_token = builder.require_string_value('api_token_endpoint')
        self.password = builder.require_string_value('password')
        self.username = builder.require_string_value('username')

        # Country Code value, required from connector-oneroster.yml
        self.country_code = builder.require_string_value('country_code')

        # Identity Type of Users from User-Sync YML file
        self.user_identity_type = user_sync.identity_type.parse_identity_type(options['user_identity_type'])

        self.logger = logger = user_sync.connector.helper.create_logger(options)
        caller_config.report_unused_values(logger)

    def load_users_and_groups(self, groups, extended_attributes, all_users):
        """
        description: Leverages class components to return and send a user list to UMAPI
        :type groups: list(str)
        :type extended_attributes: list(str)
        :type all_users: bool
        :rtype (bool, iterable(dict))
        """

        auth = Authenticator(self.username, self.password, self.api_token)
        api_token = auth.retrieve_api_token()

        conn = Connection(self.host, api_token=api_token)

        groups_from_yml = self.parse_yml_groups(groups)
        users_result = dict()
        rp = ResultParser()

        for group_filter in groups_from_yml:
            inner_dict = groups_from_yml[group_filter]
            original_group = inner_dict['original_group']
            del inner_dict['original_group']
            for group_name in inner_dict:
                user_filter = inner_dict[group_name]
                users_list = conn.get_user_list(group_filter, group_name, user_filter)
                users_result.update(rp.parse_results(users_list, extended_attributes, original_group))

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


class Authenticator:
    """
    description: Retrieves api token from One-Roster implementation, using user's credentials
    :type username str()
    :type password str()
    :type token_endpoint str()
    :rtype api_token str()
    """

    def __init__(self, username=None, password=None, token_endpoint=None):
        self._username = username
        self._password = password
        self._token_endpoint = token_endpoint

    @property
    def username(self):
        return self._username

    @property
    def password(self):
        return self._password

    @property
    def token_endpoint(self):
        return self._token_endpoint

    @username.setter
    def username(self, username):
        self._username = username

    @password.setter
    def password(self, password):
        self._password = password

    @token_endpoint.setter
    def token_endpoint(self, token_endpoint):
        self._token_endpoint = token_endpoint

    @username.getter
    def username(self):
        return self._username

    @password.getter
    def password(self):
        return self._password

    @token_endpoint.getter
    def token_endpoint(self):
        return self._token_endpoint

    def retrieve_api_token(self):
        payload = dict()
        header = dict()
        payload['grant_type'] = 'client_credentials'

        response = requests.post(Authenticator.__getattribute__(self, 'token_endpoint'),
                          auth=(Authenticator.__getattribute__(self, 'username'),
                                Authenticator.__getattribute__(self, 'password')),
                          headers=header, data=payload)

        if response.ok is not True:
            raise ValueError('Token Not Received with the following info:'
                             + '  ' + 'status_code:' + str(response.status_code) + '\nmessage:' + response.text)

        return json.loads(response.content)['access_token']


class Connection:
    """ Starts connection and makes queries with One-Roster API"""

    def __init__(self, host_name=None, api_token=None):
        self._api_token = api_token
        self._host_name = host_name

    @property
    def api_token(self):
        return self._api_token

    @property
    def host_name(self):
        return self._host_name

    @api_token.setter
    def api_token(self, api_token):
        self._api_token = api_token

    @host_name.setter
    def host_name(self, host_name):
        self._host_name = host_name

    @api_token.getter
    def api_token(self):
        return self._api_token

    @host_name.getter
    def host_name(self):
        return self._host_name

    def get_user_list(self, group_filter, group_name, user_filter):
        """
        description:
        :type group_filter: str()
        :type group_name: str()
        :type user_filter: str()
        :rtype parsed_json_list: list(str)
        """
        header = dict()
        payload = dict()
        parsed_json_list = list()
        header['Authorization'] = "Bearer" + Connection.__getattribute__(self, 'api_token')
        if group_filter == 'courses':
            class_list = self.get_classlist_for_course(group_name)
            for each_class in class_list:
                sourced_id = class_list[each_class]
                api_call = Connection.__getattribute__(self, 'host_name') + 'classes' + '/' + sourced_id + '/' + user_filter
                response = requests.get(api_call, headers=header)
                if response.ok is False:
                    raise ValueError('No ' + user_filter + ' Found for:' + " " + group_name + "\nError Response Message:" + " " +
                                     response.text)
                parsed_response = json.loads(response.content)
                parsed_json_list.extend(parsed_response)

        else:
            sourced_id = self.get_sourced_id(group_filter, group_name)
            api_endpoint_call = Connection.__getattribute__(self, 'host_name') + group_filter + '/' + sourced_id + '/' + user_filter
            response = requests.get(api_endpoint_call, headers=header)
            if response.ok is False:
                raise ValueError('No ' + user_filter + ' Found for: ' + group_name + "\nError Response Message:" + " " +
                                 response.text)
            parsed_json_list = json.loads(response.content)

        return parsed_json_list

    def get_sourced_id(self, group_filter, group_name):
        """
        description: Returns sourcedId for targeted group_name from One-Roster
        :type group_filter: str()
        :type group_name: str()
        :rtype sourced_id: str()
        """
        header = dict()
        payload = dict()
        why = list()
        header['Authorization'] = "Bearer" + Connection.__getattribute__(self, 'api_token')

        endpoint_sourced_id = Connection.__getattribute__(self, 'host_name') + group_filter
        response = requests.get(endpoint_sourced_id, headers=header)
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
                sourced_id = x['sourcedId']
                why.append(sourced_id)
                break
        if why.__len__() != 1:
            raise ValueError('No Source Ids Found for:' + " " + group_filter + ":" + " " + group_name)

        return_value = why[0]
        return return_value

    def get_classlist_for_course(self, group_name):
        """
        description: returns list of sourceIds for classes of a course (group_name)
        :type group_name: str()
        :rtype class_list: list(str)
        """

        header = dict()
        payload = dict()
        class_list = dict()
        header['Authorization'] = "Bearer" + Connection.__getattribute__(self, 'api_token')

        sourced_id = self.get_sourced_id('courses', group_name)
        endpoint_sourced_id = Connection.__getattribute__(self,
                                                          'host_name') + 'courses' + '/' + sourced_id + '/' + 'classes'
        response = requests.get(endpoint_sourced_id, headers=header)
        if response.ok is not True:
            status = response.status_code
            message = response.reason
            raise ValueError('Non Successful Response'
                             + '  ' + 'status:' + str(status) + '  ' + 'message:' + str(message))
        parsed_json = json.loads(response.content)

        for each_class in parsed_json:
            class_sourced_id = each_class['sourcedId']
            class_name = each_class['classCode']
            class_list[class_name] = class_sourced_id

        return class_list


class ResultParser:

    def parse_results(self, result_set, extended_attributes, original_group):
        """
        description: parses through user_list from API calls, to create final user objects
        :type result_set: list(dict())
        :type extended_attributes: list(str)
        :type original_group: str()
        :rtype users_dict: dict(constructed user objects)
        """
        users_dict = dict()
        for user in result_set:
            if user['status'] == 'active':
                returned_user = self.create_user_object(user, extended_attributes, original_group)
                users_dict[user['sourcedId']] = returned_user
        return users_dict

    def create_user_object(self, user, extended_attributes, original_group):
        """
        description: Using user's API information to construct final user objects
        :type user: dict()
        :type extended_attributes: list(str)
        :type original_group: str()
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
        source_attributes['username'] = formatted_user['username'] = user['username']
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

        #       adds any extended_attribute values
        #       from the one-roster user information into the final user object utilized by the UST
        if extended_attributes is not None:
            for attribute in extended_attributes:
                formatted_user[attribute] = user[attribute]

        formatted_user['source_attributes'] = source_attributes

        return formatted_user


