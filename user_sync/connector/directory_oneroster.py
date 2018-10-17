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

        builder.set_string_value('user_identity_type', None)
        builder.set_string_value('logger_name', self.name)

#       Values needed to query API, values from YML file
        self.host = builder.require_string_value('host')
        self.api_token = builder.require_string_value('api_token_endpoint')
        self.password = builder.require_string_value('password')
        self.username = builder.require_string_value('username')

#       Country Code passed from YML file
        self.country_code = builder.require_string_value('country_code')

        #Extended Attributes from YML file
        #self.extended_attributes = builder.set_value(caller_config.value['extended_attributes'], list(), None)
        # self.extended_attributes = caller_options['extended_attributes']

        # Assemble data from YAML into options object
        options = builder.get_options()

        # #Extended Attributes from YML file
        # self.extended_attributes = options.values()

        self.logger = logger = user_sync.connector.helper.create_logger(options)

#       Identity Type of Users from User-Sync YML file
        self.user_identity_type = user_sync.identity_type.parse_identity_type(options['user_identity_type'])
        self.options = options
        caller_config.report_unused_values(logger)

#       Makes call to mockroster API, parses response,
#       needs to call convert user to fill user object with necessary values that are missing form API call,
#       that are found from the user_sync.yml file
    def load_users_and_groups(self, groups, extended_attributes, all_users):
        """
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
        """ description: Adds country code and identity_type from yml files """

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
    """ Retrieves api token from One-Roster implementation"""

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

# Starts connection with mockroster API and makes queries


class Connection:

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
# Parses response from api call
class ResultParser:

    def parse_results(self, result_set, extended_attributes, original_group):
        users_dict = dict()
        for user in result_set:
            if user['status'] == 'active':
                returned_user = self.create_user_object(user, extended_attributes, original_group)
                users_dict[user['sourcedId']] = returned_user
        return users_dict
    def create_user_object(self, user, extended_attributes, original_group):
        formatted_user = dict()
        source_attributes = dict()
        groups = list()
        #member_groups = list() #May not need
        groups.append(original_group)

#       Probably can eliminate use of these variables?????
        user_email = user['email']
        user_given_name = user['givenName']
        user_family_name = user['familyName']
        user_username = user['username']
        x, user_domain = str(user_email).split('@')
        enabledUser = user['enabledUser']
        grades = user['grades']
        identifier = user['identifier']
        metadata = user['metadata']
        middleName = user['middleName']
        phone = user['phone']
        role = user['role']
        schoolId = user['schoolId']
        sourcedId = user['sourcedId']
        status = user['status']
        type = user['type']
        userId = user['userId']
        userIds = user['userIds']

#       User information available from One-Roster
        source_attributes['email'] = user_email
        source_attributes['username'] = user_username
        source_attributes['givenName'] = user_given_name
        source_attributes['familyName'] = user_family_name
        source_attributes['domain'] = user_domain
        source_attributes['enabledUser'] = enabledUser
        source_attributes['grades'] = grades
        source_attributes['identifier'] = identifier
        source_attributes['metadata'] = metadata
        source_attributes['middleName'] = middleName
        source_attributes['phone'] = phone
        source_attributes['role'] = role
        source_attributes['schoolId'] = schoolId
        source_attributes['sourcedId'] = sourcedId
        source_attributes['status'] = status
        source_attributes['type'] = type
        source_attributes['userId'] = userId
        source_attributes['userIds'] = userIds

#       User info that will be used to make UMAPI calls
        formatted_user['domain'] = user_domain
        formatted_user['firstname'] = user_given_name
        formatted_user['lastname'] = user_family_name
        formatted_user['email'] = user_email
        formatted_user['groups'] = groups
#       Formatted_user['memberGroups'] = None #May not need
        formatted_user['source_attributes'] = source_attributes
        formatted_user['username'] = user_email

#       adds any extended_attribute values
#       from the one-roster user information into the final user object utilized by the UST
        if extended_attributes is not None:
            for attribute in extended_attributes:
                formatted_user[attribute] = user[attribute]

        formatted_user['source_attributes'] = source_attributes

        return formatted_user


