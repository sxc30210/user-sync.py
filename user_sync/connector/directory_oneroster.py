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

import json
import six
import re
import string

import user_sync.config
import user_sync.connector.helper
import user_sync.helper
import user_sync.identity_type
from user_sync.error import AssertionException

from user_sync.connector.oneroster import OneRoster


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
        builder.set_string_value('string_encoding', 'utf8')

        # Values from connector-oneroster.yml via builder

        self.options = builder.get_options()
        self.host = builder.require_string_value('host')
        self.key_identifier = builder.require_string_value('key_identifier')
        self.limit = builder.require_string_value('limit')
        if int(self.limit) < 1:
            raise ValueError("limit must be >= 1")
        self.country_code = builder.require_string_value('country_code')
        self.client_id = builder.require_string_value('client_id')
        self.client_secret = builder.require_string_value('client_secret')
        self.user_identity_type = user_sync.identity_type.parse_identity_type(self.options['user_identity_type'])
        self.logger = user_sync.connector.helper.create_logger(self.options)
        options = builder.get_options()
        self.options = options
        self.logger = logger = user_sync.connector.helper.create_logger(options)
        logger.debug('%s initialized with options: %s', self.name, options)
        caller_config.report_unused_values(self.logger)

    def load_users_and_groups(self, groups, extended_attributes, all_users):
        """
        description: Leverages class components to return and send a user list to UMAPI
        :type groups: list(str)
        :type extended_attributes: list(str)
        :type all_users: bool
        :rtype (bool, iterable(dict))
        """
        conn = Connection(self.logger, self.host, self.limit, self.client_id, self.client_secret)
        groups_from_yml = self.parse_yml_groups(groups)
        users_result = {}

        for group_filter in groups_from_yml:
            inner_dict = groups_from_yml[group_filter]
            for group_name in inner_dict:
                for user_group in inner_dict[group_name]:
                    user_filter = inner_dict[group_name][user_group]
                    users_list = conn.get_user_list(group_filter, group_name, user_filter, self.key_identifier, self.limit)
                    api_response = ResultParser.parse_results(users_list, extended_attributes, self.key_identifier)
                    users_result = self.merge_users(users_result, api_response, user_group)

        for first_dict in users_result:
            values = users_result[first_dict]
            self.convert_user(values)

        return six.itervalues(users_result)

    def merge_users(self, user_list, new_users, group_name):

        for uid in new_users:
            if uid not in user_list:
                user_list[uid] = new_users[uid]

            (user_list[uid]['groups']).add(group_name)

        return user_list

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

            if group_filter not in full_dict:
                full_dict[group_filter] = {group_name: dict()}
            elif group_name not in full_dict[group_filter]:
                full_dict[group_filter][group_name] = dict()

            full_dict[group_filter][group_name].update({text: user_filter})

        return full_dict

class Connection:
    """ Starts connection and makes queries with One-Roster API"""

    def __init__(self, logger, host_name=None, limit='100', client_id=None, client_secret=None):
        self.host_name = host_name
        self.logger = logger
        self.limit = limit
        self.client_id = client_id
        self.client_secret = client_secret
        self.oneroster = OneRoster(client_id, client_secret)

    def get_user_list(self, group_filter, group_name, user_filter, key_identifier, limit):
        """
        description:
        :type group_filter: str()
        :type group_name: str()
        :type user_filter: str()
        :type key_identifier: str()
        :type limit: str()
        :rtype parsed_json_list: list(str)
        """
        parsed_json_list = list()

        if group_filter == 'courses':
            class_list = self.get_classlist_for_course(group_name, key_identifier, limit)
            for each_class in class_list:
                key_id_classes = class_list[each_class]
                response_classes = self.oneroster.make_roster_request(self.host_name + 'classes' + '/' + key_id_classes + '/' + user_filter + '?limit=' + limit + '&offset=0')
                if response_classes.ok is False:
                    self.logger.warning(
                        'Error fetching ' + user_filter + ' Found for: ' + group_name + "\nError Response Message:" + " " +
                        response_classes.text)
                    return {}
                for ignore3, users3 in json.loads(response_classes.content).items():
                    parsed_json_list.extend(users3)
                while self.is_last_call_to_make(response_classes) is False:
                    response_classes = self.oneroster.make_roster_request(response_classes.headers._store['next'][1])
                    if response_classes.ok is not True:
                        break
                    parsed_json_list.extend(json.loads(response_classes.content))

        else:
            try:

                key_id = self.get_key_identifier(group_filter, group_name, key_identifier, limit)
                response = self.oneroster.make_roster_request(self.host_name + group_filter + '/' + key_id + '/' + user_filter + '?limit=' + limit + '&offset=0')
                if response.ok is False:
                    self.logger.warning(
                        'Error fetching ' + user_filter + ' Found for: ' + group_name + "\nError Response Message:" + " " +
                        response.text)
                    return {}

                for ignore, users in json.loads(response.content).items():
                    parsed_json_list.extend(users)

                while self.is_last_call_to_make(response) is False:
                    response = self.oneroster.make_roster_request(response.links['next']['url'])
                    if response.ok is not True:
                        break
                    for ignore2, users2 in json.loads(response.content).items():
                        parsed_json_list.extend(users2)

            except ValueError as e:
                self.logger.warning(e)
                return {}

        return parsed_json_list

    def is_last_call_to_make(self, response):
        """
        handles pagination
        :type response: dict() response from url call
        :rType: boolean:
        """

        try:
            if response.links['next']['url'] is not None:
                return False
        except:
            return True

        returned_result_count = response.headers._store['x-count'][1]
        if int(returned_result_count) < int(self.limit):
            return True
        else:
            return False



    def get_key_identifier(self, group_filter, group_name, key_identifier, limit):
        """
        description: Returns key_identifier (eg: sourcedID) for targeted group_name from One-Roster
        :type group_filter: str()
        :type group_name: str()
        :type key_identifier: str()
        :type limit: str()
        :rtype sourced_id: str()
        """
        keys = list()
        # Not used if using name and title
        # if group_filter == 'courses':
        #     esless = group_filter[:-1] + "Code"
        # elif group_filter == 'classes':
        #     esless = group_filter[:-2] + "Code"
        # else:
        #     esless = 'name'

        response = self.oneroster.make_roster_request(self.host_name + group_filter + '?limit=' + limit + '&offset=0')

        if response.status_code is not 200:
            raise ValueError('Non Successful Response'
                             + '  ' + 'status:' + str(response.status_code) + "\n" + response.text)
        parsed_json = json.loads(response.content)
        if self.is_last_call_to_make(response) is True:
            if group_filter == 'schools':
                name_identifier = 'name'
                revised_key = 'orgs'
            else:
                name_identifier = 'title'
                revised_key = group_filter
            try:
                for each_class in parsed_json.get(revised_key):
                    if self.encode_str(each_class[name_identifier]) == self.encode_str(group_name):
                        try:
                            key_id = each_class[key_identifier]
                        except:
                            raise ValueError('Key identifier: ' + key_identifier + ' not a valid identifier')
                        keys.append(key_id)
                        break
            except:
                raise AssertionException("response list key mismatch" + "for" + revised_key)
        while self.is_last_call_to_make(response) is False:
            if group_filter == 'schools':
                name_identifier = 'name'
                revised_key = 'orgs'
            else:
                name_identifier = 'title'
                revised_key = group_filter
            parsed_json = json.loads(response.content)
            for each in parsed_json.get(revised_key):
                if self.encode_str(each[name_identifier]) == self.encode_str(group_name):
                    try:
                        key_id = each[key_identifier]
                        keys.append(key_id)
                        return keys[0]
                    except:
                        raise ValueError('Key identifier: ' + key_identifier + ' not a valid identifier')

            response = self.oneroster.make_roster_request(response.links['next']['url'])
        parsed_json = json.loads(response.content)
        for each in parsed_json.get(revised_key):
            if self.encode_str(each[name_identifier]) == self.encode_str(group_name):
                try:
                    key_id = each[key_identifier]
                    keys.append(key_id)
                    return keys[0]
                except:
                    raise ValueError('Key identifier: ' + key_identifier + ' not a valid identifier')

        if len(keys) == 0:
            raise ValueError('No key ids found for: ' + " " + group_filter + ":" + " " + group_name)
        elif len(keys) > 1:
            raise ValueError('Duplicate ID found: ' + " " + group_filter + ":" + " " + group_name)

        return keys[0]

    def get_classlist_for_course(self, group_name, key_identifier, limit):
        """
        description: returns list of sourceIds for classes of a course (group_name)
        :type group_name: str()
        :type key_identifier: str()
        :type limit: str()
        :rtype class_list: list(str)
        """

        class_list = dict()
        try:
            key_id = self.get_key_identifier('courses', group_name, key_identifier, limit)
            response = self.oneroster.make_roster_request(self.host_name + 'courses' + '/' + key_id + '/' + 'classes' + '?limit=' + limit + '&offset=0')

            if response.ok is not True:
                status = response.status_code
                message = response.reason
                raise ValueError('Non Successful Response'
                                 + '  ' + 'status:' + str(status) + '  ' + 'message:' + str(message))
            parsed_json = json.loads(response.content)

            while self.is_last_call_to_make(response) is False:
                response = self.oneroster.make_roster_request(response.headers._store['next'][1])
                if response.ok is not True:
                    break
                parsed_json.extend(json.loads(response.content))

            for ignore, each_class in parsed_json.items():
                class_key_id = each_class[0][key_identifier]
                #class_name = each_class['classCode']
                class_name = each_class[0]['title']
                class_list[class_name] = class_key_id

        except ValueError as e:
            self.logger.warning(e)

        return class_list

    def encode_str(self, text):
        return re.sub(r'(\s)', '', text).lower()


class ResultParser:

    @staticmethod
    def parse_results(result_set, extended_attributes, key_identifier):
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
                returned_user = ResultParser.create_user_object(user, extended_attributes, key_identifier)
                users_dict[user[key_identifier]] = returned_user
        return users_dict

    @staticmethod
    def create_user_object(user, extended_attributes, key_identifier):
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

        #       User information available from One-Roster
        try:
            source_attributes['sourcedId'] = user['sourcedId']
            source_attributes['status'] = user['status']
            source_attributes['dateLastModified'] = user['dateLastModified']
            source_attributes['username'] = user['username']
            source_attributes['userIds'] = user['userIds']
            source_attributes['enabledUser'] = user['enabledUser']
            source_attributes['givenName'] = formatted_user['firstname'] = user['givenName']
            source_attributes['familyName'] = formatted_user['lastname'] = user['familyName']
            source_attributes['middleName'] = user['middleName']
            source_attributes['role'] = user['role']
            source_attributes['identifier'] = user['identifier']
            source_attributes['email'] = formatted_user['email'] = formatted_user['username'] = user['email']
            source_attributes['sms'] = user['sms']
            source_attributes['phone'] = user['phone']
            source_attributes['agents'] = user['agents']
            source_attributes['orgs'] = user['orgs']
            source_attributes['grades'] = user['grades']
            source_attributes['domain'] = formatted_user['domain'] = str(user['email']).split('@')[1]
            source_attributes['password'] = user['password']
            source_attributes[key_identifier] = user[key_identifier]
            #Can be found in userIds if needed
            #source_attributes['userId'] = user['userId']
            #source_attributes['type'] = user['type']

        except:
            raise AssertionException("A key not found in user info object")

#       adds any extended_attribute values
#       from the one-roster user information into the final user object utilized by the UST
        if extended_attributes is not None:
            for attribute in extended_attributes:
                formatted_user[attribute] = user[attribute]

        formatted_user['source_attributes'] = source_attributes
        formatted_user['groups'] = set()

        return formatted_user


class LDAPValueFormatter(object):
    encoding = 'utf8'

    def __init__(self, string_format):
        """
        The format string must be a unicode or ascii string: see notes above about being careful in Py2!
        """
        if string_format is None:
            attribute_names = []
        else:
            string_format = six.text_type(string_format)    # force unicode so attribute values are unicode
            formatter = string.Formatter()
            attribute_names = [six.text_type(item[1]) for item in formatter.parse(string_format) if item[1]]
        self.string_format = string_format
        self.attribute_names = attribute_names

    def get_attribute_names(self):
        """
        :rtype list(str)
        """
        return self.attribute_names

    def generate_value(self, record):
        """
        :type record: dict
        :rtype (unicode, unicode)
        """
        result = None
        attribute_name = None
        if self.string_format is not None:
            values = {}
            for attribute_name in self.attribute_names:
                value = self.get_attribute_value(record, attribute_name, first_only=True)
                if value is None:
                    values = None
                    break
                values[attribute_name] = value
            if values is not None:
                result = self.string_format.format(**values)
        return result, attribute_name

    @classmethod
    def get_attribute_value(cls, attributes, attribute_name, first_only=False):
        """
        The attribute value type must be decodable (str in py2, bytes in py3)
        :type attributes: dict
        :type attribute_name: unicode
        :type first_only: bool
        """
        attribute_values = attributes.get(attribute_name)
        if attribute_values:
            try:
                if first_only or len(attribute_values) == 1:
                    return attribute_values[0].decode(cls.encoding)
                else:
                    return [val.decode(cls.encoding) for val in attribute_values]
            except UnicodeError as e:
                raise AssertionException("Encoding error in value of attribute '%s': %s" % (attribute_name, e))
        return None