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
import requests
import six
import re
import string
from oauthlib.oauth2 import BackendApplicationClient
from requests.auth import HTTPBasicAuth
from requests_oauthlib import OAuth1Session
from requests_oauthlib import OAuth2Session

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
        builder.set_string_value('string_encoding', 'utf8')

        # Values from connector-oneroster.yml via builder

        self.options = builder.get_options()
        self.host = builder.require_string_value('host')
        self.api_token_endpoint = builder.require_string_value('api_token_endpoint')
        self.key_identifier = builder.require_string_value('key_identifier')
        self.limit = builder.require_string_value('limit')
        self.country_code = builder.require_string_value('country_code')
        self.auth_specs = builder.require_value('authentication_type', type({}))
        self.user_identity_type = user_sync.identity_type.parse_identity_type(self.options['user_identity_type'])
        self.logger = user_sync.connector.helper.create_logger(self.options)
        self.apiconnector = self.load_connector(self.auth_specs)

        options = builder.get_options()
        self.options = options
        self.logger = logger = user_sync.connector.helper.create_logger(options)
        logger.debug('%s initialized with options: %s', self.name, options)
        caller_config.report_unused_values(self.logger)

        # LDAPValueFormatter.encoding = options['string_encoding']
        # self.user_identity_type = user_sync.identity_type.parse_identity_type(options['user_identity_type'])
        # self.user_identity_type_formatter = LDAPValueFormatter(options['user_identity_type_format'])
        # self.user_email_formatter = LDAPValueFormatter(options['user_email_format'])
        # self.user_username_formatter = LDAPValueFormatter(options['user_username_format'])
        # self.user_domain_formatter = LDAPValueFormatter(options['user_domain_format'])
        # self.user_given_name_formatter = LDAPValueFormatter(options['user_given_name_format'])
        # self.user_surname_formatter = LDAPValueFormatter(options['user_surname_format'])
        # self.user_country_code_formatter = LDAPValueFormatter(options['user_country_code_format'])

    def load_users_and_groups(self, groups, extended_attributes, all_users):
        """
        description: Leverages class components to return and send a user list to UMAPI
        :type groups: list(str)
        :type extended_attributes: list(str)
        :type all_users: bool
        :rtype (bool, iterable(dict))
        """
        conn = Connection(self.logger, self.host, self.apiconnector, self.limit)
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

    def load_connector(self, auth_specs):
        """
        :description: Loads appropriate authentication protocol, using the Authentication specifications from connector-oneroster.yml.
        :type auth_specs: dict()
        :rtype: class(Proper Connector)
        """

        if auth_specs['auth_type'] == 'oauth2':
            return OAuthConnector2(auth_specs, self.api_token_endpoint)
        elif auth_specs['auth_type'] == 'oauth2_non_lib':
            return OAuthConnector2_NON_LIB(auth_specs, self.api_token_endpoint)
        elif auth_specs['auth_type'] == 'oauth':
            return OAuthConnector1(auth_specs, self.api_token_endpoint)
        else:
            raise TypeError("Unrecognized authentication type: " + auth_specs['auth_type'])


class OAuthConnector2_NON_LIB:

    def __init__(self, auth_specs, token_endpoint=None):
        self.auth_specs =auth_specs
        self.token_endpoint = token_endpoint
        self.req_headers = dict()

    def authenticate(self):
        payload = dict()
        payload['grant_type'] = 'client_credentials'

        response = requests.post(self.token_endpoint,
                                 auth=(self.auth_specs['client_id'],
                                       self.auth_specs['client_secret']), data=payload)

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
    def __init__(self, auth_specs, basic_header=False, token_endpoint=None):
        self.auth_specs = auth_specs
        self.basic_header = basic_header
        self.token_endpoint = token_endpoint
        self.token = str()

    def authenticate(self):

        client = BackendApplicationClient(client_id=self.auth_specs['client_id'])
        oauth = OAuth2Session(client=client)

        if self.basic_header is True:
            auth = HTTPBasicAuth(self.auth_specs['client_id'], self.auth_specs['client_secret'])
            self.token = oauth.fetch_token(self.token_endpoint, auth=auth)

        else:
            self.token = oauth.fetch_token(token_url=self.token_endpoint, client_id=self.auth_specs['client_id'],
                                       client_secret=self.auth_specs['client_secret'])

    def get(self, url=None):
        return OAuth2Session(self.auth_specs['client_id'], token=self.token).get(url, token=self.token)


class OAuthConnector1:

    def __init__(self, auth_specs, host_name_oauth1=None):
        self.auth_specs = auth_specs
        self.host_name_oauth1 = host_name_oauth1
        self.req_headers = dict()

    def authenticate(self):
        host = self.host_name_oauth1
        key = self.auth_specs['client_id']
        secret = self.auth_specs['client_secret']
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

    def __init__(self, logger, host_name=None, connector=None, limit='100'):
        self.host_name = host_name
        self.connector = connector
        self.logger = logger
        self.connector.authenticate()
        self.limit = limit


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
                response_classes = self.connector.get(self.host_name + 'classes' + '/' + key_id_classes + '/' + user_filter + '?limit=' + limit + '&offset=0')
                if response_classes.ok is False:
                    self.logger.warning(
                        'Error fetching ' + user_filter + ' Found for: ' + group_name + "\nError Response Message:" + " " +
                        response_classes.text)
                    return {}
                parsed_json_list = json.loads(response_classes.content)
                while self.is_last_call_to_make(response_classes) is False:
                    response_classes = self.connector.get(response_classes.headers._store['next'][1])
                    if response_classes.ok is not True:
                        break
                    parsed_json_list.extend(json.loads(response_classes.content))


        else:
            try:

                key_id = self.get_key_identifier(group_filter, group_name, key_identifier, limit)
                response = self.connector.get(self.host_name + group_filter + '/' + key_id + '/' + user_filter  + '?limit=' + limit + '&offset=0')
                if response.ok is False:
                    self.logger.warning(
                        'Error fetching ' + user_filter + ' Found for: ' + group_name + "\nError Response Message:" + " " +
                        response.text)
                    return {}
                parsed_json_list = json.loads(response.content)

                while self.is_last_call_to_make(response) is False:
                    response = self.connector.get(response.headers._store['next'][1])
                    if response.ok is not True:
                        break
                    parsed_json_list.extend(json.loads(response.content))

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
            returned_result_count = response.headers._store['result-count'][1]
            if returned_result_count < self.limit:
                return True
            else:
                return False

        except:
            return True


    def get_key_identifier(self, group_filter, group_name, key_identifier, limit):
        """
        description: Returns key_identifier (eg: sourcedID) for targeted group_name from One-Roster
        :type group_filter: str()
        :type group_name: str()
        :type key_identifier: str()
        :type limit: str()
        :rtype sourced_id: str()
        """
        why = list()
        if group_filter == 'courses':
            esless = group_filter[:-1] + "Code"
        elif group_filter == 'classes':
            esless = group_filter[:-2] + "Code"
        else:
            esless = 'name'

        response = self.connector.get(self.host_name + group_filter + '?limit=' + limit + '&offset=0')

        if response.ok is not True:
            raise ValueError('Non Successful Response'
                             + '  ' + 'status:' + str(response.status_code) + "\n" + response.text)
        parsed_json = json.loads(response.content)
        if self.is_last_call_to_make(response) is True:
            for x in parsed_json:
                if self.encode_str(x[esless]) == self.encode_str(group_name):
                    try:
                        key_id = x[key_identifier]
                    except:
                        raise ValueError('Key identifier: ' + key_identifier + ' not a valid identifier')
                    why.append(key_id)
                    break
        while self.is_last_call_to_make(response) is False:
            #parsed_json.extend(json.loads(response.content))
            parsed_json = json.loads(response.content)
            for x in parsed_json:
            # for x in json.loads(response.content):
                if self.encode_str(x[esless]) == self.encode_str(group_name):
                    try:
                        key_id = x[key_identifier]
                        why.append(key_id)
                        return why[0]
                    except:
                        raise ValueError('Key identifier: ' + key_identifier + ' not a valid identifier')

            response = self.connector.get(response.headers._store['next'][1])
        if len(why) == 0:
            raise ValueError('No key ids found for: ' + " " + group_filter + ":" + " " + group_name)
        elif len(why) > 1:
            raise ValueError('Duplicate ID found: ' + " " + group_filter + ":" + " " + group_name)

        return why[0]


    def get_classlist_for_course(self, group_name, key_identifier, limit):
        """
        description: returns list of sourceIds for classes of a course (group_name)
        :type group_name: str()
        :type key_identifier: str()
        :type limit: str()
        :rtype class_list: list(str)
        """

        parsed_json = list()
        class_list = dict()
        try:
            key_id = self.get_key_identifier('courses', group_name, key_identifier, limit)
            response = self.connector.get(self.host_name + 'courses' + '/' + key_id + '/' + 'classes' + '?limit=' + limit + '&offset=0')

            if response.ok is not True:
                status = response.status_code
                message = response.reason
                raise ValueError('Non Successful Response'
                                 + '  ' + 'status:' + str(status) + '  ' + 'message:' + str(message))
            parsed_json = json.loads(response.content)

            while self.is_last_call_to_make(response) is False:
                response = self.connector.get(response.headers._store['next'][1])
                if response.ok is not True:
                    break
                parsed_json.extend(json.loads(response.content))

            for each_class in parsed_json:
                class_key_id = each_class[key_identifier]
                class_name = each_class['classCode']
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
        #groups = set()
        # member_groups = list() #May not need
        #groups.add(original_group)

        #       User information available from One-Roster
        source_attributes['email'] = formatted_user['email'] = formatted_user['username'] = user['email']
        source_attributes['username'] = user['username']
        source_attributes['givenName'] = formatted_user['firstname'] = user['givenName']
        source_attributes['familyName'] = formatted_user['lastname'] = user['familyName']
        source_attributes['domain'] = formatted_user['domain'] = str(user['email']).split('@')[1]
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