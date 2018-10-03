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


        # Get the configuration information and apply data from YAML

        caller_config = user_sync.config.DictConfig('%s configuration' % self.name, caller_options)
        builder = user_sync.config.OptionsBuilder(caller_config)
        builder.set_string_value('group_filter_format',
                                 '{group}')
        builder.set_string_value('all_users_filter',
                                 '{user|students|teachers}')
        builder.set_string_value('group_name', '{group_name}')
        builder.set_string_value('string_encoding', 'utf8')
        builder.set_string_value('user_identity_type_format', None)
        builder.set_string_value('user_email_format', six.text_type('{email}'))
        builder.set_string_value('user_username_format', None)
        builder.set_string_value('user_domain_format', None)
        builder.set_string_value('user_given_name_format', six.text_type('{firstName}'))
        builder.set_string_value('user_surname_format', six.text_type('{lastName}'))
        builder.set_string_value('user_country_code_format', six.text_type('{countryCode}'))
        builder.set_string_value('user_identity_type', None)
        builder.set_string_value('logger_name', self.name)

        #Values needed to query API, values from YML file
        host = builder.require_string_value('host')
        api_token = builder.require_string_value('api_token_endpoint')
        password = builder.require_string_value('password')
        username = builder.require_string_value('username')




        # Assemble data from YAML into options object
        options = builder.get_options()



        ONEROSTERValueFormatter.encoding = options['string_encoding']
        #added for oneroster yml file, values placed into usable objects
        self.username = ONEROSTERValueFormatter(username)
        self.password = ONEROSTERValueFormatter(password)
        self.host = ONEROSTERValueFormatter(host)
        self.api_token = ONEROSTERValueFormatter(api_token)

        self.group_name = ONEROSTERValueFormatter(options['group_name'])
        self.group_filter = ONEROSTERValueFormatter(options['group_filter'])
        self.user_filter = ONEROSTERValueFormatter(options['user_filter'])

        self.user_identity_type = user_sync.identity_type.parse_identity_type(options['user_identity_type'])
        self.user_identity_type_formatter = ONEROSTERValueFormatter(options['user_identity_type_format'])
        self.user_email_formatter = ONEROSTERValueFormatter(options['user_email_format'])
        self.user_username_formatter = ONEROSTERValueFormatter(options['user_username_format'])
        self.user_domain_formatter = ONEROSTERValueFormatter(options['user_domain_format'])
        self.user_given_name_formatter = ONEROSTERValueFormatter(options['user_given_name_format'])
        self.user_surname_formatter = ONEROSTERValueFormatter(options['user_surname_format'])
        self.user_country_code_formatter = ONEROSTERValueFormatter(options['user_country_code_format'])


        self.logger = logger = user_sync.connector.helper.create_logger(options)
        self.user_identity_type = user_sync.identity_type.parse_identity_type(options['user_identity_type'])
        self.options = options
        caller_config.report_unused_values(logger)

# Makes call to mockroster API, parses response, needs to call convert user to fill user object with necessary values that are missing form API call, that are found from the user_sync.yml file
    def load_users_and_groups(self, groups, extended_attributes, all_users):
        """
        :type groups: list(str)
        :type extended_attributes: list(str)
        :type all_users: bool
        :rtype (bool, iterable(dict))
        """

        extended_attributes = [] #hardcoded for now

        auth = Authenticator(self.username, self.password, self.api_token)
        api_token = auth.retrieve_api_token()

        conn = Connection(self.host, api_token=api_token)

        groups_from_yml = self.parse_yml_groups(groups)

        for group_filter in groups_from_yml:
            inner_dict = groups_from_yml[group_filter]
            for group_name in inner_dict:
                user_filter = inner_dict[group_name]
                if group_filter is 'courses':
                    classes = conn.get_classes_for_course(group_name)
                    for each_class in classes:
                        sourced_id = conn.get_sourced_id('classes', each_class)
                        users_list = conn.get_user_list(group_filter, user_filter, sourced_id)
                        rp = ResultParser()
                        users_result = rp.parse_results(users_list, [])

                else:
                    sourced_id = conn.get_sourced_id(group_filter, group_name)
                    users_list = conn.get_user_list(group_filter, user_filter, sourced_id)
                    rp = ResultParser()
                    users_result = rp.parse_results(users_list, [])




        return six.itervalues(users_result)

# NEEDS WORK
# Values missing from API call that are needed: identity_type, username??, domain, country
# I'm thinking that we can pass the user records from parse_results to this function, which will use values from oneroster.YML&Usersync.YML along with the user record to construct the final user object
    def convert_user(self, user_record, extended_attributes):
        user_record['login'] = login = ONEROSTERValueFormatter.get_profile_value(user_record,'login')

        user = user_sync.connector.helper.create_blank_user()

        user_record['identity_type'] = user_identity_type = self.user_identity_type
        if not user_identity_type:
            user['identity_type'] = self.user_identity_type
        else:
            try:
                user['identity_type'] = user_sync.identity_type.parse_identity_type(user_identity_type)
            except AssertionException as e:
                self.logger.warning('Skipping user %s: %s', login, e)
                return None



        username, last_attribute_name = self.user_username_formatter.generate_value(user_record)
        username = username.strip() if username else None
        user_record['username'] = username
        if username:
            user['username'] = username
        else:
            if last_attribute_name:
                self.logger.warning('No username attribute (%s) for user with login: %s, default to email (%s)',
                                    last_attribute_name, login, email)
            user['username'] = email

        domain, last_attribute_name = self.user_domain_formatter.generate_value(user_record)
        domain = domain.strip() if domain else None
        user_record['domain'] = domain
        if domain:
            user['domain'] = domain
        elif username != email:
            user['domain'] = email[email.find('@') + 1:]
        elif last_attribute_name:
            self.logger.warning('No domain attribute (%s) for user with login: %s', last_attribute_name, login)


        country_value, last_attribute_name = self.user_country_code_formatter.generate_value(user_record)
        user_record['c'] = country_value
        if country_value is not None:
            user['country'] = country_value.upper()
        elif last_attribute_name:
            self.logger.warning('No country code attribute (%s) for user with login: %s', last_attribute_name, login)

        if extended_attributes is not None:
            for extended_attribute in extended_attributes:
                extended_attribute_value = ONEROSTERValueFormatter.get_profile_value(record, extended_attribute)
                user_record[extended_attribute] = extended_attribute_value

        user['source_attributes'] = user_record.copy()
        return user

    def parse_yml_groups(self, groups_list):
        """
        description: parses group options from user-sync.config file into a dict with group_filter as a key and corresponding entries as a list of values
        :type groups_list: set(str)
        :rtype: iterable(dict)
        """
        keys = set()
        full_dict = dict()

        for text in groups_list:
            group_filter, group_name, user_filter = text.split("::")
            keys.add(group_filter)
            if group_filter in full_dict:
                full_dict[group_filter][group_name] = user_filter
            else:
                full_dict[group_filter] = {group_name: user_filter}

        return full_dict

class ONEROSTERValueFormatter(object):
    encoding = 'utf8'

    def __init__(self, string_format):
        """
        The format string must be a unicode or ascii string: see notes above about being careful in Py2!
        """
        if string_format is None:
            attribute_names = []
        else:
            string_format = six.text_type(string_format)  # force unicode so attribute values are unicode
            formatter = string.Formatter()
            attribute_names = [six.text_type(item[1]) for item in formatter.parse(string_format) if item[1]]
        self.string_format = string_format
        self.attribute_names = attribute_names

    def get_attribute_names(self):
        """
        :rtype list(str)
        """
        return self.attribute_names

    @staticmethod
    def get_extended_attribute_dict(attributes):

        attr_dict = {}
        for attribute in attributes:
            if attribute not in attr_dict:
                attr_dict.update({attribute: str})

        return attr_dict

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
                value = self.get_profile_value(record, attribute_name)
                if value is None:
                    values = None
                    break
                values[attribute_name] = value
            if values is not None:
                result = self.string_format.format(**values)
        return result, attribute_name

    @classmethod
    def get_profile_value(cls, record, attribute_name):
        """
        The attribute value type must be decodable (str in py2, bytes in py3)
        :type record: okta.models.user.User
        :type attribute_name: unicode
        """
        if hasattr(record.profile, attribute_name):
            attribute_values = getattr(record.profile,attribute_name)
            if attribute_values:
                try:
                    return attribute_values.decode(cls.encoding)
                except UnicodeError as e:
                    raise AssertionException("Encoding error in value of attribute '%s': %s" % (attribute_name, e))
        return None


# Custom Classes and Functions created

#  Used to retrieve api token from mockroster implementation
class Authenticator:

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

        x = requests.post(Authenticator.__getattribute__(self, 'token_endpoint'),
                          auth=(Authenticator.__getattribute__(self, 'username'),
                                Authenticator.__getattribute__(self, 'password')),
                          headers=header, data=payload)

        parsed_json = json.loads(x.content)

        if x.ok is not True:
            status = parsed_json['status']
            message = parsed_json['message']
            raise ValueError('Token Not Received with the following info:'
                             + '  ' + 'status:' + str(status) + '  ' + 'message:' + str(message))

        token = parsed_json['access_token']

        return token

# Starts connection with mockroster API and makes queries
# ???Idea, to call these classes and functions from within the existing naming conventions used by the UST????

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

    def get_sourced_id(self, group_filter, group_name):
        header = dict()
        payload = dict()
        why = list()
        header['Authorization'] = "Bearer" + Connection.__getattribute__(self, 'api_token')

        endpoint_sourced_id = Connection.__getattribute__(self, 'host_name') + group_filter
        response = requests.get(endpoint_sourced_id, headers=header)
        parsed_json = json.loads(response.content)
        esless = group_filter[:-2] + "Code"

        for x in parsed_json:
            if x[esless] == group_name:
                sourced_id = x['sourcedId']
                why.append(sourced_id)
                break

        return_value = why[0]
        return return_value

    def get_classes_for_course(self, group_name):
        header = dict()
        payload = dict()
        sourced_id_of_classes_within_course = dict()
        header['Authorization'] = "Bearer" + Connection.__getattribute__(self, 'api_token')

        endpoint_sourced_id = Connection.__getattribute__(self, 'host_name') + 'courses'
        response = requests.get(endpoint_sourced_id, headers=header)
        parsed_json = json.loads(response.content)

        for x in parsed_json:
            sourced_id = str(parsed_json['sourcedId'])
            final_endpoint = Connection.__getattribute__(self, 'host_name') + 'courses' + '/' + sourced_id + '/classes'
            response = requests.get(final_endpoint, headers=header)
            parsed_json = json.loads(response.content)
            for xx in parsed_json:
                sourced_id = str(parsed_json['sourcedID'])
                sourced_id_of_classes_within_course[group_name] = sourced_id

        return sourced_id_of_classes_within_course



    def get_user_list(self, group_filter, user_filter, sourced_id):
        header = dict()
        payload = dict()
        header['Authorization'] = "Bearer" + Connection.__getattribute__(self, 'api_token')

        # checks to see if the query is either an allUsers/allStudents/allTeachers call
        if group_filter is None:
            api_endpoint_call = Connection.__getattribute__(self, 'host_name') + user_filter

        else:
            api_endpoint_call = Connection.__getattribute__(self, 'host_name') + \
                            group_filter + '/' + sourced_id + '/' + user_filter

        response = requests.get(api_endpoint_call, headers=header)
        parsed_json = json.loads(response.content)
        return parsed_json

# Parses response from api call

class ResultParser:

    def __init__(self):
        pass

    def parse_results(self, result_set, extended_attributes):
        user_by_id = dict()
        for user in result_set:
            if user['status'] == 'active':
                returned_user = self.create_user_object(user, extended_attributes)
                user_by_id[user['sourcedId']] = returned_user
        return user_by_id

    def create_user_object(self, user, extended_attributes):
        formatted_user = dict()
        source_attributes = dict()
        groups = list()
        member_groups = list()

        user_email = user['email']
        user_given_name = user['givenName']
        user_family_name = user['familyName']
        user_username = user['username']

        source_attributes['email'] = user_email
        source_attributes['givenName'] = user_given_name
        source_attributes['sn'] = user_family_name
        source_attributes['username'] = user_username

        formatted_user['firstname'] = user_given_name
        formatted_user['lastname'] = user_family_name
        formatted_user['email'] = user_email
        formatted_user['groups'] = groups
        formatted_user['memberGroups'] = member_groups
        formatted_user['source_attributes'] = source_attributes


        if extended_attributes is not None:
            for attribute in extended_attributes:
                source_attributes[attribute] = user[attribute]

        formatted_user['source_attributes'] = source_attributes

        return formatted_user


