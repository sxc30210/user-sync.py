import os
import logging
import pytest
import user_sync.helper as help
import csv
from six import StringIO

#Test CSVAdapter class
field_names = ['firstname', 'lastname', 'email', 'country', 'groups', 'type', 'username', 'domain']
user_list = [
        {'firstname': 'John', 'lastname': 'Smith', 'email': 'jsmith@example.com', 'country': 'US',
         'groups': 'AdobeCC-All', 'type': 'enterpriseID', 'username': None, 'domain': None},
        {'firstname': 'Jane', 'lastname': 'Doe', 'email': 'jdoe@example.com', 'country': 'US', 'groups': 'AdobeCC-All',
         'type': 'federatedID', 'username': None, 'domain': None},
        {'firstname': 'Richard', 'lastname': 'Roe', 'email': 'rroe@example.com', 'country': 'US',
         'groups': 'AdobeCC-All', 'type': None, 'username': None, 'domain': None},
        {'firstname': '', 'lastname': 'Dorathy', 'email': None, 'country': None, 'groups': None, 'type': None,
         'username': None, 'domain': None}
    ]
adapter = help.CSVAdapter

def test_open_csv_file():

    mode_r = 'r'
    mode_w = 'w'
    mode_invalid = 'i'
    filename  = 'blank.csv'
    file = open(filename, 'w')
    file.close()
    assert adapter.open_csv_file(filename, mode_r)
    assert adapter.open_csv_file(filename, mode_w)

    with pytest.raises(ValueError) :
        adapter.open_csv_file(filename, mode_invalid)
    os.remove(filename)

def test_guess_delimiter_from_filename():

    filename1 = 'helper_test.csv'
    assert adapter.guess_delimiter_from_filename(filename1) == ','

    filename2 = 'test.tsv'
    assert adapter.guess_delimiter_from_filename(filename2) == '\t'

    #use a wrong delimiter; should default to '\t'
    filename3 = 'test.mtv'
    assert adapter.guess_delimiter_from_filename(filename3) == '\t'


def test_read_csv_rows():
    filename = 'test_read.csv'
    file = open(filename, 'w')
    file.write('firstname,lastname,email,country,groups,type,username,domain\n')
    file.write('John,Smith,jsmith@example.com,US,"AdobeCC-All",enterpriseID\n')
    file.write('Jane,Doe,jdoe@example.com,US,"AdobeCC-All",federatedID\n')
    file.write('Richard,Roe,rroe@example.com,US,"AdobeCC-All"\n')
    file.write(',Dorathy')
    file.close()
    csv_yield = list(adapter.read_csv_rows(filename, field_names))
    reduced_output = [dict(e) for e in csv_yield]
    assert reduced_output == user_list
    os.remove(filename)

def test_write_csv_rows():

    final_user_list = [
        {'firstname': 'John', 'lastname': 'Smith', 'email': 'jsmith@example.com', 'country': 'US',
         'groups': 'AdobeCC-All', 'type': 'enterpriseID', 'username': '', 'domain': ''},
        {'firstname': 'Jane', 'lastname': 'Doe', 'email': 'jdoe@example.com', 'country': 'US', 'groups': 'AdobeCC-All',
         'type': 'federatedID', 'username': '', 'domain': ''},
        {'firstname': 'Richard', 'lastname': 'Roe', 'email': 'rroe@example.com', 'country': 'US',
         'groups': 'AdobeCC-All', 'type': '', 'username': '', 'domain': ''},
        {'firstname': '', 'lastname': 'Dorathy', 'email': '', 'country': '', 'groups': '', 'type': '', 'username': '',
         'domain': ''}
    ]
    filename = 'test.csv'
    adapter.write_csv_rows(filename, field_names, user_list)
    csv_yield = list(adapter.read_csv_rows(filename, field_names))
    reduced_output = [dict(e) for e in csv_yield]
    assert reduced_output == final_user_list

    adapter.write_csv_rows(filename, field_names, final_user_list)
    csv_yield = list(adapter.read_csv_rows(filename, field_names))
    reduced_output = [dict(e) for e in csv_yield]
    assert reduced_output == final_user_list
    os.remove(filename)