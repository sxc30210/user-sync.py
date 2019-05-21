import os
import logging
import pytest
import user_sync.helper as help
import csv

#Test CSVAdapter class

csv_name_r = 'helper_test.csv'
csv_name_w = 'helper_test_w.csv'
adapter = help.CSVAdapter

def test_open_csv_file():

    mode_r = 'r'
    mode_w = 'w'
    mode_invalid = 'i'

    assert adapter.open_csv_file(csv_name_r,mode_r)
    assert adapter.open_csv_file(csv_name_w, mode_w)

    with pytest.raises(ValueError) :
        adapter.open_csv_file(csv_name_r, mode_invalid)


    pass


def test_guess_delimiter_from_filename():

    filename1 = 'helper_test.csv'
    assert adapter.guess_delimiter_from_filename(filename1) == ','

    filename2 = 'test.tsv'
    assert adapter.guess_delimiter_from_filename(filename2) == '\t'

    #use a wrong delimiter; should default to '\t'
    filename3 = 'test.mtv'
    assert adapter.guess_delimiter_from_filename(filename3) == '\t'


def test_read_csv_rows():

    assert adapter.read_csv_rows(csv_name_r)
    #read a bad csv
    assert adapter.read_csv_rows('test_helper.py')

    pass


def test_write_csv_rows():

    #assert filename exists
    field_names = ['firstname','lastname','email','country','groups','type','username','domain']
    rows = [{'firstname' : 'John' , 'lastname' : 'Smith', 'email' : 'jsmith@example.com','country' : 'US','groups' : "AdobeCC-All", 'type' : 'enterpriseID'}]

    #test unrecognized column; lines 111 -112

    assert adapter.write_csv_rows(csv_name_w, field_names, rows) is None
    #read .csv back in and compare it
    pass

