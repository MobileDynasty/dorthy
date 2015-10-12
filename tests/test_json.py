import pytest
from dorthy.json import jsonify
from sqlalchemy import Column, String, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.postgresql import JSON
from dorthy.enum import DeclarativeEnum
from datetime import datetime
import pytz

Base = declarative_base()


@pytest.fixture
def gen_dict():
    test_dict = {
        "stringArg": "hello",
        "intArg": 1,
        "floatArg": 1.2,
        "listArg": ["hello", "world"],
        "dictArg": {"hello": "first", "world": "second"}
    }
    test_dict["recurseArg"] = test_dict
    test_dict['listArg'].append(test_dict)
    test_dict["dictArg"]["recurseArg"] = test_dict
    test_dict["dictArg"]["floatArg"] = test_dict["floatArg"] # this should not trigger recursion probs
    return test_dict


@pytest.fixture
def gen_sqlalchemy():
    class Enum(DeclarativeEnum):
        Option1 = "option1"
        Option2 = "option2"

    class ChildEntity(Base):
        __tablename__ = "child"
        id = Column(Integer, primary_key=True)
        name = Column(String)
        parent_id = Column(Integer, ForeignKey("parent.id"))

    class ParentEntity(Base):
        __tablename__ = "parent"
        id = Column(Integer, primary_key=True)
        name = Column(String)
        attrs = Column(JSON)
        option = Column(Enum.db_type())
        children = relationship(ChildEntity, backref="parent")


    dad = ParentEntity(name="Dad", attrs={"att1": "val1", "attr2": 2}, option=Enum.Option1)
    bobby = ChildEntity(name="Bobby", parent=dad)
    judy = ChildEntity(name="Judy", parent=dad)

    return {'dad': dad, 'bobby': bobby, 'judy': judy}


@pytest.fixture
def gen_obj():
    class ParentObject(object):
        def __init__(self, name, children=None):
            self.name = name
            self.children = children or []

    class ChildObject(object):
        def __init__(self, name, parent=None, siblings=None, cousins=None):
            self.name = name
            self.parent = parent
            self.siblings = siblings
            self.cousins = cousins

    class ChildTransient(ChildObject):
        _transients = ("parent", "siblings", "cousins")

    dad = ParentObject(name="Dad")
    bobby = ChildObject(name="Bobby", parent=dad)
    judy = ChildObject(name="Judy", parent=dad)
    rebel = ChildObject(name="Rebel")
    transient = ChildTransient(name="Trudy", parent=dad)
    jimbob = ChildObject(name="JimBob", siblings=[bobby, ], cousins=(rebel, ))
    dad.children = [bobby, judy, rebel, transient, jimbob]

    return {'dad': dad, 'bobby': bobby, 'judy': judy, 'trudy': transient, 'jimbob': jimbob}


@pytest.fixture
def gen_recur_list():
    the_list = [1, "two"]
    list_one = ["1a", "1b"]
    list_two = ["2a", "2b", list_one] # make sure ancestor checking isn't checking siblings
    the_list.append(list_one)
    the_list.append(list_two)
    the_list.append(the_list) # test recursion handling
    return the_list


def test_jsonify_basics():
    assert jsonify(["hello world's fair", 45, 4.5, None]) == '["hello world\'s fair", 45, 4.5, null]'
    assert jsonify({"num": 99.44, "str": 'string', "none": None}) == '{"none": null, "num": 99.44, "str": "string"}'
    assert jsonify(None) is 'null'
    assert jsonify([datetime(1978, 10, 4, 14, 50, tzinfo=pytz.timezone("US/Mountain"))]) == '["1978-10-04T14:50:00-07:00"]'
    assert jsonify([datetime(1978, 10, 4, 14, 50, tzinfo=pytz.utc)]) == '["1978-10-04T14:50:00+00:00"]'


def test_jsonify_list(gen_recur_list):
    with pytest.raises(ValueError) as excinfo:
        bad_out = jsonify(gen_recur_list)
    assert 'Circular reference detected: list is parent .' in str(excinfo.value)


def test_jsonify_generic_obj(gen_obj):
    with pytest.raises(ValueError) as excinfo:
        bad_out = jsonify(gen_obj["dad"])
    assert 'Circular reference detected: children.parent is parent .' in str(excinfo.value)

    ignore_list_attribute = jsonify(gen_obj["dad"], ignore_attributes=("children",))
    assert ignore_list_attribute == '{"name": "Dad"}'

    respects_transients = jsonify(gen_obj["trudy"])
    assert respects_transients == '{"name": "Trudy"}'


    # two copies of same item, but not an infinite loop
    ignore_list_items = jsonify(gen_obj["dad"], ignore_attributes=("children.parent", "children.siblings.parent", "children.cousins", "children.siblings.cousins"))

    assert ignore_list_items == '{"children": [{"name": "Bobby", "siblings": null}, ' + \
                                '{"name": "Judy", "siblings": null}, {"name": "Rebel", "siblings": null}, ' + \
                                '{"name": "Trudy"}, {"name": "JimBob", "siblings": ' + \
                                '[{"name": "Bobby", "siblings": null}]}], "name": "Dad"}'

    whitelist_collections = jsonify(gen_obj["jimbob"], include_collections=set())
    assert whitelist_collections == '{"name": "JimBob", "parent": null}'

    # parent is ignored, but siblings.parent is not
    blacklist_attributes = jsonify(gen_obj["jimbob"], ignore_attributes=("parent", ), include_collections=("siblings", "siblings.cousins" ))
    assert blacklist_attributes == '{"name": "JimBob", "siblings": [{"cousins": null, "name": "Bobby", "parent": {"name": "Dad"}, "siblings": null}]}'


def test_sqlalchemy(gen_sqlalchemy):

    with pytest.raises(ValueError) as excinfo:
        bad_out = jsonify(gen_sqlalchemy['dad'])
    assert str(excinfo.value) == 'Circular reference detected: children.parent is parent .'

    children_ignored = jsonify(gen_sqlalchemy['dad'], ignore_attributes=("children", ))
    assert children_ignored == '{"attrs": {"att1": "val1", "attr2": 2}, "id": null, "name": "Dad", "option": ' + \
                               '{"description": null, "name": "Option1", "value": "option1"}}'

    # enums count as collections and must be whitelisted if a whitelist is provided. fixme?
    explicit_whitelist = jsonify(gen_sqlalchemy['dad'], include_collections=("attrs", "option"))
    assert explicit_whitelist == '{"attrs": {"att1": "val1", "attr2": 2}, "id": null, "name": "Dad", "option": ' + \
                                 '{"description": null, "name": "Option1", "value": "option1"}}'


    blacklist_attrs_of_children = jsonify(gen_sqlalchemy['dad'], ignore_attributes=("children.parent", ))
    assert blacklist_attrs_of_children == '{"attrs": {"att1": "val1", "attr2": 2}, ' + \
                                          '"children": [{"id": null, "name": "Bobby", "parent_id": null}, ' + \
                                          '{"id": null, "name": "Judy", "parent_id": null}], ' + \
                                          '"id": null, "name": "Dad", ' + \
                                          '"option": {"description": null, "name": "Option1", "value": "option1"}}'

# todo: more test cases
