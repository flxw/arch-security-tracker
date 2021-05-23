
from flask import url_for
from werkzeug.exceptions import Forbidden
from werkzeug.exceptions import NotFound

from tracker.form import CVEForm
from tracker.form.validators import ERROR_INVALID_URL
from tracker.form.validators import ERROR_ISSUE_ID_INVALID
from tracker.model.cve import CVE
from tracker.model.cve import issue_types
from tracker.model.enum import Publication
from tracker.model.enum import Remote
from tracker.model.enum import Severity
from tracker.model.enum import UserRole
from tracker.view.add import CVE_MERGED
from tracker.view.add import CVE_MERGED_PARTIALLY
from tracker.view.add import ERROR_ISSUE_REFERENCED_BY_ADVISORY

from .conftest import DEFAULT_ADVISORY_ID
from .conftest import DEFAULT_GROUP_ID
from .conftest import DEFAULT_GROUP_NAME
from .conftest import DEFAULT_ISSUE_ID
from .conftest import ERROR_INVALID_CHOICE
from .conftest import ERROR_LOGIN_REQUIRED
from .conftest import create_advisory
from .conftest import create_group
from .conftest import create_issue
from .conftest import create_package
from .conftest import default_issue_dict
from .conftest import logged_in


def set_and_assert_cve_data(db, client, cve_id, route):
    issue_type = issue_types[1]
    remote = Remote.remote
    severity = Severity.critical
    description = 'very important description\nstuff'
    notes = 'foobar\n1234'
    reference = 'https://security.archlinux.org/'
    resp = client.post(route, follow_redirects=True,
                       data=dict(cve=cve_id,
                                 issue_type=issue_type,
                                 remote=remote.name,
                                 severity=severity.name,
                                 description=description,
                                 notes=notes,
                                 reference=reference))
    assert 200 == resp.status_code

    cve = CVE.query.get(cve_id)
    assert cve_id == cve.id
    assert issue_type == cve.issue_type
    assert remote == cve.remote
    assert severity == cve.severity
    assert description == cve.description
    assert notes == cve.notes
    assert reference == cve.reference


@logged_in
def test_add_cve(db, client):
    set_and_assert_cve_data(db, client, 'CVE-1122-0042', url_for('tracker.add_cve'))


@logged_in(role=UserRole.reporter)
def test_reporter_can_add(db, client):
    resp = client.post(url_for('tracker.add_cve'), follow_redirects=True, data=default_issue_dict())
    assert 200 == resp.status_code
    cve = CVE.query.get(DEFAULT_ISSUE_ID)
    assert DEFAULT_ISSUE_ID == cve.id


@create_issue
def test_add_needs_login(db, client):
    resp = client.post(url_for('tracker.add_cve'), follow_redirects=True,
                       data=default_issue_dict())
    assert ERROR_LOGIN_REQUIRED in resp.data.decode()


@logged_in
def test_add_invalid_cve_id(db, client):
    cve_id = 'LOL'
    data = default_issue_dict()
    data.update(dict(cve=cve_id))
    resp = client.post(url_for('tracker.add_cve'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert ERROR_ISSUE_ID_INVALID in resp.data.decode()


@logged_in
def test_cve_id_suffix_too_short(db, client):
    cve_id = 'CVE-1234-123'
    data = default_issue_dict()
    data.update(dict(cve=cve_id))
    resp = client.post(url_for('tracker.add_cve'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert ERROR_ISSUE_ID_INVALID in resp.data.decode()


@logged_in
def test_cve_id_suffix_long(db, client):
    cve_id = 'CVE-1234-12345678'
    data = default_issue_dict()
    data.update(dict(cve=cve_id))
    resp = client.post(url_for('tracker.add_cve'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert ERROR_ISSUE_ID_INVALID not in resp.data.decode()


@logged_in
def test_add_invalid_reference(db, client):
    reference = 'OMG'
    data = default_issue_dict()
    data.update(dict(reference=reference))
    resp = client.post(url_for('tracker.add_cve'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert ERROR_INVALID_URL.format(reference) in resp.data.decode()


@logged_in
def test_add_invalid_severity(db, client):
    data = default_issue_dict()
    data.update(dict(severity='OMG'))
    resp = client.post(url_for('tracker.add_cve'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert ERROR_INVALID_CHOICE in resp.data.decode()
    assert 1 == resp.data.decode().count(ERROR_INVALID_CHOICE)


@logged_in
def test_add_invalid_remote(db, client):
    data = default_issue_dict()
    data.update(dict(remote='OMG'))
    resp = client.post(url_for('tracker.add_cve'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert ERROR_INVALID_CHOICE in resp.data.decode()
    assert 1 == resp.data.decode().count(ERROR_INVALID_CHOICE)


@logged_in
def test_add_invalid_type(db, client):
    data = default_issue_dict()
    data.update(dict(issue_type='OMG'))
    resp = client.post(url_for('tracker.add_cve'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert ERROR_INVALID_CHOICE in resp.data.decode()
    assert 1 == resp.data.decode().count(ERROR_INVALID_CHOICE)


@create_issue
@logged_in
def test_edit_cve(db, client):
    set_and_assert_cve_data(db, client, DEFAULT_ISSUE_ID, url_for('tracker.edit_cve', cve=DEFAULT_ISSUE_ID))


@create_issue
@logged_in(role=UserRole.reporter)
def test_reporter_can_edit(db, client):
    description = 'LOLWUT'
    data = default_issue_dict()
    data.update(dict(description=description))
    resp = client.post(url_for('tracker.edit_cve', cve=DEFAULT_ISSUE_ID), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    cve = CVE.query.get(DEFAULT_ISSUE_ID)
    assert description == cve.description


@create_issue
@logged_in(role=UserRole.reporter)
def test_edit_cve_invalid(db, client):
    data = default_issue_dict()
    data.update(dict(issue_type='OMG'))
    resp = client.post(url_for('tracker.edit_cve', cve=DEFAULT_ISSUE_ID), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert 'Edit {}'.format(DEFAULT_ISSUE_ID) in resp.data.decode()
    assert ERROR_INVALID_CHOICE in resp.data.decode()
    assert 1 == resp.data.decode().count(ERROR_INVALID_CHOICE)


@create_issue
@logged_in(role=UserRole.reporter)
def test_reporter_can_delete(db, client):
    resp = client.post(url_for('tracker.delete_issue', issue=DEFAULT_ISSUE_ID), follow_redirects=True,
                       data=dict(confirm=True))
    assert 200 == resp.status_code
    cve = CVE.query.get(DEFAULT_ISSUE_ID)
    assert cve is None


@create_issue
@logged_in(role=UserRole.reporter)
def test_reporter_can_copy(db, client):
    resp = client.get(url_for('tracker.copy_issue', issue=DEFAULT_ISSUE_ID), follow_redirects=True)
    assert 200 == resp.status_code
    assert ERROR_LOGIN_REQUIRED not in resp.data.decode()


@create_issue
@logged_in(role=UserRole.reporter)
def test_abort_delete(db, client):
    resp = client.post(url_for('tracker.delete_issue', issue=DEFAULT_ISSUE_ID), follow_redirects=True,
                       data=dict(abort=True))
    assert 200 == resp.status_code
    cve = CVE.query.get(DEFAULT_ISSUE_ID)
    assert DEFAULT_ISSUE_ID == cve.id


@create_issue
def test_edit_needs_login(db, client):
    resp = client.post(url_for('tracker.edit_cve', cve=DEFAULT_ISSUE_ID), follow_redirects=True)
    assert ERROR_LOGIN_REQUIRED in resp.data.decode()


@create_issue
def test_delete_needs_login(db, client):
    resp = client.post(url_for('tracker.delete_issue', issue=DEFAULT_ISSUE_ID), follow_redirects=True)
    assert ERROR_LOGIN_REQUIRED in resp.data.decode()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1])
@logged_in
def test_forbid_delete_with_advisory(db, client):
    resp = client.post(url_for('tracker.delete_issue', issue=DEFAULT_ISSUE_ID), follow_redirects=True)
    assert Forbidden.code == resp.status_code


@create_issue
def test_copy_needs_login(db, client):
    resp = client.get(url_for('tracker.copy_issue', issue=DEFAULT_ISSUE_ID), follow_redirects=True)
    assert ERROR_LOGIN_REQUIRED in resp.data.decode()


@create_issue
def test_show_issue(db, client):
    resp = client.get(url_for('tracker.show_cve', cve=DEFAULT_ISSUE_ID, path=''))
    assert 200 == resp.status_code
    assert DEFAULT_ISSUE_ID in resp.data.decode()


@logged_in
def test_show_issue_not_found(db, client):
    resp = client.get(url_for('tracker.show_cve', cve='CVE-2011-0000', path=''), follow_redirects=True)
    assert resp.status_code == NotFound.code


@create_issue
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', issues=[DEFAULT_ISSUE_ID])
def test_show_issue_group_links(db, client):
    resp = client.get(url_for('tracker.show_cve', cve=DEFAULT_ISSUE_ID, path=''))
    assert 200 == resp.status_code
    data = resp.data.decode('utf-8')
    assert '<a href="/{0}">{0}</a>'.format(DEFAULT_GROUP_NAME) in data
    assert '<a href="/package/{0}">{0}</a>'.format('foo') in data


@logged_in
def test_edit_issue_not_found(db, client):
    resp = client.post(url_for('tracker.edit_cve', cve='CVE-2011-0000'), follow_redirects=True,
                       data=default_issue_dict())
    assert resp.status_code == NotFound.code


@logged_in
def test_copy_issue_not_found(db, client):
    resp = client.get(url_for('tracker.copy_issue', issue='CVE-2011-0000', path=''), follow_redirects=True)
    assert resp.status_code == NotFound.code


@logged_in
def test_delete_issue_not_found(db, client):
    resp = client.post(url_for('tracker.delete_issue', issue='CVE-2011-0000'), follow_redirects=True)
    assert resp.status_code == NotFound.code


@create_issue
def test_issue_json(db, client):
    resp = client.get(url_for('tracker.show_cve_json', cve=DEFAULT_ISSUE_ID, path='', suffix='.json'), follow_redirects=True)
    assert 200 == resp.status_code

    data = resp.get_json()
    assert DEFAULT_ISSUE_ID == data['name']


def test_issue_json_not_found(db, client):
    resp = client.get(url_for('tracker.show_cve_json', cve=DEFAULT_ISSUE_ID, path='', suffix='.json'), follow_redirects=True)
    assert resp.status_code == NotFound.code


@create_issue
@logged_in
def test_add_cve_overwrites_existing_but_empty_cve(db, client):
    issue_type = issue_types[1]
    severity = Severity.critical
    remote = Remote.remote
    description = 'much wow'
    reference = 'https://security.archlinux.org'
    notes = 'very secret'
    resp = client.post(url_for('tracker.add_cve'), follow_redirects=True, data=default_issue_dict(dict(
                       cve=DEFAULT_ISSUE_ID,
                       issue_type=issue_type,
                       severity=severity.name,
                       remote=remote.name,
                       description=description,
                       reference=reference,
                       notes=notes)))
    assert 200 == resp.status_code
    assert CVE_MERGED.format(DEFAULT_ISSUE_ID) in resp.data.decode()
    assert CVE_MERGED_PARTIALLY.format(DEFAULT_ISSUE_ID, '') not in resp.data.decode()

    cve = CVE.query.get(DEFAULT_ISSUE_ID)
    assert DEFAULT_ISSUE_ID == cve.id
    assert issue_type == cve.issue_type
    assert severity == cve.severity
    assert remote == cve.remote
    assert description == cve.description
    assert reference == cve.reference
    assert notes == cve.notes


@create_issue(issue_type=issue_types[3], severity=Severity.low, remote=Remote.local,
              description='foobar', reference='https://archlinux.org', notes='the cake is a lie')
@logged_in
def test_add_cve_does_not_overwrite_existing_cve(db, client):
    resp = client.post(url_for('tracker.add_cve'), follow_redirects=True, data=default_issue_dict(dict(
                       cve=DEFAULT_ISSUE_ID,
                       issue_type=issue_types[1],
                       severity=Severity.critical.name,
                       remote=Remote.remote.name,
                       description='deadbeef',
                       reference='https://security.archlinux.org',
                       notes='very secret')))
    assert 200 == resp.status_code

    assert CVE_MERGED.format(DEFAULT_ISSUE_ID) in resp.data.decode()
    form = CVEForm()
    unmerged_fields = [form.issue_type.label.text,
                       form.severity.label.text,
                       form.remote.label.text,
                       form.description.label.text,
                       form.notes.label.text]
    assert CVE_MERGED_PARTIALLY.format(DEFAULT_ISSUE_ID, ', '.join(unmerged_fields)) in resp.data.decode()

    cve = CVE.query.get(DEFAULT_ISSUE_ID)
    assert DEFAULT_ISSUE_ID == cve.id
    assert issue_types[3] == cve.issue_type
    assert Severity.low == cve.severity
    assert Remote.local == cve.remote
    assert 'foobar' == cve.description
    assert 'https://archlinux.org\nhttps://security.archlinux.org' == cve.reference
    assert 'the cake is a lie' == cve.notes


@create_issue(description='foo AVG-1 bar CVE-1234-5678 qux https://foo.bar doo CVE-1337-1337.')
def test_show_issue_urlize_description(db, client):
    resp = client.get(url_for('tracker.show_cve', cve=DEFAULT_ISSUE_ID, path=''))
    assert 200 == resp.status_code
    data = resp.data.decode()
    assert 'foo <a href="/{0}" rel="noopener">{0}</a> bar'.format('AVG-1') in data
    assert 'bar <a href="/{0}" rel="noopener">{0}</a> qux'.format('CVE-1234-5678') in data
    assert 'qux <a href="{0}" rel="noopener">{0}</a> doo'.format('https://foo.bar') in data
    assert 'doo <a href="/{0}" rel="noopener">{0}</a>.'.format('CVE-1337-1337') in data


@create_issue(notes='foo AVG-1 bar CVE-1234-5678 qux https://foo.bar doo CVE-1337-1337.')
def test_show_issue_urlize_notes(db, client):
    resp = client.get(url_for('tracker.show_cve', cve=DEFAULT_ISSUE_ID, path=''))
    assert 200 == resp.status_code
    data = resp.data.decode()
    assert 'foo <a href="/{0}" rel="noopener">{0}</a> bar'.format('AVG-1') in data
    assert 'bar <a href="/{0}" rel="noopener">{0}</a> qux'.format('CVE-1234-5678') in data
    assert 'qux <a href="{0}" rel="noopener">{0}</a> doo'.format('https://foo.bar') in data
    assert 'doo <a href="/{0}" rel="noopener">{0}</a>.'.format('CVE-1337-1337') in data


@create_issue
@logged_in
def test_edit_issue_non_relational_field_updates_changed_date(db, client):
    issue_changed_old = CVE.query.get(DEFAULT_ISSUE_ID).changed

    resp = client.post(url_for('tracker.edit_cve', cve=DEFAULT_ISSUE_ID), follow_redirects=True,
                       data=default_issue_dict(dict(description='changed')))
    assert 200 == resp.status_code
    assert f'Edited {DEFAULT_ISSUE_ID}' in resp.data.decode()

    issue = CVE.query.get(DEFAULT_ISSUE_ID)
    assert issue.changed > issue_changed_old


@create_issue(issue_type=issue_types[0])
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', issues=[DEFAULT_ISSUE_ID])
@logged_in
def test_edit_issue_changed_severity_updates_changed_date(db, client):
    issue_changed_old = CVE.query.get(DEFAULT_ISSUE_ID).changed

    resp = client.post(url_for('tracker.edit_cve', cve=DEFAULT_ISSUE_ID), follow_redirects=True,
                       data=default_issue_dict(dict(issue_type=issue_types[1])))
    assert 200 == resp.status_code
    assert f'Edited {DEFAULT_ISSUE_ID}' in resp.data.decode()

    issue = CVE.query.get(DEFAULT_ISSUE_ID)
    assert issue.changed > issue_changed_old


@create_issue
@logged_in
def test_edit_issue_does_nothing_when_data_is_same(db, client):
    issue_changed_old = CVE.query.get(DEFAULT_ISSUE_ID).changed

    resp = client.post(url_for('tracker.edit_cve', cve=DEFAULT_ISSUE_ID), follow_redirects=True,
                       data=default_issue_dict())
    assert 200 == resp.status_code
    assert f'Edited {DEFAULT_ISSUE_ID}' not in resp.data.decode()

    issue = CVE.query.get(DEFAULT_ISSUE_ID)
    assert issue.changed == issue_changed_old


@create_issue
@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1], reference='https://security.archlinux.org', publication=Publication.scheduled)
@logged_in(role=UserRole.reporter)
def test_edit_issue_as_reporter_with_referenced_advisory_fails(db, client):
    resp = client.post(url_for('tracker.edit_cve', cve=DEFAULT_ISSUE_ID), follow_redirects=True,
                       data=default_issue_dict(dict(description='changed')))
    assert Forbidden.code == resp.status_code

    data = resp.data.decode()
    assert f'Edited {DEFAULT_ISSUE_ID}' not in data
    assert ERROR_ISSUE_REFERENCED_BY_ADVISORY.format(DEFAULT_ISSUE_ID) in data

    issue = CVE.query.get(DEFAULT_ISSUE_ID)
    assert 'changed' not in issue.description


@create_issue
@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1], reference='https://security.archlinux.org', publication=Publication.scheduled)
@logged_in(role=UserRole.security_team)
def test_edit_issue_as_security_team_with_referenced_advisory(db, client):
    resp = client.post(url_for('tracker.edit_cve', cve=DEFAULT_ISSUE_ID), follow_redirects=True,
                       data=default_issue_dict(dict(description='changed')))
    assert 200 == resp.status_code

    data = resp.data.decode()
    assert f'Edited {DEFAULT_ISSUE_ID}' in data

    issue = CVE.query.get(DEFAULT_ISSUE_ID)
    assert 'changed' == issue.description



@create_issue
@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1], reference='https://security.archlinux.org', publication=Publication.scheduled)
@logged_in(role=UserRole.reporter)
def test_merge_issue_as_reporter_with_referenced_advisory_fails(db, client):
    resp = client.post(url_for('tracker.add_cve', cve=DEFAULT_ISSUE_ID), follow_redirects=True,
                       data=default_issue_dict(dict(description='changed')))
    assert Forbidden.code == resp.status_code

    data = resp.data.decode()
    assert CVE_MERGED.format(DEFAULT_ISSUE_ID) not in data
    assert CVE_MERGED_PARTIALLY.format(DEFAULT_ISSUE_ID, '') not in data
    assert ERROR_ISSUE_REFERENCED_BY_ADVISORY.format(DEFAULT_ISSUE_ID) in data

    issue = CVE.query.get(DEFAULT_ISSUE_ID)
    assert 'changed' not in issue.description


@create_issue
@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1], reference='https://security.archlinux.org', publication=Publication.scheduled)
@logged_in(role=UserRole.security_team)
def test_merge_issue_as_security_team_with_referenced_advisory(db, client):
    resp = client.post(url_for('tracker.add_cve', cve=DEFAULT_ISSUE_ID), follow_redirects=True,
                       data=default_issue_dict(dict(description='changed')))
    assert 200 == resp.status_code

    data = resp.data.decode()
    assert CVE_MERGED.format(DEFAULT_ISSUE_ID) in data
    assert CVE_MERGED_PARTIALLY.format(DEFAULT_ISSUE_ID, '') not in data

    issue = CVE.query.get(DEFAULT_ISSUE_ID)
    assert 'changed' == issue.description
