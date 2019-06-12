# (c) 2016, Adrian Likins <alikins@redhat.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import ansible
import json
import os
import pytest
import shutil
import tarfile
import tempfile
import yaml

from ansible import context
from ansible.cli.arguments import option_helpers as opt_help
from ansible.cli.galaxy import GalaxyCLI
from ansible.errors import AnsibleError
from ansible.utils import context_objects as co
from units.compat import unittest
from units.compat.mock import call, patch


@pytest.fixture(autouse='function')
def reset_cli_args():
    co.GlobalCLIArgs._Singleton__instance = None
    yield
    co.GlobalCLIArgs._Singleton__instance = None


class TestGalaxy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        '''creating prerequisites for installing a role; setUpClass occurs ONCE whereas setUp occurs with every method tested.'''
        # class data for easy viewing: role_dir, role_tar, role_name, role_req, role_path

        cls.temp_dir = tempfile.mkdtemp(prefix='ansible-test_galaxy-')
        os.chdir(cls.temp_dir)

        if os.path.exists("./delete_me"):
            shutil.rmtree("./delete_me")

        # creating framework for a role
        gc = GalaxyCLI(args=["ansible-galaxy", "init", "--offline", "delete_me"])
        gc.run()
        cls.role_dir = "./delete_me"
        cls.role_name = "delete_me"

        # making a temp dir for role installation
        cls.role_path = os.path.join(tempfile.mkdtemp(), "roles")
        if not os.path.isdir(cls.role_path):
            os.makedirs(cls.role_path)

        # creating a tar file name for class data
        cls.role_tar = './delete_me.tar.gz'
        cls.makeTar(cls.role_tar, cls.role_dir)

        # creating a temp file with installation requirements
        cls.role_req = './delete_me_requirements.yml'
        fd = open(cls.role_req, "w")
        fd.write("- 'src': '%s'\n  'name': '%s'\n  'path': '%s'" % (cls.role_tar, cls.role_name, cls.role_path))
        fd.close()

    @classmethod
    def makeTar(cls, output_file, source_dir):
        ''' used for making a tarfile from a role directory '''
        # adding directory into a tar file
        try:
            tar = tarfile.open(output_file, "w:gz")
            tar.add(source_dir, arcname=os.path.basename(source_dir))
        except AttributeError:  # tarfile obj. has no attribute __exit__ prior to python 2.    7
            pass
        finally:  # ensuring closure of tarfile obj
            tar.close()

    @classmethod
    def tearDownClass(cls):
        '''After tests are finished removes things created in setUpClass'''
        # deleting the temp role directory
        if os.path.exists(cls.role_dir):
            shutil.rmtree(cls.role_dir)
        if os.path.exists(cls.role_req):
            os.remove(cls.role_req)
        if os.path.exists(cls.role_tar):
            os.remove(cls.role_tar)
        if os.path.isdir(cls.role_path):
            shutil.rmtree(cls.role_path)

        os.chdir('/')
        shutil.rmtree(cls.temp_dir)

    def setUp(self):
        # Reset the stored command line args
        co.GlobalCLIArgs._Singleton__instance = None
        self.default_args = ['ansible-galaxy']

    def tearDown(self):
        # Reset the stored command line args
        co.GlobalCLIArgs._Singleton__instance = None

    def test_init(self):
        galaxy_cli = GalaxyCLI(args=self.default_args)
        self.assertTrue(isinstance(galaxy_cli, GalaxyCLI))

    def test_display_min(self):
        gc = GalaxyCLI(args=self.default_args)
        role_info = {'name': 'some_role_name'}
        display_result = gc._display_role_info(role_info)
        self.assertTrue(display_result.find('some_role_name') > -1)

    def test_display_galaxy_info(self):
        gc = GalaxyCLI(args=self.default_args)
        galaxy_info = {}
        role_info = {'name': 'some_role_name',
                     'galaxy_info': galaxy_info}
        display_result = gc._display_role_info(role_info)
        if display_result.find('\n\tgalaxy_info:') == -1:
            self.fail('Expected galaxy_info to be indented once')

    def test_run(self):
        ''' verifies that the GalaxyCLI object's api is created and that execute() is called. '''
        gc = GalaxyCLI(args=["ansible-galaxy", "install", "--ignore-errors", "imaginary_role"])
        gc.parse()
        with patch.object(ansible.cli.CLI, "run", return_value=None) as mock_run:
            gc.run()
            # testing
            self.assertIsInstance(gc.galaxy, ansible.galaxy.Galaxy)
            self.assertEqual(mock_run.call_count, 1)
            self.assertTrue(isinstance(gc.api, ansible.galaxy.api.GalaxyAPI))

    def test_execute_remove(self):
        # installing role
        gc = GalaxyCLI(args=["ansible-galaxy", "install", "-p", self.role_path, "-r", self.role_req, '--force'])
        gc.run()

        # location where the role was installed
        role_file = os.path.join(self.role_path, self.role_name)

        # removing role
        # Have to reset the arguments in the context object manually since we're doing the
        # equivalent of running the command line program twice
        co.GlobalCLIArgs._Singleton__instance = None
        gc = GalaxyCLI(args=["ansible-galaxy", "remove", role_file, self.role_name])
        gc.run()

        # testing role was removed
        removed_role = not os.path.exists(role_file)
        self.assertTrue(removed_role)

    def test_exit_without_ignore_without_flag(self):
        ''' tests that GalaxyCLI exits with the error specified if the --ignore-errors flag is not used '''
        gc = GalaxyCLI(args=["ansible-galaxy", "install", "--server=None", "fake_role_name"])
        with patch.object(ansible.utils.display.Display, "display", return_value=None) as mocked_display:
            # testing that error expected is raised
            self.assertRaises(AnsibleError, gc.run)
            self.assertTrue(mocked_display.called_once_with("- downloading role 'fake_role_name', owned by "))

    def test_exit_without_ignore_with_flag(self):
        ''' tests that GalaxyCLI exits without the error specified if the --ignore-errors flag is used  '''
        # testing with --ignore-errors flag
        gc = GalaxyCLI(args=["ansible-galaxy", "install", "--server=None", "fake_role_name", "--ignore-errors"])
        with patch.object(ansible.utils.display.Display, "display", return_value=None) as mocked_display:
            gc.run()
            self.assertTrue(mocked_display.called_once_with("- downloading role 'fake_role_name', owned by "))

    def test_parse_no_action(self):
        ''' testing the options parser when no action is given '''
        gc = GalaxyCLI(args=["ansible-galaxy", ""])
        self.assertRaises(SystemExit, gc.parse)

    def test_parse_invalid_action(self):
        ''' testing the options parser when an invalid action is given '''
        gc = GalaxyCLI(args=["ansible-galaxy", "NOT_ACTION"])
        self.assertRaises(SystemExit, gc.parse)

    def test_parse_delete(self):
        ''' testing the options parser when the action 'delete' is given '''
        gc = GalaxyCLI(args=["ansible-galaxy", "delete", "foo", "bar"])
        gc.parse()
        self.assertEqual(context.CLIARGS['verbosity'], 0)

    def test_parse_import(self):
        ''' testing the options parser when the action 'import' is given '''
        gc = GalaxyCLI(args=["ansible-galaxy", "import", "foo", "bar"])
        gc.parse()
        self.assertEqual(context.CLIARGS['wait'], True)
        self.assertEqual(context.CLIARGS['reference'], None)
        self.assertEqual(context.CLIARGS['check_status'], False)
        self.assertEqual(context.CLIARGS['verbosity'], 0)

    def test_parse_info(self):
        ''' testing the options parser when the action 'info' is given '''
        gc = GalaxyCLI(args=["ansible-galaxy", "info", "foo", "bar"])
        gc.parse()
        self.assertEqual(context.CLIARGS['offline'], False)

    def test_parse_init(self):
        ''' testing the options parser when the action 'init' is given '''
        gc = GalaxyCLI(args=["ansible-galaxy", "init", "foo"])
        gc.parse()
        self.assertEqual(context.CLIARGS['offline'], False)
        self.assertEqual(context.CLIARGS['force'], False)

    def test_parse_install(self):
        ''' testing the options parser when the action 'install' is given '''
        gc = GalaxyCLI(args=["ansible-galaxy", "install"])
        gc.parse()
        self.assertEqual(context.CLIARGS['ignore_errors'], False)
        self.assertEqual(context.CLIARGS['no_deps'], False)
        self.assertEqual(context.CLIARGS['role_file'], None)
        self.assertEqual(context.CLIARGS['force'], False)

    def test_parse_list(self):
        ''' testing the options parser when the action 'list' is given '''
        gc = GalaxyCLI(args=["ansible-galaxy", "list"])
        gc.parse()
        self.assertEqual(context.CLIARGS['verbosity'], 0)

    def test_parse_login(self):
        ''' testing the options parser when the action 'login' is given '''
        gc = GalaxyCLI(args=["ansible-galaxy", "login"])
        gc.parse()
        self.assertEqual(context.CLIARGS['verbosity'], 0)
        self.assertEqual(context.CLIARGS['token'], None)

    def test_parse_remove(self):
        ''' testing the options parser when the action 'remove' is given '''
        gc = GalaxyCLI(args=["ansible-galaxy", "remove", "foo"])
        gc.parse()
        self.assertEqual(context.CLIARGS['verbosity'], 0)

    def test_parse_search(self):
        ''' testing the options parswer when the action 'search' is given '''
        gc = GalaxyCLI(args=["ansible-galaxy", "search"])
        gc.parse()
        self.assertEqual(context.CLIARGS['platforms'], None)
        self.assertEqual(context.CLIARGS['galaxy_tags'], None)
        self.assertEqual(context.CLIARGS['author'], None)

    def test_parse_setup(self):
        ''' testing the options parser when the action 'setup' is given '''
        gc = GalaxyCLI(args=["ansible-galaxy", "setup", "source", "github_user", "github_repo", "secret"])
        gc.parse()
        self.assertEqual(context.CLIARGS['verbosity'], 0)
        self.assertEqual(context.CLIARGS['remove_id'], None)
        self.assertEqual(context.CLIARGS['setup_list'], False)


class ValidRoleTests(object):

    expected_role_dirs = ('defaults', 'files', 'handlers', 'meta', 'tasks', 'templates', 'vars', 'tests')

    @classmethod
    def setUpRole(cls, role_name, galaxy_args=None, skeleton_path=None, use_explicit_type=False):
        if galaxy_args is None:
            galaxy_args = []

        if skeleton_path is not None:
            cls.role_skeleton_path = skeleton_path
            galaxy_args += ['--role-skeleton', skeleton_path]

        # Make temp directory for testing
        cls.test_dir = tempfile.mkdtemp()
        if not os.path.isdir(cls.test_dir):
            os.makedirs(cls.test_dir)

        cls.role_dir = os.path.join(cls.test_dir, role_name)
        cls.role_name = role_name

        # create role using default skeleton
        args = ['ansible-galaxy']
        if use_explicit_type:
            args += ['role']
        args += ['init', '-c', '--offline'] + galaxy_args + ['--init-path', cls.test_dir, cls.role_name]

        gc = GalaxyCLI(args=args)
        gc.run()
        cls.gc = gc

        if skeleton_path is None:
            cls.role_skeleton_path = gc.galaxy.default_role_skeleton_path

    @classmethod
    def tearDownClass(cls):
        if os.path.isdir(cls.test_dir):
            shutil.rmtree(cls.test_dir)

    def test_metadata(self):
        with open(os.path.join(self.role_dir, 'meta', 'main.yml'), 'r') as mf:
            metadata = yaml.safe_load(mf)
        self.assertIn('galaxy_info', metadata, msg='unable to find galaxy_info in metadata')
        self.assertIn('dependencies', metadata, msg='unable to find dependencies in metadata')

    def test_readme(self):
        readme_path = os.path.join(self.role_dir, 'README.md')
        self.assertTrue(os.path.exists(readme_path), msg='Readme doesn\'t exist')

    def test_main_ymls(self):
        need_main_ymls = set(self.expected_role_dirs) - set(['meta', 'tests', 'files', 'templates'])
        for d in need_main_ymls:
            main_yml = os.path.join(self.role_dir, d, 'main.yml')
            self.assertTrue(os.path.exists(main_yml))
            expected_string = "---\n# {0} file for {1}".format(d, self.role_name)
            with open(main_yml, 'r') as f:
                self.assertEqual(expected_string, f.read().strip())

    def test_role_dirs(self):
        for d in self.expected_role_dirs:
            self.assertTrue(os.path.isdir(os.path.join(self.role_dir, d)), msg="Expected role subdirectory {0} doesn't exist".format(d))

    def test_travis_yml(self):
        with open(os.path.join(self.role_dir, '.travis.yml'), 'r') as f:
            contents = f.read()

        with open(os.path.join(self.role_skeleton_path, '.travis.yml'), 'r') as f:
            expected_contents = f.read()

        self.assertEqual(expected_contents, contents, msg='.travis.yml does not match expected')

    def test_readme_contents(self):
        with open(os.path.join(self.role_dir, 'README.md'), 'r') as readme:
            contents = readme.read()

        with open(os.path.join(self.role_skeleton_path, 'README.md'), 'r') as f:
            expected_contents = f.read()

        self.assertEqual(expected_contents, contents, msg='README.md does not match expected')

    def test_test_yml(self):
        with open(os.path.join(self.role_dir, 'tests', 'test.yml'), 'r') as f:
            test_playbook = yaml.safe_load(f)
        print(test_playbook)
        self.assertEqual(len(test_playbook), 1)
        self.assertEqual(test_playbook[0]['hosts'], 'localhost')
        self.assertEqual(test_playbook[0]['remote_user'], 'root')
        self.assertListEqual(test_playbook[0]['roles'], [self.role_name], msg='The list of roles included in the test play doesn\'t match')


class TestGalaxyInitDefault(unittest.TestCase, ValidRoleTests):

    @classmethod
    def setUpClass(cls):
        cls.setUpRole(role_name='delete_me')

    def test_metadata_contents(self):
        with open(os.path.join(self.role_dir, 'meta', 'main.yml'), 'r') as mf:
            metadata = yaml.safe_load(mf)
        self.assertEqual(metadata.get('galaxy_info', dict()).get('author'), 'your name', msg='author was not set properly in metadata')


class TestGalaxyInitAPB(unittest.TestCase, ValidRoleTests):

    @classmethod
    def setUpClass(cls):
        cls.setUpRole('delete_me_apb', galaxy_args=['--type=apb'])

    def test_metadata_apb_tag(self):
        with open(os.path.join(self.role_dir, 'meta', 'main.yml'), 'r') as mf:
            metadata = yaml.safe_load(mf)
        self.assertIn('apb', metadata.get('galaxy_info', dict()).get('galaxy_tags', []), msg='apb tag not set in role metadata')

    def test_metadata_contents(self):
        with open(os.path.join(self.role_dir, 'meta', 'main.yml'), 'r') as mf:
            metadata = yaml.safe_load(mf)
        self.assertEqual(metadata.get('galaxy_info', dict()).get('author'), 'your name', msg='author was not set properly in metadata')

    def test_apb_yml(self):
        self.assertTrue(os.path.exists(os.path.join(self.role_dir, 'apb.yml')), msg='apb.yml was not created')

    def test_test_yml(self):
        with open(os.path.join(self.role_dir, 'tests', 'test.yml'), 'r') as f:
            test_playbook = yaml.safe_load(f)
        print(test_playbook)
        self.assertEqual(len(test_playbook), 1)
        self.assertEqual(test_playbook[0]['hosts'], 'localhost')
        self.assertFalse(test_playbook[0]['gather_facts'])
        self.assertEqual(test_playbook[0]['connection'], 'local')
        self.assertIsNone(test_playbook[0]['tasks'], msg='We\'re expecting an unset list of tasks in test.yml')


class TestGalaxyInitContainer(unittest.TestCase, ValidRoleTests):

    @classmethod
    def setUpClass(cls):
        cls.setUpRole('delete_me_container', galaxy_args=['--type=container'])

    def test_metadata_container_tag(self):
        with open(os.path.join(self.role_dir, 'meta', 'main.yml'), 'r') as mf:
            metadata = yaml.safe_load(mf)
        self.assertIn('container', metadata.get('galaxy_info', dict()).get('galaxy_tags', []), msg='container tag not set in role metadata')

    def test_metadata_contents(self):
        with open(os.path.join(self.role_dir, 'meta', 'main.yml'), 'r') as mf:
            metadata = yaml.safe_load(mf)
        self.assertEqual(metadata.get('galaxy_info', dict()).get('author'), 'your name', msg='author was not set properly in metadata')

    def test_meta_container_yml(self):
        self.assertTrue(os.path.exists(os.path.join(self.role_dir, 'meta', 'container.yml')), msg='container.yml was not created')

    def test_test_yml(self):
        with open(os.path.join(self.role_dir, 'tests', 'test.yml'), 'r') as f:
            test_playbook = yaml.safe_load(f)
        print(test_playbook)
        self.assertEqual(len(test_playbook), 1)
        self.assertEqual(test_playbook[0]['hosts'], 'localhost')
        self.assertFalse(test_playbook[0]['gather_facts'])
        self.assertEqual(test_playbook[0]['connection'], 'local')
        self.assertIsNone(test_playbook[0]['tasks'], msg='We\'re expecting an unset list of tasks in test.yml')


class TestGalaxyInitSkeleton(unittest.TestCase, ValidRoleTests):

    @classmethod
    def setUpClass(cls):
        role_skeleton_path = os.path.join(os.path.split(__file__)[0], 'test_data', 'role_skeleton')
        cls.setUpRole('delete_me_skeleton', skeleton_path=role_skeleton_path, use_explicit_type=True)

    def test_empty_files_dir(self):
        files_dir = os.path.join(self.role_dir, 'files')
        self.assertTrue(os.path.isdir(files_dir))
        self.assertListEqual(os.listdir(files_dir), [], msg='we expect the files directory to be empty, is ignore working?')

    def test_template_ignore_jinja(self):
        test_conf_j2 = os.path.join(self.role_dir, 'templates', 'test.conf.j2')
        self.assertTrue(os.path.exists(test_conf_j2), msg="The test.conf.j2 template doesn't seem to exist, is it being rendered as test.conf?")
        with open(test_conf_j2, 'r') as f:
            contents = f.read()
        expected_contents = '[defaults]\ntest_key = {{ test_variable }}'
        self.assertEqual(expected_contents, contents.strip(), msg="test.conf.j2 doesn't contain what it should, is it being rendered?")

    def test_template_ignore_jinja_subfolder(self):
        test_conf_j2 = os.path.join(self.role_dir, 'templates', 'subfolder', 'test.conf.j2')
        self.assertTrue(os.path.exists(test_conf_j2), msg="The test.conf.j2 template doesn't seem to exist, is it being rendered as test.conf?")
        with open(test_conf_j2, 'r') as f:
            contents = f.read()
        expected_contents = '[defaults]\ntest_key = {{ test_variable }}'
        self.assertEqual(expected_contents, contents.strip(), msg="test.conf.j2 doesn't contain what it should, is it being rendered?")

    def test_template_ignore_similar_folder(self):
        self.assertTrue(os.path.exists(os.path.join(self.role_dir, 'templates_extra', 'templates.txt')))

    def test_skeleton_option(self):
        self.assertEquals(self.role_skeleton_path, context.CLIARGS['role_skeleton'], msg='Skeleton path was not parsed properly from the command line')


@pytest.fixture()
def collection_skeleton(request):
    name, skeleton_path = request.param

    galaxy_args = ['ansible-galaxy', 'collection', 'init', '-c']

    if skeleton_path is not None:
        galaxy_args += ['--collection-skeleton', skeleton_path]

    test_dir = tempfile.mkdtemp()
    if not os.path.isdir(test_dir):
        os.makedirs(test_dir)
    galaxy_args += ['--init-path', test_dir, name]

    gc = GalaxyCLI(args=galaxy_args)
    gc.run()

    namespace_name, collection_name = name.split('.', 1)
    collection_dir = os.path.join(test_dir, namespace_name, collection_name)
    yield collection_dir

    if os.path.isdir(test_dir):
        shutil.rmtree(test_dir)


@pytest.mark.parametrize('collection_skeleton', [
    ('ansible_test.my_collection', None),
], indirect=True)
def test_collection_default(collection_skeleton):
    meta_path = os.path.join(collection_skeleton, 'galaxy.yml')
    assert os.path.exists(meta_path)

    with open(meta_path, 'r') as galaxy_meta:
        metadata = yaml.safe_load(galaxy_meta)

    for item in ['namespace', 'name', 'version', 'authors', 'description', 'license', 'tags', 'dependencies',
                 'repository', 'documentation', 'homepage', 'issues']:
        assert item in metadata, 'unable to find {0}'.format(item)

    assert metadata.get('namespace', '') == 'ansible_test'
    assert metadata.get('name', '') == 'my_collection'
    assert metadata.get('authors', []) == ['your name <example@domain.com>']
    assert metadata.get('description', '') == 'your description'
    assert metadata.get('license', '') == 'license (GPL-2.0-or-later, MIT, etc)'
    assert metadata.get('tags', None) == []
    assert metadata.get('dependencies', None) == {}
    assert metadata.get('documentation', '') == 'http://docs.example.com'
    assert metadata.get('repository', '') == 'http://example.com/repository'
    assert metadata.get('homepage', '') == 'http://example.com'
    assert metadata.get('issues', '') == 'http://example.com/issue/tracker'

    for d in ['docs', 'plugins', 'roles']:
        assert os.path.isdir(os.path.join(collection_skeleton, d)), \
            "Expected collection subdirectory {0} doesn't exist".format(d)


@pytest.mark.parametrize('collection_skeleton', [
    ('ansible_test.delete_me_skeleton', os.path.join(os.path.split(__file__)[0], 'test_data', 'collection_skeleton')),
], indirect=True)
def test_collection_skeleton(collection_skeleton):
    meta_path = os.path.join(collection_skeleton, 'galaxy.yml')
    assert os.path.exists(meta_path)

    with open(meta_path, 'r') as galaxy_meta:
        metadata = yaml.safe_load(galaxy_meta)

    for item in ['namespace', 'name', 'version', 'authors']:
        assert item in metadata, 'unable to find {0}'.format(item)

    assert metadata.get('namespace', '') == 'ansible_test'
    assert metadata.get('name', '') == 'delete_me_skeleton'
    assert metadata.get('authors', []) == ['Ansible Cow <acow@bovineuniversity.edu>',
                                           'Tu Cow <tucow@bovineuniversity.edu>']
    assert metadata.get('version', '') == '0.1.0'

    assert os.path.exists(os.path.join(collection_skeleton, 'README.md'))

    # Test empty directories exist and are empty
    for empty_dir in ['plugins/action', 'plugins/filter', 'plugins/inventory', 'plugins/lookup',
                      'plugins/module_utils', 'plugins/modules']:

        assert os.path.isdir(os.path.join(collection_skeleton, empty_dir))
        assert os.listdir(os.path.join(collection_skeleton, empty_dir)) == []

    # Test files that don't end with .j2 were not templated
    doc_file = os.path.join(collection_skeleton, 'docs', 'My Collection.md')
    assert os.path.exists(doc_file)
    with open(doc_file, 'r') as f:
        doc_contents = f.read()
    assert doc_contents.strip() == 'Welcome to my test collection doc for {{ namespace }}.'

    # Test files that end with .j2 but are in the templates directory were not templated
    for template_dir in ['playbooks/templates', 'playbooks/templates/subfolder',
                         'roles/common/templates', 'roles/common/templates/subfolder']:
        test_conf_j2 = os.path.join(collection_skeleton, template_dir, 'test.conf.j2')
        assert os.path.exists(test_conf_j2)

        with open(test_conf_j2, 'r') as f:
            contents = f.read()
        expected_contents = '[defaults]\ntest_key = {{ test_variable }}'

        assert expected_contents == contents.strip()


@pytest.fixture()
def collection_build(collection_skeleton, reset_cli_args):
    output_dir = tempfile.mkdtemp()
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)

    # Because we call GalaxyCLI in collection_skeleton we need to reset the singleton back to None so it uses the new
    # args, we reset the original args once it is done.
    orig_cli_args = co.GlobalCLIArgs._Singleton__instance
    try:
        co.GlobalCLIArgs._Singleton__instance = None
        galaxy_args = ['ansible-galaxy', 'collection', 'build', collection_skeleton, '--output-path', output_dir]
        gc = GalaxyCLI(args=galaxy_args)
        gc.run()

        yield output_dir
    finally:
        co.GlobalCLIArgs._Singleton__instance = orig_cli_args

    if os.path.isdir(output_dir):
        shutil.rmtree(output_dir)


def test_invalid_skeleton_path():
    expected = "- the skeleton path '/fake/path' does not exist, cannot init collection"
    with pytest.raises(AnsibleError, match=expected):
        gc = GalaxyCLI(args=['ansible-galaxy', 'collection', 'init', 'my.collection', '--collection-skeleton',
                             '/fake/path'])
        gc.run()


@pytest.mark.parametrize("name", ["invalid", "hypen-ns.collection", "ns.hyphen-collection", "ns.collection.weird"])
def test_invalid_collection_name(name):
    expected = "Invalid collection name, must be in the format <namespace>.<collection>"
    with pytest.raises(AnsibleError, match=expected):
        gc = GalaxyCLI(args=['ansible-galaxy', 'collection', 'init', name])
        gc.run()


@pytest.mark.parametrize('collection_skeleton', [
    ('ansible_test.build_collection', None),
], indirect=True)
def test_collection_build(collection_build):
    tar_path = os.path.join(collection_build, 'ansible_test-build_collection-1.0.0.tar.gz')
    assert os.path.exists(tar_path)
    assert tarfile.is_tarfile(tar_path)

    tar = tarfile.open(tar_path)
    try:
        tar_members = tar.getmembers()

        assert len(tar_members) == 6
        assert tar_members[0].name == 'MANIFEST.json'
        assert tar_members[1].name == 'FILES.json'
        assert tar_members[2].name == 'roles'
        assert tar_members[3].name == 'docs'
        assert tar_members[4].name == 'plugins'
        assert tar_members[5].name == 'plugins/README.md'

        # Verify the uid and gid is 0 and the correct perms are set
        for member in tar_members:
            assert member.gid == 0
            assert member.gname == ''
            assert member.uid == 0
            assert member.uname == ''
            if member.isdir():
                assert member.mode == 0o0755
            else:
                assert member.mode == 0o0644

        manifest_file = tar.extractfile(tar_members[0])
        try:
            manifest = json.loads(manifest_file.read())
        finally:
            manifest_file.close()

        assert sorted(list(manifest.keys())) == ['collection_info', 'file_manifest_file', 'format']
        coll_info = manifest['collection_info']
        file_manifest = manifest['file_manifest_file']
        assert manifest['format'] == 1

        assert sorted(list(coll_info.keys())) == [
            'authors', 'dependencies', 'description', 'documentation', 'homepage', 'issues', 'license',
            'license_file', 'name', 'namespace', 'readme', 'repository', 'tags', 'version'
        ]

        assert coll_info['namespace'] == 'ansible_test'
        assert coll_info['name'] == 'build_collection'
        assert coll_info['version'] == '1.0.0'
        assert coll_info['authors'] == ['your name <example@domain.com>']
        assert coll_info['readme'] == 'README.md'
        assert coll_info['tags'] == []
        assert coll_info['description'] == 'your description'
        assert coll_info['license'] == ['license (GPL-2.0-or-later, MIT, etc)']
        assert coll_info['license_file'] is None
        assert coll_info['dependencies'] == {}
        assert coll_info['repository'] == 'http://example.com/repository'
        assert coll_info['documentation'] == 'http://docs.example.com'
        assert coll_info['homepage'] == 'http://example.com'
        assert coll_info['issues'] == 'http://example.com/issue/tracker'

        assert sorted(list(file_manifest.keys())) == ['chksum_sha256', 'chksum_type', 'format', 'ftype', 'name']
        assert file_manifest['name'] == 'FILES.json'
        assert file_manifest['ftype'] == 'file'
        assert file_manifest['chksum_type'] == 'sha256'
        assert file_manifest['chksum_sha256'] is not None  # Order of keys makes it hard to verify the checksum
        assert file_manifest['format'] == 1

        files_file = tar.extractfile(tar_members[1])
        try:
            files = json.loads(files_file.read())
        finally:
            files_file.close()

        assert list(files.keys()) == ['files', 'format']
        assert len(files['files']) == 5
        assert files['format'] == 1

        for file_entry in files['files']:
            assert sorted(list(file_entry.keys())) == ['chksum_sha256', 'chksum_type', 'format', 'ftype', 'name']

        assert files['files'][0]['name'] == '.'
        assert files['files'][0]['ftype'] == 'dir'
        assert files['files'][0]['chksum_type'] is None
        assert files['files'][0]['chksum_sha256'] is None
        assert files['files'][0]['format'] == 1

        assert files['files'][1]['name'] == 'roles'
        assert files['files'][1]['ftype'] == 'dir'
        assert files['files'][1]['chksum_type'] is None
        assert files['files'][1]['chksum_sha256'] is None
        assert files['files'][1]['format'] == 1

        assert files['files'][2]['name'] == 'docs'
        assert files['files'][2]['ftype'] == 'dir'
        assert files['files'][2]['chksum_type'] is None
        assert files['files'][2]['chksum_sha256'] is None
        assert files['files'][2]['format'] == 1

        assert files['files'][3]['name'] == 'plugins'
        assert files['files'][3]['ftype'] == 'dir'
        assert files['files'][3]['chksum_type'] is None
        assert files['files'][3]['chksum_sha256'] is None
        assert files['files'][3]['format'] == 1

        assert files['files'][4]['name'] == 'plugins/README.md'
        assert files['files'][4]['ftype'] == 'file'
        assert files['files'][4]['chksum_type'] == 'sha256'
        assert files['files'][4]['chksum_sha256'] == '5be7ec7b71096d56e1cc48311b6a2266b77b5fdb9d1985b5bc625787b1e857c5'
        assert files['files'][4]['format'] == 1
    finally:
        tar.close()
