# (c) 2012, Michael DeHaan <michael.dehaan@gmail.com>
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

import multiprocessing
import signal
import os
import pwd
import Queue
import random
import traceback
import tempfile
import time
import collections
import socket

import ansible.constants as C
import ansible.inventory
from ansible import utils
from ansible import errors
from ansible import module_common
import poller
import connection
from return_data import ReturnData
from ansible.callbacks import DefaultRunnerCallbacks, vv

HAS_ATFORK=True
try:
    from Crypto.Random import atfork
except ImportError:
    HAS_ATFORK=False

dirname = os.path.dirname(__file__)
action_plugins = utils.import_plugins(os.path.join(dirname, 'action_plugins'))

################################################

def _executor_hook(job_queue, result_queue):
    ''' callback used by multiprocessing pool '''

    # attempt workaround of https://github.com/newsapps/beeswithmachineguns/issues/17
    # this function also not present in CentOS 6
    if HAS_ATFORK:
        atfork()

    signal.signal(signal.SIGINT, signal.SIG_IGN)
    while not job_queue.empty():
        try:
            job = job_queue.get(block=False)
            runner, host = job
            result_queue.put(runner._executor(host))
        except Queue.Empty:
            pass
        except:
            traceback.print_exc()

class Runner(object):
    ''' core API interface to ansible '''

    # see bin/ansible for how this is used...

    def __init__(self,
        host_list=C.DEFAULT_HOST_LIST,      # ex: /etc/ansible/hosts, legacy usage
        module_path=C.DEFAULT_MODULE_PATH,  # ex: /usr/share/ansible
        module_name=C.DEFAULT_MODULE_NAME,  # ex: copy
        module_args=C.DEFAULT_MODULE_ARGS,  # ex: "src=/tmp/a dest=/tmp/b"
        forks=C.DEFAULT_FORKS,              # parallelism level
        timeout=C.DEFAULT_TIMEOUT,          # SSH timeout
        pattern=C.DEFAULT_PATTERN,          # which hosts?  ex: 'all', 'acme.example.org'
        remote_user=C.DEFAULT_REMOTE_USER,  # ex: 'username'
        remote_pass=C.DEFAULT_REMOTE_PASS,  # ex: 'password123' or None if using key
        remote_port=C.DEFAULT_REMOTE_PORT,  # if SSH on different ports
        private_key_file=C.DEFAULT_PRIVATE_KEY_FILE, # if not using keys/passwords
        sudo_pass=C.DEFAULT_SUDO_PASS,      # ex: 'password123' or None
        background=0,                       # async poll every X seconds, else 0 for non-async
        basedir=None,                       # directory of playbook, if applicable
        setup_cache=None,                   # used to share fact data w/ other tasks
        transport=C.DEFAULT_TRANSPORT,      # 'ssh', 'paramiko', 'local'
        conditional='True',                 # run only if this fact expression evals to true
        callbacks=None,                     # used for output
        sudo=False,                         # whether to run sudo or not
        sudo_user=C.DEFAULT_SUDO_USER,      # ex: 'root'
        module_vars=None,                   # a playbooks internals thing
        is_playbook=False,                  # running from playbook or not?
        inventory=None,                     # reference to Inventory object
        subset=None                         # subset pattern
        ):

        # storage & defaults
        self.setup_cache      = utils.default(setup_cache, lambda: collections.defaultdict(dict))
        self.basedir          = utils.default(basedir, lambda: os.getcwd())
        self.callbacks        = utils.default(callbacks, lambda: DefaultRunnerCallbacks())
        self.generated_jid    = str(random.randint(0, 999999999999))
        self.transport        = transport
        self.inventory        = utils.default(inventory, lambda: ansible.inventory.Inventory(host_list))

        self.module_vars      = utils.default(module_vars, lambda: {})
        self.sudo_user        = sudo_user
        self.connector        = connection.Connection(self)
        self.conditional      = utils.normalize_conditional(conditional)
        self.module_path      = module_path
        self.module_name      = module_name
        self.forks            = int(forks)
        self.pattern          = pattern
        self.module_args      = module_args
        self.timeout          = timeout
        self.remote_user      = remote_user
        self.remote_pass      = remote_pass
        self.remote_port      = remote_port
        self.private_key_file = private_key_file
        self.background       = background
        self.sudo             = sudo
        self.sudo_pass        = sudo_pass
        self.is_playbook      = is_playbook

        # misc housekeeping
        if subset and self.inventory._subset is None:
            # don't override subset when passed from playbook
            self.inventory.subset(subset)

        if self.transport == 'ssh' and remote_pass:
            raise errors.AnsibleError("SSH transport does not support passwords, only keys or agents")
        if self.transport == 'local':
            self.remote_user = pwd.getpwuid(os.geteuid())[0]

        # ensure we are using unique tmp paths
        random.seed()

        # instantiate plugin classes
        self.action_plugins = {}
        for (k,v) in action_plugins.iteritems():
            self.action_plugins[k] = v.ActionModule(self)

    # *****************************************************

    def _delete_remote_files(self, conn, files):
        ''' deletes one or more remote files '''

        if os.getenv("ANSIBLE_KEEP_REMOTE_FILES","0") == "1":
            # ability to turn off temp file deletion for debug purposes
            return

        if type(files) == str:
            files = [ files ]
        for filename in files:
            if filename.find('/tmp/') == -1:
                raise Exception("not going to happen")
            self._low_level_exec_command(conn, "rm -rf %s" % filename, None)

    # *****************************************************

    def _transfer_str(self, conn, tmp, name, data):
        ''' transfer string to remote file '''

        if type(data) == dict:
            data = utils.jsonify(data)

        afd, afile = tempfile.mkstemp()
        afo = os.fdopen(afd, 'w')
        afo.write(data.encode('utf8'))
        afo.flush()
        afo.close()

        remote = os.path.join(tmp, name)
        try:
            conn.put_file(afile, remote)
        finally:
            os.unlink(afile)
        return remote

    # *****************************************************

    def _execute_module(self, conn, tmp, module_name, args,
        async_jid=None, async_module=None, async_limit=None, inject=None):

        ''' runs a module that has already been transferred '''

        (remote_module_path, is_new_style) = self._copy_module(conn, tmp, module_name, args, inject)
        cmd = "chmod u+x %s" % remote_module_path
        if self.sudo and self.sudo_user != 'root':
            # deal with possible umask issues once sudo'ed to other user
            cmd = "chmod a+rx %s" % remote_module_path
        self._low_level_exec_command(conn, cmd, tmp)

        cmd = ""
        if not is_new_style:
            args = utils.template(self.basedir, args, inject)
            argsfile = self._transfer_str(conn, tmp, 'arguments', args)
            if async_jid is None:
                cmd = "%s %s" % (remote_module_path, argsfile)
            else:
                cmd = " ".join([str(x) for x in [remote_module_path, async_jid, async_limit, async_module, argsfile]])
        else:
            if async_jid is None:
                cmd = "%s" % (remote_module_path)
            else:
                cmd = " ".join([str(x) for x in [remote_module_path, async_jid, async_limit, async_module]])

        res = self._low_level_exec_command(conn, cmd, tmp, sudoable=True)
        return ReturnData(conn=conn, result=res)

    # *****************************************************

    def _executor(self, host):
        ''' handler for multiprocessing library '''

        try:
            exec_rc = self._executor_internal(host)
            if type(exec_rc) != ReturnData:
                raise Exception("unexpected return type: %s" % type(exec_rc))
            # redundant, right?
            if not exec_rc.comm_ok:
                self.callbacks.on_unreachable(host, exec_rc.result)
            return exec_rc
        except errors.AnsibleError, ae:
            msg = str(ae)
            self.callbacks.on_unreachable(host, msg)
            return ReturnData(host=host, comm_ok=False, result=dict(failed=True, msg=msg))
        except Exception:
            msg = traceback.format_exc()
            self.callbacks.on_unreachable(host, msg)
            return ReturnData(host=host, comm_ok=False, result=dict(failed=True, msg=msg))

    # *****************************************************

    def _executor_internal(self, host):
        ''' executes any module one or more times '''

        host_variables = self.inventory.get_variables(host)
        port = host_variables.get('ansible_ssh_port', self.remote_port)

        inject = {}
        inject.update(host_variables)
        inject.update(self.module_vars)
        inject.update(self.setup_cache[host])
        inject['hostvars'] = self.setup_cache
        inject['group_names'] = host_variables.get('group_names', [])
        inject['groups'] = self.inventory.groups_list()

        # allow with_items to work in playbooks...
        # apt and yum are converted into a single call, others run in a loop

        items = self.module_vars.get('items', [])
        if isinstance(items, basestring) and items.startswith("$"):
            items = utils.varLookup(items, inject)
        if type(items) != list:
            raise errors.AnsibleError("with_items only takes a list: %s" % items)

        if len(items) and self.module_name in [ 'apt', 'yum' ]:
            # hack for apt and soon yum, with_items maps back into a single module call
            inject['item'] = ",".join(items)
            items = []

        # logic to decide how to run things depends on whether with_items is used

        if len(items) == 0:
            return self._executor_internal_inner(host, self.module_name, self.module_args, inject, port)
        else:
            # executing using with_items, so make multiple calls
            # TODO: refactor
            aggregrate = {}
            all_comm_ok = True
            all_changed = False
            all_failed = False
            results = []
            for x in items:
                inject['item'] = x
                result = self._executor_internal_inner(host, self.module_name, self.module_args, inject, port)
                results.append(result.result)
                if result.comm_ok == False:
                    all_comm_ok = False
                    break
                for x in results:
                    if x.get('changed') == True:
                        all_changed = True
                    if (x.get('failed') == True) or (('rc' in x) and (x['rc'] != 0)):
                        all_failed = True
                        break
            msg = 'All items succeeded'
            if all_failed:
                msg = "One or more items failed."
            rd_result = dict(failed=all_failed, changed=all_changed, results=results, msg=msg)
            if not all_failed:
                del rd_result['failed']
            return ReturnData(host=host, comm_ok=all_comm_ok, result=rd_result)

    # *****************************************************

    def _executor_internal_inner(self, host, module_name, module_args, inject, port, is_chained=False):
        ''' decides how to invoke a module '''

        # special non-user/non-fact variables:
        # 'groups' variable is a list of host name in each group
        # 'hostvars' variable contains variables for each host name
        #  ... and is set elsewhere
        # 'inventory_hostname' is also set elsewhere
        inject['groups'] = self.inventory.groups_list()

        # allow module args to work as a dictionary
        # though it is usually a string
        new_args = ""
        if type(module_args) == dict:
            for (k,v) in module_args.iteritems():
                new_args = new_args + "%s='%s' " % (k,v)
            module_args = new_args

        conditional = utils.template(self.basedir, self.conditional, inject)
        if not utils.check_conditional(conditional):
            result = utils.jsonify(dict(skipped=True))
            self.callbacks.on_skipped(host, inject.get('item',None))
            return ReturnData(host=host, result=result)

        conn = None
        actual_host = host
        try:
            delegate_to = inject.get('delegate_to', None)
            alternative_host = inject.get('ansible_ssh_host', None)
            if delegate_to is not None:
                actual_host = delegate_to
            elif alternative_host is not None:
                actual_host = alternative_host
            conn = self.connector.connect(actual_host, port)
            if delegate_to is not None or alternative_host is not None:
                conn._delegate_for = host
        except errors.AnsibleConnectionFailed, e:
            result = dict(failed=True, msg="FAILED: %s" % str(e))
            return ReturnData(host=host, comm_ok=False, result=result)

        module_name = utils.template(self.basedir, module_name, inject)
        module_args = utils.template(self.basedir, module_args, inject)

        tmp = ''
        if self.module_name != 'raw':
            tmp = self._make_tmp_path(conn)
        result = None

        handler = self.action_plugins.get(module_name, None)
        if handler:
            result = handler.run(conn, tmp, module_name, module_args, inject)
        else:
            if self.background == 0:
                result = self.action_plugins['normal'].run(conn, tmp, module_name, module_args, inject)
            else:
                result = self.action_plugins['async'].run(conn, tmp, module_name, module_args, inject)

        if result.is_successful() and 'daisychain' in result.result:
            result2 = self._executor_internal_inner(host, result.result['daisychain'], result.result.get('daisychain_args', {}), inject, port, is_chained=True)

            changed = False
            if result.result.get('changed',False) or result2.result.get('changed',False):
                changed = True
            result.result.update(result2.result)
            result.result['changed'] = changed

            del result.result['daisychain']

        if self.module_name != 'raw':
            self._delete_remote_files(conn, tmp)
        conn.close()

        if not result.comm_ok:
            # connection or parsing errors...
            self.callbacks.on_unreachable(host, result.result)
        else:
            data = result.result
            if 'item' in inject:
                result.result['item'] = inject['item']

            result.result['invocation'] = dict(
                module_args=module_args,
                module_name=module_name
            )

            if is_chained:
                # no callbacks
                return result
            if 'skipped' in data:
                self.callbacks.on_skipped(host)
            elif not result.is_successful():
                ignore_errors = self.module_vars.get('ignore_errors', False)
                self.callbacks.on_failed(host, data, ignore_errors)
            else:
                self.callbacks.on_ok(host, data)
        return result

    # *****************************************************

    def _low_level_exec_command(self, conn, cmd, tmp, sudoable=False):
        ''' execute a command string over SSH, return the output '''

        sudo_user = self.sudo_user
        stdin, stdout, stderr = conn.exec_command(cmd, tmp, sudo_user, sudoable=sudoable)

        if type(stdout) != str:
            out = "\n".join(stdout.readlines())
        else:
            out = stdout

        if type(stderr) != str:
            err = "\n".join(stderr.readlines())
        else:
            err = stderr

        return out + err

    # *****************************************************

    def _remote_md5(self, conn, tmp, path):
        ''' takes a remote md5sum without requiring python, and returns 0 if no file '''

        test = "rc=0; [ -r \"%s\" ] || rc=2; [ -f \"%s\" ] || rc=1" % (path,path)
        md5s = [
            "(/usr/bin/md5sum %s 2>/dev/null)" % path,
            "(/sbin/md5sum -q %s 2>/dev/null)" % path,
            "(/usr/bin/digest -a md5 -v %s 2>/dev/null)" % path
        ]

        cmd = " || ".join(md5s)
        cmd = "%s; %s || (echo \"${rc}  %s\")" % (test, cmd, path)
        data = self._low_level_exec_command(conn, cmd, tmp, sudoable=False)
        data = utils.last_non_blank_line(data)
        return data.split()[0]

    # *****************************************************

    def _make_tmp_path(self, conn):
        ''' make and return a temporary path on a remote box '''

        basefile = 'ansible-%s-%s' % (time.time(), random.randint(0, 2**48))
        basetmp = os.path.join(C.DEFAULT_REMOTE_TMP, basefile)
        if self.remote_user == 'root':
            basetmp = os.path.join('/var/tmp', basefile)
        elif self.sudo and self.sudo_user != 'root':
            basetmp = os.path.join('/tmp', basefile)

        cmd = 'mkdir -p %s' % basetmp
        if self.remote_user != 'root':
            cmd += ' && chmod a+rx %s' % basetmp
        cmd += ' && echo %s' % basetmp

        result = self._low_level_exec_command(conn, cmd, None, sudoable=False)
        return utils.last_non_blank_line(result).strip() + '/'

    # *****************************************************

    def _copy_module(self, conn, tmp, module_name, module_args, inject):
        ''' transfer a module over SFTP, does not run it '''

        if module_name.startswith("/"):
            raise errors.AnsibleFileNotFound("%s is not a module" % module_name)

        # Search module path(s) for named module.
        for module_path in self.module_path.split(os.pathsep):
            in_path = os.path.expanduser(os.path.join(module_path, module_name))
            if os.path.exists(in_path):
                break
        else:
            raise errors.AnsibleFileNotFound("module %s not found in %s" % (module_name, self.module_path))

        out_path = os.path.join(tmp, module_name)

        module_data = ""
        is_new_style=False

        with open(in_path) as f:
            module_data = f.read()
            if module_common.REPLACER in module_data:
                is_new_style=True
            module_data = module_data.replace(module_common.REPLACER, module_common.MODULE_COMMON)
            encoded_args = "\"\"\"%s\"\"\"" % module_args.replace("\"","\\\"")
            module_data = module_data.replace(module_common.REPLACER_ARGS, encoded_args)

        # use the correct python interpreter for the host
        if 'ansible_python_interpreter' in inject:
            interpreter = inject['ansible_python_interpreter']
            module_lines = module_data.split('\n')
            if '#!' and 'python' in module_lines[0]:
                module_lines[0] = "#!%s" % interpreter
            module_data = "\n".join(module_lines)

        self._transfer_str(conn, tmp, module_name, module_data)
        return (out_path, is_new_style)

    # *****************************************************

    def _parallel_exec(self, hosts):
        ''' handles mulitprocessing when more than 1 fork is required '''

        job_queue = multiprocessing.Manager().Queue()
        [job_queue.put(i) for i in hosts]
        result_queue = multiprocessing.Manager().Queue()

        workers = []
        for i in range(self.forks):
            prc = multiprocessing.Process(target=_executor_hook,
                args=(job_queue, result_queue))
            prc.start()
            workers.append(prc)

        try:
            for worker in workers:
                worker.join()
        except KeyboardInterrupt:
            for worker in workers:
                worker.terminate()
                worker.join()

        results = []
        try:
            while not result_queue.empty():
                results.append(result_queue.get(block=False))
        except socket.error:
            raise errors.AnsibleError("<interrupted>")
        return results

    # *****************************************************

    def _partition_results(self, results):
        ''' seperate results by ones we contacted & ones we didn't '''

        if results is None:
            return None
        results2 = dict(contacted={}, dark={})

        for result in results:
            host = result.host
            if host is None:
                raise Exception("internal error, host not set")
            if result.communicated_ok():
                results2["contacted"][host] = result.result
            else:
                results2["dark"][host] = result.result

        # hosts which were contacted but never got a chance to return
        for host in self.inventory.list_hosts(self.pattern):
            if not (host in results2['dark'] or host in results2['contacted']):
                results2["dark"][host] = {}
        return results2

    # *****************************************************

    def run(self):
        ''' xfer & run module on all matched hosts '''

        # find hosts that match the pattern
        hosts = self.inventory.list_hosts(self.pattern)
        if len(hosts) == 0:
            self.callbacks.on_no_hosts()
            return dict(contacted={}, dark={})

        hosts = [ (self,x) for x in hosts ]
        results = None
        if self.forks > 1:
            results = self._parallel_exec(hosts)
        else:
            results = [ self._executor(h[1]) for h in hosts ]
        return self._partition_results(results)

    # *****************************************************

    def run_async(self, time_limit):
        ''' Run this module asynchronously and return a poller. '''

        self.background = time_limit
        results = self.run()
        return results, poller.AsyncPoller(results, self)
