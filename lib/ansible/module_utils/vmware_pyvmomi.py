#!/usr/bin/python

# -*- coding: utf-8 -*-
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

# TODO:
# Ability to set CPU/Memory reservations

try:
    import json
except ImportError:
    import simplejson as json

HAS_PYVMOMI = False
try:
    import pyVmomi
    from pyVmomi import vim
    from pyVim.connect import SmartConnect, Disconnect
    HAS_PYVMOMI = True
except ImportError:
    pass

import atexit
import ssl
import time
from pprint import pprint

from ansible.module_utils.urls import *


class PyVmomiHelper(object):

    def __init__(self, module):

        if not HAS_PYVMOMI:
            module.fail_json(msg='pyvmomi module required')

        self.module = module
        self.params = module.params
        self.si = None
        self.smartconnect()
        self.datacenter = None

    def smartconnect(self):
        kwargs = {'host': self.params['vcenter_hostname'],
                  'user': self.params['username'],
                  'pwd': self.params['password'],
                  'port': self.params['vcenter_port']}

        if hasattr(ssl, 'SSLContext'):
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            context.verify_mode = ssl.CERT_NONE
            kwargs['sslContext'] = context

        # CONNECT TO THE SERVER
        try:
            self.si = SmartConnect(**kwargs)
        except Exception:
            err = get_exception()
            self.module.fail_json(msg="Cannot connect to %s: %s" %
                             (kwargs['host'], err))
        atexit.register(Disconnect, self.si)
        self.content = self.si.RetrieveContent()

    def _build_folder_tree(self, folder, tree={}, treepath=None):

        tree = {'virtualmachines': [],
                        'subfolders': {},
                        'name': folder.name}

        children = None
        if hasattr(folder, 'childEntity'):
            children = folder.childEntity

        if children:
            for child in children:
                if child == folder or child in tree:
                    continue
                if type(child) == vim.Folder:
                    #ctree = self._build_folder_tree(child, tree={})
                    ctree = self._build_folder_tree(child)
                    tree['subfolders'][child] = dict.copy(ctree)
                elif type(child) == vim.VirtualMachine:
                    tree['virtualmachines'].append(child)
        else:
            if type(folder) == vim.VirtualMachine:
                return folder
        return tree


    def _build_folder_map(self, folder, vmap={}, inpath='/'):

        ''' Build a searchable index for vms+uuids+folders '''

        if type(folder) == tuple:
            folder = folder[1]

        if not 'names' in vmap:
            vmap['names'] = {}
        if not 'uuids' in vmap:
            vmap['uuids'] = {}
        if not 'paths' in vmap:
            vmap['paths'] = {}

        if inpath == '/':
            thispath = '/vm'
        else:
            thispath = os.path.join(inpath, folder['name'])

        for item in folder.items():
            k = item[0]
            v = item[1]
            if k == 'name':
                pass
            elif k == 'subfolders':
                for x in v.items():
                    vmap = self._build_folder_map(x, vmap=vmap, inpath=thispath)
            elif k == 'virtualmachines':
                for x in v:
                    if not x.config.name in vmap['names']:
                        vmap['names'][x.config.name] = []
                    vmap['names'][x.config.name].append(x.config.uuid)
                    vmap['uuids'][x.config.uuid] = x.config.name
                    if not thispath in vmap['paths']:
                        vmap['paths'][thispath] = []
                    vmap['paths'][thispath].append(x.config.uuid)

        return vmap

    def getfolders(self):

        if not self.datacenter:
            self.datacenter = get_obj(self.content, [vim.Datacenter], 
                                       self.params['esxi']['datacenter'])
        self.folders = self._build_folder_tree(self.datacenter.vmFolder)
        self.folder_map = self._build_folder_map(self.folders)
        #pprint(self.folder_map)
        #sys.exit(1)
        return (self.folders, self.folder_map)


    def getvm(self, name=None, uuid=None, folder=None, firstmatch=False):

        # https://www.vmware.com/support/developer/vc-sdk/visdk2xpubs/ReferenceGuide/vim.SearchIndex.html
        # self.si.content.searchIndex.FindByInventoryPath('DC1/vm/test_folder')

        vm = None
        folder_path = None

        if uuid:
            vm = self.si.content.searchIndex.FindByUuid(uuid=uuid, vmSearch=True)

        elif folder:

            matches = []
            folder_paths = []

            datacenter = None
            if 'esxi' in self.params:
                if 'datacenter' in self.params['esxi']:
                    datacenter = self.params['esxi']['datacenter']

            if datacenter:
                folder_paths.append('%s/vm/%s' % (datacenter, folder))
            else:
                # get a list of datacenters
                datacenters = get_all_objs(self.content, [vim.Datacenter])
                datacenters = [x.name for x in datacenters]
                for dc in datacenters:
                    folder_paths.append('%s/vm/%s' % (dc, folder))

            for folder_path in folder_paths:
                fObj = self.si.content.searchIndex.FindByInventoryPath(folder_path)
                for cObj in fObj.childEntity:
                    if not type(cObj) == vim.VirtualMachine:
                        continue
                    if cObj.name == name:
                        #vm = cObj
                        #break
                        matches.append(cObj)
            if len(matches) > 1 and not firstmatch:
                assert len(matches) <= 1, "more than 1 vm exists by the name %s in folder %s. Please specify a uuid, a datacenter or firstmatch=true" % name
            elif len(matches) > 0:
                vm = matches[0]
            #else:
            #import epdb; epdb.st()

        else:
            if firstmatch:
                vm = get_obj(self.content, [vim.VirtualMachine], name)
            else:
                matches = []
                vmList = get_all_objs(self.content, [vim.VirtualMachine])
                for thisvm in vmList:
                    if thisvm.config == None:
                        import epdb; epdb.st()
                    if thisvm.config.name == name:
                        matches.append(thisvm)
                # FIXME - fail this properly
                #import epdb; epdb.st()
                assert len(matches) <= 1, "more than 1 vm exists by the name %s. Please specify a folder, a uuid, or firstmatch=true" % name
                if matches:
                    vm = matches[0]

        return vm


    def set_powerstate(self, vm, state, force):
	"""
	Set the power status for a VM determined by the current and
	requested states. force is forceful
	"""
        facts = self.gather_facts(vm)
        expected_state = state.replace('_', '').lower()
        current_state = facts['hw_power_status'].lower()
        result = {}

	# Need Force
	if not force and current_state not in ['poweredon', 'poweredoff']:
	    return "VM is in %s power state. Force is required!" % current_state

	# State is already true
	if current_state == expected_state:
            result['changed'] = False
            result['failed'] = False

	else:

            task = None

            try:
                if expected_state == 'poweredoff':
                    task = vm.PowerOff()

                elif expected_state == 'poweredon':
                    task = vm.PowerOn()

                elif expected_state == 'restarted':
                    if current_state in ('poweredon', 'poweringon', 'resetting'):
                        task = vm.Reset()
                    else:
                        result = {'changed': False, 'failed': True, 
                                  'msg': "Cannot restart VM in the current state %s" % current_state}

            except Exception:
                result = {'changed': False, 'failed': True, 
                          'msg': get_exception()}

            if task:
                self.wait_for_task(task)
                if task.info.state == 'error':
                    result = {'changed': False, 'failed': True, 'msg': task.info.error.msg}
                else:
                    result = {'changed': True, 'failed': False}

        # need to get new metadata if changed
        if result['changed']:
            newvm = self.getvm(uuid=vm.config.uuid)
            facts = self.gather_facts(newvm)
            result['instance'] = facts
        return result


    def gather_facts(self, vm):

        ''' Gather facts from vim.VirtualMachine object. '''

        facts = {
            'module_hw': True,
            'hw_name': vm.config.name,
            'hw_power_status': vm.summary.runtime.powerState,
            'hw_guest_full_name':  vm.summary.guest.guestFullName,
            'hw_guest_id': vm.summary.guest.guestId,
            'hw_product_uuid': vm.config.uuid,
            'hw_processor_count': vm.config.hardware.numCPU,
            'hw_memtotal_mb': vm.config.hardware.memoryMB,
            'hw_interfaces':[],
            'ipv4': None,
            'ipv6': None,
        }

        netDict = {}
        for device in vm.guest.net:
            mac = device.macAddress
            ips = list(device.ipAddress)
            netDict[mac] = ips
        #facts['network'] = {}
        #facts['network']['ipaddress_v4'] = None
        #facts['network']['ipaddress_v6'] = None
        for k,v in netDict.iteritems():
            for ipaddress in v:
                if ipaddress:
                    if '::' in ipaddress:
                        facts['ipv6'] = ipaddress
                    else:
                        facts['ipv4'] = ipaddress

	for idx,entry in enumerate(vm.config.hardware.device):

	    if not hasattr(entry, 'macAddress'):
		continue

	    factname = 'hw_eth' + str(idx)
	    facts[factname] = {
		'addresstype': entry.addressType,
		'label': entry.deviceInfo.label,
		'macaddress': entry.macAddress,
		'ipaddresses': netDict.get(entry.macAddress, None),
		'macaddress_dash': entry.macAddress.replace(':', '-'),
		'summary': entry.deviceInfo.summary,
	    }
	    facts['hw_interfaces'].append('eth'+str(idx))

        #import epdb; epdb.st()
        return facts


    def remove_vm(self, vm):
        # https://www.vmware.com/support/developer/converter-sdk/conv60_apireference/vim.ManagedEntity.html#destroy
        task = vm.Destroy()
        self.wait_for_task(task)

        if task.info.state == 'error':
            return ({'changed': False, 'failed': True, 'msg': task.info.error.msg})
        else:
            return ({'changed': True, 'failed': False})
 

    def deploy_template(self, poweron=False, wait_for_ip=False):

        # https://github.com/vmware/pyvmomi-community-samples/blob/master/samples/clone_vm.py

        '''
        deploy_template(
        vsphere_client=viserver,
        esxi=esxi,
        resource_pool=resource_pool,
        guest=guest,
        template_src=template_src,
        module=module,
        cluster_name=cluster,
        snapshot_to_clone=snapshot_to_clone,
        power_on_after_clone=power_on_after_clone,
        vm_extra_config=vm_extra_config
        )
        '''

        # FIXME:
        #   - folders
        #   - clusters
        #   - resource pools
        #   - multiple templates by the same name

        datacenters = get_all_objs(self.content, [vim.Datacenter])
        datacenter = get_obj(self.content, [vim.Datacenter], 
                             self.params['esxi']['datacenter'])

        # folder is a required clone argument
        if len(datacenters) > 1:
            # FIXME: need to find the folder in the right DC.
            raise "multi-dc with folders is not yet implemented"
        else:    
            destfolder = get_obj(self.content, [vim.Folder], self.params['vm_folder'])

        datastore_name = self.params['vm_disk']['disk1']['datastore']
        datastore = get_obj(self.content, [vim.Datastore], datastore_name)


        # cluster or hostsystem ... ?
        #cluster = get_obj(self.content, [vim.ClusterComputeResource], self.params['esxi']['hostname'])
        hostsystem = get_obj(self.content, [vim.HostSystem], self.params['esxi']['hostname'])
        #import epdb; epdb.st()

        resource_pools = get_all_objs(self.content, [vim.ResourcePool])
        #import epdb; epdb.st()

        relospec = vim.vm.RelocateSpec()
        relospec.datastore = datastore

        # fixme ... use the pool from the cluster if given
        relospec.pool = resource_pools[0]
        relospec.host = hostsystem
        #import epdb; epdb.st()

        clonespec = vim.vm.CloneSpec()
        clonespec.location = relospec
        #clonespec.powerOn = power_on

        print "cloning VM..."
        template = get_obj(self.content, [vim.VirtualMachine], self.params['template_src'])
        task = template.Clone(folder=destfolder, name=self.params['guest'], spec=clonespec)
        self.wait_for_task(task)

        if task.info.state == 'error':
            return ({'changed': False, 'failed': True, 'msg': task.info.error.msg})
        else:

            #import epdb; epdb.st()
            vm = task.info.result

            #if wait_for_ip and not poweron:
            #    print "powering on the VM ..."
            #    self.set_powerstate(vm, 'poweredon')

            if wait_for_ip:
                print "powering on the VM ..."
                self.set_powerstate(vm, 'poweredon', force=False)
                print "waiting for IP ..."
                self.wait_for_vm_ip(vm)

            vm_facts = self.gather_facts(vm)
            #import epdb; epdb.st()
            return ({'changed': True, 'failed': False, 'instance': vm_facts})
        

    def wait_for_task(self, task):
        # https://www.vmware.com/support/developer/vc-sdk/visdk25pubs/ReferenceGuide/vim.Task.html
        # https://www.vmware.com/support/developer/vc-sdk/visdk25pubs/ReferenceGuide/vim.TaskInfo.html
        # https://github.com/virtdevninja/pyvmomi-community-samples/blob/master/samples/tools/tasks.py
        while task.info.state not in ['success', 'error']:
            print(task.info.state)
            time.sleep(1)

    def wait_for_vm_ip(self, vm, poll=100, sleep=5):            
        ips = None
        facts = {}
        thispoll = 0
        while not ips and thispoll <= poll:
            print "polling for IP"
            newvm = self.getvm(uuid=vm.config.uuid)
            facts = self.gather_facts(newvm)
            print "\t%s %s" % (facts['ipv4'], facts['ipv6'])
            if facts['ipv4'] or facts['ipv6']:
                ips = True
            else:
                time.sleep(sleep)
                thispoll += 1

        #import epdb; epdb.st()
        return facts


    def fetch_file_from_guest(self, vm, username, password, src, dest):

        ''' Use VMWare's filemanager api to fetch a file over http '''

        result = {'failed': False}

        tools_status = vm.guest.toolsStatus
        if (tools_status == 'toolsNotInstalled' or
                tools_status == 'toolsNotRunning'):
            result['failed'] = True
            result['msg'] = "VMwareTools is not installed or is not running in the guest"
            return result

        # https://github.com/vmware/pyvmomi/blob/master/docs/vim/vm/guest/NamePasswordAuthentication.rst
        creds = vim.vm.guest.NamePasswordAuthentication(
            username=username, password=password
        )

        # https://github.com/vmware/pyvmomi/blob/master/docs/vim/vm/guest/FileManager/FileTransferInformation.rst
        fti = self.content.guestOperationsManager.fileManager. \
                            InitiateFileTransferFromGuest(vm, creds, src)

        result['size'] = fti.size
        result['url'] = fti.url

        # Use module_utils to fetch the remote url returned from the api
        rsp, info = fetch_url(self.module, fti.url, use_proxy=False, 
                             force=True, last_mod_time=None, 
                             timeout=10, headers=None)

        # save all of the transfer data
        for k,v in info.iteritems():
            result[k] = v

        # exit early if xfer failed
        if info['status'] != 200:
            result['failed'] = True
            return result

        # attempt to read the content and write it
        try:
            with open(dest, 'wb') as f:
                f.write(rsp.read())        
        except Exception as e:
            result['failed'] = True
            result['msg'] = str(e)

        return result


    def push_file_to_guest(self, vm, username, password, src, dest, overwrite=True):

        ''' Use VMWare's filemanager api to push a file over http '''

        result = {'failed': False}

        tools_status = vm.guest.toolsStatus
        if (tools_status == 'toolsNotInstalled' or
                tools_status == 'toolsNotRunning'):
            result['failed'] = True
            result['msg'] = "VMwareTools is not installed or is not running in the guest"
            return result

        # https://github.com/vmware/pyvmomi/blob/master/docs/vim/vm/guest/NamePasswordAuthentication.rst
        creds = vim.vm.guest.NamePasswordAuthentication(
            username=username, password=password
        )

        # the api requires a filesize in bytes
        filesize = None
        fdata = None
        try:
            #filesize = os.path.getsize(src)
            filesize = os.stat(src).st_size
            fdata = None
            with open(src, 'rb') as f:
                fdata = f.read()
            result['local_filesize'] = filesize
        except Exception as e:
            result['failed'] = True
            result['msg'] = "Unable to read src file: %s" % str(e)
            return result

        # https://www.vmware.com/support/developer/converter-sdk/conv60_apireference/vim.vm.guest.FileManager.html#initiateFileTransferToGuest
        file_attribute = vim.vm.guest.FileManager.FileAttributes()
        url = self.content.guestOperationsManager.fileManager. \
                InitiateFileTransferToGuest(vm, creds, dest, file_attribute, 
                                            filesize, overwrite)

        # PUT the filedata to the url ...
        rsp, info = fetch_url(self.module, url, method="put", data=fdata,
                             use_proxy=False, force=True, last_mod_time=None, 
                             timeout=10, headers=None)

        result['msg'] = str(rsp.read())

        # save all of the transfer data
        for k,v in info.iteritems():
            result[k] = v

        return result


    def run_command_in_guest(self, vm, username, password, program_path, program_args, program_cwd, program_env):

        result = {'failed': False}

        tools_status = vm.guest.toolsStatus
        if (tools_status == 'toolsNotInstalled' or
                tools_status == 'toolsNotRunning'):
            result['failed'] = True
            result['msg'] = "VMwareTools is not installed or is not running in the guest"
            return result

        # https://github.com/vmware/pyvmomi/blob/master/docs/vim/vm/guest/NamePasswordAuthentication.rst
        creds = vim.vm.guest.NamePasswordAuthentication(
            username=username, password=password
        )

        res = None
        pdata = None
        try:
            # https://github.com/vmware/pyvmomi/blob/master/docs/vim/vm/guest/ProcessManager.rst
            pm = self.content.guestOperationsManager.processManager
            # https://www.vmware.com/support/developer/converter-sdk/conv51_apireference/vim.vm.guest.ProcessManager.ProgramSpec.html
            ps = vim.vm.guest.ProcessManager.ProgramSpec(
                #programPath=program,
                #arguments=args
                programPath=program_path,
                arguments=program_args,
                workingDirectory=program_cwd,
            )
            res = pm.StartProgramInGuest(vm, creds, ps)
            result['pid'] = res
            pdata = pm.ListProcessesInGuest(vm, creds, [res])

            # wait for pid to finish
            while not pdata[0].endTime:
                time.sleep(1)
                pdata = pm.ListProcessesInGuest(vm, creds, [res])
            result['owner'] = pdata[0].owner
            result['startTime'] = pdata[0].startTime.isoformat()
            result['endTime'] = pdata[0].endTime.isoformat()
            result['exitCode'] = pdata[0].exitCode
            if result['exitCode'] != 0:
                result['failed'] = True
                result['msg'] = "program exited non-zero"
            else:
                result['msg'] = "program completed successfully"

        except Exception as e:
            result['msg'] = str(e)
            result['failed'] = True

        return result


def get_obj(content, vimtype, name):
    """
    Return an object by name, if name is None the
    first found object is returned
    """
    obj = None
    container = content.viewManager.CreateContainerView(
        content.rootFolder, vimtype, True)
    for c in container.view:
        if name:
            if c.name == name:
                obj = c
                break
        else:
            obj = c
            break

    container.Destroy()
    return obj


def get_all_objs(content, vimtype):
    """
    Get all the vsphere objects associated with a given type
    """
    obj = []
    container = content.viewManager.CreateContainerView(content.rootFolder, vimtype, True)
    for c in container.view:
        obj.append(c)
    container.Destroy()
    return obj


def _build_folder_tree(nodes, parent):
    tree = {}

    for node in nodes:
        if node['parent'] == parent:
            tree[node['name']] = dict.copy(node)
            tree[node['name']]['subfolders'] = _build_folder_tree(nodes, node['id'])
            del tree[node['name']]['parent']

    return tree


def _find_path_in_tree(tree, path):
    for name, o in tree.iteritems():
        if name == path[0]:
            if len(path) == 1:
                return o
            else:
                return _find_path_in_tree(o['subfolders'], path[1:])

    return None


def _get_folderid_for_path(vsphere_client, datacenter, path):
    content = vsphere_client._retrieve_properties_traversal(property_names=['name', 'parent'], obj_type=MORTypes.Folder)
    if not content: return {}

    node_list = [
        {
            'id': o.Obj,
            'name': o.PropSet[0].Val,
            'parent': (o.PropSet[1].Val if len(o.PropSet) > 1 else None)
        } for o in content
    ]

    tree = _build_folder_tree(node_list, datacenter)
    tree = _find_path_in_tree(tree, ['vm'])['subfolders']
    folder = _find_path_in_tree(tree, path.split('/'))
    return folder['id'] if folder else None



