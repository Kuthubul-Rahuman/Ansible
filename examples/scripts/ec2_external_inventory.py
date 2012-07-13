#!/usr/bin/python -tt

'''
EC2 external inventory script
=================================

NOTE: This script assumes Ansible is being executed where the environment
variables needed for Boto have been set:
    export AWS_ACCESS_KEY_ID=''
    export AWS_SECRET_ACCESS_KEY=''
For more details, see: http://docs.pythonboto.org/en/latest/boto_config_tut.html




mdehaan
1:14 I'd break the get_instances_by_region function up so it calls a few smaller functions

1:18 each function having a comment is a good thing

1:19 parser script needs to support taking a hostname to get the variables, right?
1:22 pas256: read the source to the cobbler inventory script
1:22 it has two modes... list all my groups
1:22 and another is for this given host, what variables do I use
mdehaan
1:23 if you are not actually generating the file, and are using it as a param to -i, it will need to do both
mdehaan
1:23 API is not as friendly as YAML or JSON, but it is ok
1:23 I will not do YAML config files again if I can help it
pas256
1:26 Ooo I missed that functionality so `script --list hostname` returns just a JSON object with whatever variables that host has
1:26 very cool
1:26 I can add that
mdehaan
1:26 no
1:26 script --list is one way it is executed
1:26 script --host <hostname>, is the other, I believe
pas256
1:26 o ok
mdehaan
1:27 looks like the cobbler one needs fixing up
1:27 pilt [~pilt@h-60-43.a163.priv.bahnhof.se] entered the room.
mdehaan
1:27 sorry about that, clear no one is using it
pas256
1:27 the cobbler script doesn't care what the first arg is, only the count
1:27 lol yeah
mdehaan
1:27 I really kinda like the idea of just generating the inventory file
1:27 maybe it should just do that
1:27 faster, no need to cache
1:27 plus it's a nice record of exactly what it will use
pas256
1:27 but with EC2, it is always changing
1:28 at least for us it is
mdehaan
1:28 https://github.com/ansible/ansible/issues/560
mdehaan
1:29 pas256: yeah, true
mdehaan
1:29 either way
1:29 pilt left the room (quit: Client Quit).
mdehaan
1:29 you could still run it if you wanted to look
pas256
1:30 yep
mdehaan
1:31 so assuming there is a metadata way to get variables out of EC2 you could store them with the host
1:31 and let ansible see all of them or some of them
pas256
1:32 yeah the instance object has a lot of data in it, I am only grouping by what makes sense to group by
mdehaan
1:33 can you define your own namespaces for variables?   Maybe there could be an ansible one...
1:33 though there shouldn't be a lot of host specific variables really
1:33 group specific variables are nice to support though
1:33 I can see use in that
pas256
1:33 ec2_ everything?
mdehaan
1:33 webservers get fooserver=xyz.example.com
1:33 you need some way of doing stuff like that
1:34 I don't know EC2's API at all
1:34 or EC2, really
pas256
1:34 AWS in general is pretty sweet there is a lot to it
mdehaan
1:35 yeah, seems like you could spend a long time learning all their various services
1:35 it's kind of a specialization in itself
pas256
1:35 agreed

'''

import os
import argparse
import re
from time import time
from boto import ec2
import ConfigParser

try:
    import json
except ImportError:
    import simplejson as json


class Ec2Inventory(object):
    def __init__(self):
        ''' Main execution path '''
        
        # Inventory grouped by instance IDs, tags, security groups, regions,
        # and availability zones
        self.inventory = {}
        
        # Index of hostname (address) to instance ID
        self.index = {}
        
        # Read settings and parse CLI arguments
        self.read_settings()
        self.parse_cli_args()
        
        # Cache
        if self.args.refresh_cache:
            self.do_api_calls_update_cache()  
        elif not self.is_cache_valid():
            self.do_api_calls_update_cache()
        
        # Data to print
        if self.args.host:
            if len(self.index) == 0:
                # Need to load from cache
                self.load_index_from_cache()
            
            (region, instance_id) = self.index[self.args.host]
            instance = self.get_instance(region, instance_id)
            instance_vars = {}
            for key in vars(instance):
                key = self.to_safe(key)
                value = getattr(instance, key)
                
                # Handle multiple types
                if type(value) in [int, bool]:
                    instance_vars[key] = value
                elif type(value) in [str, unicode]:
                    instance_vars[key] = value.strip()
                elif type(value) == type(None):
                    instance_vars[key] = ''
                elif key == 'region':
                    instance_vars[key] = value.name
                elif key == 'tags':
                    for k, v in instance.tags.iteritems():
                        key = self.to_safe('tag_' + k)
                        instance_vars[key] = v
                else:
                    print key
                    print type(value)
                    print value
                    print "---"
                               
            data_to_print = self.json_format_dict(instance_vars, True)
        
        elif self.args.list:
            # Display list of instances for inventory
            if len(self.inventory) == 0:
                # Need to load from cache
                data_to_print = self.get_inventory_from_cache()
            else:
                data_to_print = self.json_format_dict(self.inventory, True)
            
            
        print data_to_print

        
        
    def is_cache_valid(self):
        ''' Determines if the cache files have expired, or if it is still valid '''

        if os.path.isfile(self.cache_path_cache):
            mod_time = os.path.getmtime(self.cache_path_cache)
            current_time = time()
            if (mod_time + self.cache_max_age) > current_time:
                if os.path.isfile(self.cache_path_index):

                    return True
        return False
        
        
    def read_settings(self):
        ''' Reads the settings from the ec2.ini file '''
        
        config = ConfigParser.SafeConfigParser()
        config.read('ec2.ini')
        
        # Regions
        self.regions = []
        configRegions = config.get('ec2', 'regions')
        if (configRegions == 'all'):
            for regionInfo in ec2.regions():
                self.regions.append(regionInfo.name)
        else:
            self.regions = configRegions.split(",")
        
        # Destination addresses
        self.destination_variable = config.get('ec2', 'destination_variable')
        self.vpc_destination_variable = config.get('ec2', 'vpc_destination_variable')

        # Cache related
        cache_path = config.get('ec2', 'cache_path')
        self.cache_path_cache = cache_path + "/ansible-ec2.cache"
        self.cache_path_index = cache_path + "/ansible-ec2.index"
        self.cache_max_age = config.getint('ec2', 'cache_max_age')
        
        
    def parse_cli_args(self):
        ''' Command line argument processing '''
        
        parser = argparse.ArgumentParser(description='Produce an Ansible Inventory file based on EC2')
        parser.add_argument('--list', action='store_true', default=True, 
                           help='List instances (default: True)')
        parser.add_argument('--host', action='store', 
                           help='Get all the variables about a specific instance')
        parser.add_argument('--refresh-cache', action='store_true', default=False, 
                           help='Force refresh of cache by making API requests to EC2 (default: False - use cache files)')
        self.args = parser.parse_args()
        
        
    def do_api_calls_update_cache(self):
        ''' Do API calls to each region, and save data in cache files '''
        
        for region in self.regions:
            self.get_instances_by_region(region)
        
        self.write_to_cache(self.inventory, self.cache_path_cache)
        self.write_to_cache(self.index, self.cache_path_index)


    def get_instances_by_region(self, region):
        ''' Makes an AWS EC2 API call to the list of instances in a particular
        region '''
        
        conn = ec2.connect_to_region(region)
        reservations = conn.get_all_instances()
        for reservation in reservations:
            for instance in reservation.instances:
                self.add_instance(instance, region)


    def get_instance(self, region, instance_id):
        ''' Gets details about a specific instance '''
        conn = ec2.connect_to_region(region)
        reservations = conn.get_all_instances([instance_id])
        for reservation in reservations:
            for instance in reservation.instances:
                return instance
            
        
    def add_instance(self, instance, region):
        ''' Adds an instance to the inventory and index, as long as it is addressable '''
        
        # Only want running instances
        if instance.state == 'terminated':
            return
        
        # Select the best destination address
        if instance.subnet_id:
            dest = getattr(instance, self.vpc_destination_variable)
        else:
            dest =  getattr(instance, self.destination_variable)

        if dest == None:
            # Skip instances we cannot address (e.g. private VPC subnet)
            return

        # Add to index
        self.index[dest] = [region, instance.id]

        # Inventory: Group by instance ID (always a group of 1)
        self.inventory[instance.id] = [dest]
        
        # Inventory: Group by region
        self.push(self.inventory, region, dest)
                        
        # Inventory: Group by availability zone
        self.push(self.inventory, instance.placement, dest)
        
        # Inventory: Group by security group
        for group in instance.groups:
            key = self.to_safe("security-group_" + group.name)
            self.push(self.inventory, key, dest)
                
        # Inventory: Group by tag keys
        for k, v in instance.tags.iteritems():
            key = self.to_safe("tag_" + k + "=" + v)
            self.push(self.inventory, key, dest)        
    
    
    def push(self, my_dict, key, element):
        ''' Pushed an element onto an array that may not have been defined in the dict '''
        
        if key in my_dict:
            my_dict[key].append(element);
        else:
            my_dict[key] = [element]        
    
    
    def get_inventory_from_cache(self):
        ''' Reads the inventory from the cache file and returns it as a JSON object '''

        cache = open(self.cache_path_cache, 'r')
        json_inventory = cache.read()
        return json_inventory


    def load_index_from_cache(self):
        ''' Reads the index from the cache file sets self.index '''

        cache = open(self.cache_path_index, 'r')
        json_index = cache.read()
        self.index = json.loads(json_index)
    
    
    def write_to_cache(self, data, filename):
        ''' Writes data in JSON format to a file '''
        
        json_data = self.json_format_dict(data, True)
        cache = open(filename, 'w')
        cache.write(json_data)
        cache.close()
        
        
    def to_safe(self, word):
        ''' Converts 'bad' characters in a string to underscores so they can be
        used as Ansible groups '''
        
        return re.sub("[^A-Za-z0-9\-]", "_", word)
        
        
    def json_format_dict(self, data, pretty=False):
        ''' Converts a dict to a JSON object and dumps it as a formatted
        string '''
        
        if pretty:
            return json.dumps(data, sort_keys=True, indent=2)
        else:
            return json.dumps(data)
        
    
# Run the script
Ec2Inventory()

