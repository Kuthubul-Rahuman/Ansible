#!/bin/sh

# Add valid uses of expanduser to this list
WHITELIST='cloud/lxc/lxc_container.py
cloud/rackspace/rax.py
cloud/rackspace/rax_files_objects.py
cloud/rackspace/rax_scaling_group.py
database/mongodb/mongodb_parameter.py
database/mongodb/mongodb_user.py
database/postgresql/postgresql_db.py
files/synchronize.py
source_control/git.py
system/puppet.py
utilities/logic/async_status.py
utilities/logic/async_wrapper.py
web_infrastructure/ansible_tower/tower_host.py
web_infrastructure/ansible_tower/tower_group.py
web_infrastructure/jenkins_plugin.py'

for FILE in $WHITELIST ; do
    GREP_FORMAT_WHITELIST="$GREP_FORMAT_WHITELIST -e $FILE"
done

# GREP_FORMAT_WHITELIST has been formatted so that wordsplitting is wanted.  Therefore no double quotes around the var
# shellcheck disable=SC2086
egrep -r 'expanduser' lib/ansible/modules | egrep -v $GREP_FORMAT_WHITELIST

if [ $? -ne 1 ]; then
    printf 'The module(s) listed above use expanduser.\n'
    printf 'This may indicate the module should be using an argpsec type="path" instead of type="str"\n'
    printf 'If this is a false positive, add to the whitelist in:\n'
    printf '  test/sanity/code-smell/use-argspec-type-path.sh\n'
    exit 1
fi
