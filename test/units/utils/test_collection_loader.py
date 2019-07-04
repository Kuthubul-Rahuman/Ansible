from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import sys


def test_import_from_collection(monkeypatch):
    collection_root = os.path.join(os.path.dirname(__file__), 'fixtures', 'collections')
    collection_path = os.path.join(collection_root, 'ansible_collections/my_namespace/my_collection/plugins/module_utils/my_util.py')

    # the trace we're expecting to be generated when running the code below:
    # answer = question()
    expected_trace_log = [
        (collection_path, 1, 'call'),
        (collection_path, 2, 'line'),
        (collection_path, 2, 'return'),
    ]

    # define the collection root before any ansible code has been loaded
    # otherwise config will have already been loaded and changing the environment will have no effect
    monkeypatch.setenv('ANSIBLE_COLLECTIONS_PATHS', collection_root)

    from ansible.utils.collection_loader import AnsibleCollectionLoader

    assert not any(obj for obj in sys.meta_path if isinstance(obj, AnsibleCollectionLoader))

    from ansible.plugins.loader import _configure_collection_loader
    _configure_collection_loader()  # currently redundant, the import above already calls this

    assert any(obj for obj in sys.meta_path if isinstance(obj, AnsibleCollectionLoader))

    try:
        from ansible_collections.my_namespace.my_collection.plugins.module_utils.my_util import question

        original_trace_function = sys.gettrace()
        trace_log = []

        if original_trace_function:
            # enable tracing while preserving the existing trace function (coverage)
            def my_trace_function(frame, event, arg):
                trace_log.append((frame.f_code.co_filename, frame.f_lineno, event))

                # the original trace function expects to have itself set as the trace function
                sys.settrace(original_trace_function)
                # call the original trace function
                original_trace_function(frame, event, arg)
                # restore our trace function
                sys.settrace(my_trace_function)

                return my_trace_function
        else:
            # no existing trace function, so our trace function is much simpler
            def my_trace_function(frame, event, arg):
                trace_log.append((frame.f_code.co_filename, frame.f_lineno, event))

                return my_trace_function

        sys.settrace(my_trace_function)

        try:
            # run a minimal amount of code while the trace is running
            # adding more code here, including use of a context manager, will add more to our trace
            answer = question()
        finally:
            sys.settrace(original_trace_function)
    finally:
        if isinstance(sys.meta_path[0], AnsibleCollectionLoader):
            sys.meta_path.pop(0)

    assert not any(obj for obj in sys.meta_path if isinstance(obj, AnsibleCollectionLoader))

    # verify that code loaded from a collection does not inherit __future__ statements from the collection loader
    if sys.version_info[0] == 2:
        # if the collection code inherits the division future feature from the collection loader this will fail
        assert answer == 1
    else:
        assert answer == 1.5

    # verify that the filename and line number reported by the trace is correct
    # this makes sure that collection loading preserves file paths and line numbers
    assert trace_log == expected_trace_log
