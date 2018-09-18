# Copyright: (c) 2018, Johannes Brunswicker <johannes.brunswicker@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


class ModuleDocFragment(object):
    DOCUMENTATION = """
options:
    utm_host:
        description:
          - The REST Endpoint of the Sophos UTM
        required: true
    utm_port:
        description:
            - the port of the rest interface
        default: 4444
    utm_token:
        description:
          - "The token used to identify at the REST-API. See U(https://www.sophos.com/en-us/medialibrary/\
            PDFs/documentation/UTMonAWS/Sophos-UTM-RESTful-API.pdf?la=en), Chapter 2.4.2"
        required: true
    utm_protocol:
        description:
          - The protocol of the REST Endpoint.
        choices:
          - https
          - http
        default: https
    validate_certs:
        description:
          - whether the rest interface's ssl certificate should be verified or not
        default: True
        type: bool
    state:
        description:
          - The desired state of the object
        choices:
          - present
          - absent
        default: present
"""
