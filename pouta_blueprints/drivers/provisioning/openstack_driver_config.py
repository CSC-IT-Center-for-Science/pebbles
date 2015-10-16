CONFIG = {
    'schema': {
        'type': 'object',
        'title': 'Comment',
        'description': 'Description',
        'required': [
            'name',
        ],
        'properties': {
            'name': {
                'type': 'string'
            },
            'description': {
                'type': 'string'
            },
            'flavor': {
                'type': 'string',
                'title': 'Flavor',
                'enum': [
                ]
            },
            'image': {
                'type': 'string',
                'title': 'Image',
                'enum': [
                ]
            },
            'maximum_lifetime': {
                'type": "string',
                'title': 'Maximum life-time (days hours mins secs)',
                'default': '0d0h0m0s',
                'pattern': '^\d+d\d{1,2}h\d{1,2}m\d{1,2}s$',
                'validationMessage': 'Value should be in format -d-h-m-s'
            },
            'maximum_instances_per_user': {
                'type': 'integer',
                'title': 'Maximum instances per user',
                'default': 1,
            },
            'preallocated_credits': {
                'type': 'boolean',
                'title': 'Pre-allocate credits for the instance from the user quota',
                'default': False,
            },
            'cost_multiplier': {
                'type': 'number',
                'title': 'Cost multiplier (default 1.0)',
                'default': 1.0,
            },
            'userdata': {
                'type': 'text',
                'title': 'Customization script for instance after it is launched',
                'default': '',
            },
            'firewall_rules': {
                'type': 'array',
                'title': 'Frontend firewall rules',
                'items': {
                    'type': 'string',
                    'title': 'Rules',
                }
            },
            'allow_update_client_connectivity': {
                'type': 'boolean',
                'title': "Allow user to request instance firewall to allow access to user's IP address",
                'default': False,
            },
            'needs_ssh_keys': {
                'type': 'boolean',
                'title': "Needs ssh-keys to access",
                'default': True,
            },
        }
    },
    'form': [
        {
            'type': 'help',
            'helpvalue': '<h4>OpenStack Instance config</h4>'
        },
        'name',
        'description',
        'flavor',
        'image',
        'maximum_lifetime',
        'maximum_instances_per_user',
        'preallocated_credits',
        'cost_multiplier',
        {
            'key': 'userdata',
            'type': 'textarea',
            'title': 'Customization script for instance after it is launched'
        },
        'firewall_rules',
        'allow_update_client_connectivity',
    ],
    'model': {
        'name': 'os-machine',
        'description': 'openstack blueprint',
        'flavor': 'mini',
        'image': 'Ubuntu-14.04',
        'firewall_rules': ['tcp 22 22 192.168.1.0/24'],
        'needs_ssh_keys': True,
    }
}
