from setuptools import setup, find_packages

setup(
    name='pebbles-provisioning_extensions',
    version='1.0',

    description='Provisioning extensions for Pebbles',

    author='Data Intensive Computing Group at CSC',
    author_email='notebooks-admin@postit.csc.fi',

    url='https://github.com/CSCfi/pebbles',

    classifiers=[
        'Development Status :: 3 - Alpha',
        'Programming Language :: Python',
        'Environment :: Console',
        'Operating System :: POSIX :: Linux',
    ],

    scripts=[],

    provides=[
        'pebbles.provisioning_extensions',
    ],

    packages=find_packages(),
    include_package_data=True,

    entry_points={
        'pebbles.drivers.provisioning': [
            'DummyDriver = pebbles.drivers.provisioning.dummy_driver:DummyDriver',
            'OpenStackDriver = pebbles.drivers.provisioning.openstack_driver:OpenStackDriver',
            'DockerDriver = pebbles.drivers.provisioning.docker_driver:DockerDriver',
            'OpenShiftDriver = pebbles.drivers.provisioning.openshift_driver:OpenShiftDriver',
        ],
    },

    zip_safe=False,
)
