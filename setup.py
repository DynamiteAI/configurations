from setuptools import setup

setup(
    name='dynamite-nsm-public-configurations',
    version='1.1',
    url='http://dynamite.ai',
    license='',
    author='Jamin Becker',
    author_email='jamin@dynamite.ai',
    install_requires=[
        'boto3',
        'tabulate'
    ],
    description='Deploy Dynamite NSM Configurations'
)
