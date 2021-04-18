#! /usr/bin/python3

import argparse
import sys
from ruamel import yaml
from random import randint

paths = {}
RegisterTemplate = ''
EnrollmentTemplate = ''
TLSEnrollmentTemplate = ''

DEBUG = False
def printDebug(s):
    if(DEBUG):
        print(s)
def raiseWhenDebug(e):
    if(DEBUG):
        raise e

def getOrDefault(pairs, key, defaultvalue):
    try:
        result = pairs[key]
    except Exception as _:
        result = defaultvalue
    return result

def parseRange(conf_range):
    return getOrDefault(conf_range, 0, None), getOrDefault(conf_range, 1, None)

# profile accepts items of 'CAServers' or items of 'CAIdentity' of a profile
def getMspDirPath(profile, typestr):
    typeprefix = {
        'CAAdmin': 'caadmin',
        'Identity': 'id',
        'TLS': 'tls',
    }
    rootprefix = paths['CAOutput']

    if(typestr == 'CAAdmin'):
        return (
            rootprefix + '/' +
            typeprefix[typestr] + '-' +
            profile['HostName'] + '-' + str(profile['Port'])
        )
    elif(typestr == 'Identity'):
        return (
            rootprefix + '/' +
            typeprefix[typestr] + '-' +
            profile['Name'] + '-' +
            profile['Server']['HostName'] + '-' + str(profile['Server']['Port'])
        )
    elif(typestr == 'TLS'):
        return (
            rootprefix + '/' +
            typeprefix[typestr] + '-' +
            profile['Name'] + '-' +
            profile['Server']['HostName'] + '-' + str(profile['Server']['Port'])
        )

# enroll cert for ca admin identity
# accept items in 'CAServers'
def enrollAdmin(caserver_profile, callback):
    printDebug('enter enrollAdmin')
    enrolled = getOrDefault(caserver_profile, 'Enrolled', False)
    if(enrolled == True):
        return
    mspdir_path = getOrDefault(caserver_profile, 'MSPDirPath', None)
    if(mspdir_path == None):
        mspdir_path = getMspDirPath(caserver_profile, 'CAAdmin')
        caserver_profile['MSPDirPath'] = mspdir_path
    callback(
        EnrollmentTemplate % (
            caserver_profile['CAAdminName'],
            caserver_profile['CAAdminSecret'],
            caserver_profile['HostName'],
            str(caserver_profile['Port']),
            mspdir_path
        )
    )

# register identity for one profile
# accepts an identity in an org
def register(profile, callback, **kwargs):
    printDebug('enter register')
    # no type specified, skip
    try:
        typestr = profile['Type']
    except Exception as _:
        raise Exception('Register aborted as fail to get type.')
    def registerOneIdentity(identityprofile):
        try:
            # if register already finish, skip
            registered = getOrDefault(identityprofile, 'Registered', False)
            # raise new exception to finish this part
            if(registered == True):
                return
            # if caserver enrollment not done yet, do it
            orgcaserver = identityprofile['Server']
            if(getOrDefault(orgcaserver, 'Enrolled', False) != True):
                enrollAdmin(orgcaserver, callback)
            # generate command, dump with callback, mark registered
            callback(
                RegisterTemplate % (
                    identityprofile['Name'],
                    identityprofile['Secret'],
                    orgcaserver['HostName'],
                    str(orgcaserver['Port']),
                    orgcaserver['MSPDirPath'],
                    typestr,
                )
            )
            identityprofile['Registered'] = True
        except Exception as e:
            raiseWhenDebug(e)
    
    identities = getOrDefault(profile, 'CAIdentity', None)
    if(identities == None):
        # raise Exception('Register aborted as fail to get identity profiles.')
        return
    orgprofile =  getOrDefault(identities, 'OrgCA', None)
    tlsprofile = getOrDefault(identities, 'TLSCA', None)
    if(orgprofile != None):
        registerOneIdentity(orgprofile)
    if(tlsprofile != None):
        registerOneIdentity(tlsprofile)

# enroll certs for one profile
def enroll(profile, callback):
    printDebug('enter enroll')
    register(profile, callback)
    def enrollOneIdentity(identityprofile, is_tls):
        try:
            enrolled = getOrDefault(identityprofile, 'Enrolled', False)
            registered = getOrDefault(identityprofile, 'Registered', False)
            if(enrolled == True):
                return
            if(registered == False):
                register(profile, callback)
            orgcaserver = identityprofile['Server']
            mspdir_path = getOrDefault(identityprofile, 'MSPDirPath', None)
            if(mspdir_path == None):
                if(is_tls):
                    mspdir_path = getMspDirPath(identityprofile, 'TLS')
                else:
                    mspdir_path = getMspDirPath(identityprofile, 'Identity')
                identityprofile['MSPDirPath'] = mspdir_path
            callback(
                'rm -r ' +
                mspdir_path
            )
            if(is_tls):
                # enroll, copy config.yaml, rename files
                callback(
                    TLSEnrollmentTemplate % (
                        identityprofile['Name'],
                        identityprofile['Secret'],
                        orgcaserver['HostName'],
                        orgcaserver['Port'],
                        mspdir_path,
                        # csr.hosts
                        profile['HostName'],
                        identityprofile['Name']
                    )
                )
                # rename filenames to format
                callback(
                    'mv ' +
                    mspdir_path + '/keystore/* ' +
                    mspdir_path + '/keystore/cert.private '
                )
                callback(
                    'mv ' +
                    mspdir_path + '/tlscacerts/* ' +
                    mspdir_path + '/tlscacerts/tlscacert.pem '
                )
            else:
                # enroll, copy config.yaml, rename files
                callback(
                    EnrollmentTemplate % (
                        identityprofile['Name'],
                        identityprofile['Secret'],
                        orgcaserver['HostName'],
                        orgcaserver['Port'],
                        mspdir_path,
                    )
                )
                callback(
                    'cp ' +
                    paths['config.yaml'] + ' ' +
                    mspdir_path
                )
                # rename filenames to format
                callback(
                    'mv ' +
                    mspdir_path + '/cacerts/* ' +
                    mspdir_path + '/cacerts/cacert.pem '
                )
                callback(
                    'mv ' +
                    mspdir_path + '/keystore/* ' +
                    mspdir_path + '/keystore/cert.private '
                )
        except Exception as e:
            raiseWhenDebug(e)

    identities = getOrDefault(profile, 'CAIdentity', None)
    if(identities == None):
        # raise Exception('Enrollment aborted as fail to get identity profiles.')
        return
    orgprofile =  getOrDefault(identities, 'OrgCA', None)
    tlsprofile = getOrDefault(identities, 'TLSCA', None)
    if(orgprofile != None):
        enrollOneIdentity(orgprofile, False)
    if(tlsprofile != None):
        enrollOneIdentity(tlsprofile, True)

def applyConfig2Template(config, template):
    for k in config:
        if(getOrDefault(template, k, None) == None):
            template[k] = config[k]
            continue
        if(isinstance(config[k], type(config))):
            applyConfig2Template(config[k], template[k])
        template[k] = config[k]

# init a peer with profile
def initPeer(profile, callback):
    printDebug('')
    enroll(profile, callback)
    # get path on target machine
    targetpath = profile['Path'].replace(' ','')
    if(targetpath[-1] == '/'):
        targetpath = targetpath[:-1]
    # get folder name and create path to the folder on current machine
    folder = targetpath.split('/')[-1]
    folderpath = paths['NodeOutput'] + '/' + folder

    # make the folder, clean before make
    callback(
        'rm -r ' +
        folderpath
    )
    callback(
        'mkdir -p ' +
        folderpath
    )
    # binary file, mspdir, tlsmspdir
    callback(
        'cp -r ' +
        paths['peer'] + ' ' +
        folderpath
    )
    callback(
        'cp -r ' +
        profile['CAIdentity']['OrgCA']['MSPDirPath'] + ' ' +
        folderpath + '/msp '
    )
    tlsmspdirpath = getOrDefault(
        getOrDefault(profile['CAIdentity'], 'TLSCA', None),
        'MSPDirPath',
        None
    )
    if(tlsmspdirpath != None):
        callback(
            'cp -r ' +
            tlsmspdirpath + ' ' +
            folderpath + '/tlsmsp '
        )
    # create config file from profile, write to <folder>
    with open(paths['core.yaml']) as f:
        config_template = yaml.load(f.read(), Loader=yaml.RoundTripLoader)
    peerconfig = getOrDefault(profile, 'PeerConfig', None)
    if(peerconfig != None):
        applyConfig2Template(peerconfig, config_template)
    # write to a exist path, then move
    temp_config_filepath = (
        paths['TempOutput'] + '/' +
        str(randint(1, 1000000000000000)) +
        'core.yaml'
    )
    with open(temp_config_filepath, 'w') as f:
        f.write(yaml.dump(config_template, Dumper=yaml.RoundTripDumper, indent=4))
    callback(
        'mv ' +
        temp_config_filepath + ' ' +
        folderpath + '/core.yaml'
    )

    # compress and clean
    callback(
        'tar -zcvf ' +
        folder + '.tar.gz ' +
        folderpath
    )
    callback(
        'rm -r ' +
        folderpath
    )

# init a orderer with profile
def initOrderer(profile, callback):
    enroll(profile, callback)
    # get path on target machine
    targetpath = profile['Path'].replace(' ','')
    if(targetpath[-1] == '/'):
        targetpath = targetpath[:-1]
    # get folder name and create path to the folder on current machine
    folder = targetpath.split('/')[-1]
    folderpath = paths['NodeOutput'] + '/' + folder

    # make the folder, clean before make
    callback(
        'rm -r ' +
        folderpath
    )
    callback(
        'mkdir -p ' +
        folderpath
    )
    # binary file, mspdir, tlsmspdir
    callback(
        'cp -r ' +
        paths['orderer'] + ' ' +
        folderpath
    )
    callback(
        'cp -r ' +
        profile['CAIdentity']['OrgCA']['MSPDirPath'] + ' ' +
        folderpath + '/msp '
    )
    tlsmspdirpath = getOrDefault(
        getOrDefault(profile['CAIdentity'], 'TLSCA', None),
        'MSPDirPath',
        None
    )
    if(tlsmspdirpath != None):
        callback(
            'cp -r ' +
            tlsmspdirpath + ' ' +
            folderpath + '/tlsmsp '
        )
    # create config file from profile, write to <folder>
    with open(paths['orderer.yaml']) as f:
        config_template = yaml.load(f.read(), Loader=yaml.RoundTripLoader)
    ordererconfig = getOrDefault(profile, 'OrdererConfig', None)
    if(ordererconfig != None):
        applyConfig2Template(ordererconfig, config_template)
    # write to a exist path, then move
    temp_config_filepath = (
        paths['TempOutput'] + '/' +
        str(randint(1, 1000000000000000)) +
        'orderer.yaml'
    )
    with open(temp_config_filepath, 'w') as f:
        f.write(yaml.dump(config_template, Dumper=yaml.RoundTripDumper, indent=4))
    callback(
        'mv ' +
        temp_config_filepath + ' ' +
        folderpath + '/orderer.yaml'
    )
    # copy genesis block
    genesis_block_filename = getOrDefault(
        getOrDefault(
            config_template,
            'General',
            None
        ),
        'BootstrapFile',
        None
    )

    if(genesis_block_filename == None):
        genesis_block_filename = 'genesis.block'
        general_config = getOrDefault(
            config_template,
            'General',
            None
        )
        if(general_config == None):
            config_template['General'] = {}
            general_config = config_template['General']
        general_config['BootstrapFile'] = genesis_block_filename
    callback(
        'cp ' +
        paths['genesis.block'] + ' ' +
        folderpath + '/' +
        genesis_block_filename
    )
    # compress and clean
    callback(
        'tar -zcvf ' +
        folder + '.tar.gz ' +
        folderpath
    )
    callback(
        'rm -r ' +
        folderpath
    )

# traverse each profile in config file
# filter profiles with 'range' argument
# exec command on each profile
def traverse(config, args, callback):
    ranges = parseRange(args.range.split('.'))
    command = args.command
    for org in config['Orgs']:
        printDebug('in %s' % org)
        # filter exist and not passed
        if(
            ranges[0] != None and 
            ranges[0] != '' and 
            ranges[0] != org
        ):
            continue
        for identity in config['Orgs'][org]:
            printDebug('processing %s' % identity)
            # filter exist and not passed
            if(
                ranges[1] != None and
                ranges[1] != '' and
                ranges[1] != identity
            ):
                continue
            profile = config['Orgs'][org][identity]
            # not enabled, pass
            if(getOrDefault(profile, 'Enable', True) != True):
                continue
            if(command == commands['register']):
                register(profile, callback)
            elif(command == commands['enroll']):
                printDebug('enroll %s' % identity)
                enroll(profile, callback)
            elif(command == commands['initnode']):
                printDebug('initialize node %s' % identity)
                if(profile['Type'] == 'peer'):
                    initPeer(profile, callback)
                elif(profile['Type'] == 'orderer'):
                    initOrderer(profile, callback)
                # once init as a node finished, mark to disabled
                profile['Enable'] = False
            elif(command == commands['reset']):
                profile['Enable'] = True

commands = {
    'register':'register',
    'enroll':'enroll',
    'initnode': 'initnode',
    'reset': 'reset'
}
cliargs = {
    'command': {
        'short': 'c',
        'init': '',
        'help': 'command'
    },
    'configfile': {
        'short': 'C',
        'init': '',
        'help': 'configuration file'
    },
    'updatedconfigfile': {
        'short': 'U',
        'init': '',
        'help': 'where to dump update configuration'
    },
    'range': {
        'short': 'R',
        'init': '',
        'help': 'range of identity to be process'
    }
}

def parseArgs():
    # parse argument
    parser = argparse.ArgumentParser()
    for i in cliargs:
        parser.add_argument(
            '-'+cliargs[i]['short'],
            '--'+i,
            dest=i,
            default=cliargs[i]['init'],
            type=type(cliargs[i]['init']),
            help=cliargs[i]['help']
        )
    args = parser.parse_args()
    return args

def loadConfig(configfile):
    # load config
    with open(configfile) as f:
        config = yaml.load(f.read(), Loader=yaml.RoundTripLoader)
    return config

def writebackConfig(config, targetfile):
    with open(targetfile, 'w') as f:
        f.write(yaml.dump(config, Dumper=yaml.RoundTripDumper, indent=4))

def getWriteCallback(config, args):
    return print

def main():
    args = parseArgs()
    config = loadConfig(args.configfile)
    global paths
    paths = config['Paths']
    global RegisterTemplate
    RegisterTemplate = (
        paths['fabric-ca-client'] + 
        ' register ' +
        ' --id.name %s ' +
        ' --id.secret %s ' +
        ' -u http://%s:%s' +
        ' --mspdir %s ' +
        ' --id.type %s ' +
        ' --home ./ '
    )
    global EnrollmentTemplate
    EnrollmentTemplate = (
        paths['fabric-ca-client'] + 
        ' enroll ' +
        ' -u http://%s:%s@%s:%s' +
        ' --mspdir %s ' +
        ' --home ./ '
    )
    global TLSEnrollmentTemplate
    TLSEnrollmentTemplate = (
        paths['fabric-ca-client'] + 
        ' enroll ' +
        ' -u http://%s:%s@%s:%s' +
        ' --mspdir %s ' +
        ' --csr.hosts \'%s,%s\' ' +
        ' --enrollment.profile tls' +
        ' --home ./ '
    )
    write_callback = getWriteCallback(config, args)
    
    traverse(config, args, write_callback)

    try:
        writebackConfig(config, args.updatedconfigfile)
    except Exception as _:
        pass

if __name__ == '__main__':
    main()
