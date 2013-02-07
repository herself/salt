'''
Support for the PF packet filter
'''

# Import python libs
import os

# Import salt libs
from salt import utils, exceptions

def _pfctl_run(cmd, **kwargs):
    '''
    simple, throw an exception with the error message on an error return code.
    this function may be moved to the command module, spliced with
    'cmd.run_all', and used as an alternative to 'cmd.run_all'. Some
    commands don't return proper retcodes, so this can't replace 'cmd.run_all'.
    '''
    result = __salt__['cmd.run_all'](cmd, **kwargs)

    retcode = result['retcode']

    if retcode == 0:
        if len(result['stdout']) == 0:
            return 'OK'
        else:
            return result['stdout']
    else:
        raise exceptions.CommandExecutionError('Command returned stderr: {0}'.format(result['stderr']))

def _check_pf():
    utils.check_or_die('pfctl')

def disable():
    '''
    Disables PF on the given machine.
    '''
    _check_pf()

    cmd = 'pfctl -d'
    return _pfctl_run(cmd)

def enable(rules='/etc/pf.conf'):
    '''
    Enables and loads the given firewall rules.
    Will error out if the firewall is alreaddy enabled.
    '''
    _check_pf()

    cmd = 'pfctl -n -f {0}'.format(rules)
    _pfctl_run(cmd)

    cmd = 'pfctl -e -f {0}'.format(rules)
    return _pfctl_run(cmd)

def status():
    '''
    Returns the status of PF (enabled/disabled) on the given machine.
    '''
    _check_pf()

    stdout = _pfctl_run('pfctl -s info')
    if 'Status: Enabled' in stdout:
            return True
    else:
            return False

def reload(rules='/etc/pf.conf'):
    '''
    Reloads PF checking the syntax beforehand.
    '''
    _check_pf()

    cmd = 'pfctl -n -f {0}'.format(rules)
    _pfctl_run(cmd)

    cmd = 'pfctl -f {0}'.format(rules)
    return _pfctl_run(cmd)

def safeguard(good_rules='/etc/pf.conf', delay='5 min'):
    '''
    Create an at job that will load the given firewall rules in case of a
    problem with new ones.
    '''
    __salt__['at.atrm']('all', 'pf')
    __salt__['at.at']('now + {0}'.format(delay), 'pfctl -e -f {0}'.format(good_rules), tag='pf')
    #seems like at.at always returns non-parsable data
    return True

def confirm_ok(new_rules='/etc/pf.conf.new', good_rules='/etc/pf.conf'):
    '''
    Confirm the given rules are working, removing the safeguard job
    and moving the temporary ruleset to it's destination.

    Both new_rules and good_rules can be single files as well as directories.

    CLI Example::

        salt '*' pf.confirm_ok [new_rules=<file/directory>] [good_rules=<file/directory>]
        salt '*' pf.confirm_ok new_rules=/etc/pf_temp good_rules=/etc/pf
    '''

    
    if len(__salt__['at.atq'](tag='pf')['jobs']) == 0:
      return 'No pf at job found, not copying anything!'

    __salt__['at.atrm']('all', 'pf')

    if __salt__['file.directory_exists'](good_rules) or __salt__['file.file_exists'](good_rules):
      ret =  __salt__['cmd.retcode']('rm -rf {0}.bak; mv {0} {0}.bak'.format(good_rules))
      if ret != 0:
        return "mv failed"

    ret = __salt__['cmd.retcode']('cp -r {0} {1}'.format(new_rules, good_rules))
    if ret != 0:
        return "cp failed"

    #replace all occurences of the temporary directory with the base directory - this helps tremendously with includes
    ret = __salt__['cmd.run']('find {0} -type f -exec perl -i -pe "s/{1}/{2}/g" {{}} +'
    .format(good_rules, new_rules.replace('/', '\\/'), good_rules.replace('/', '\\/')))

    return True
