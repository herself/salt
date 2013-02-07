'''
A state to manage the pf packet filter. It's written to be used mainly as 
a watcher for file.recurse or file.managed states. 

After applying new configuration, a timed at job is created which loads the
old configuration after 10 minutes. To prevent that, one must manually run
the pf.confirm_ok function from the pf module, either from the master or the
minion.

This serves a similar function as the iptables-apply script - prevents locking
oneself out from a given machine after tweaking the ruleset.

Some examples:
.. code-block:: yaml

    /etc/pf.conf.new:
      file.managed:
        - source: salt://files/pf_openbsd/{{ grains['nodename'] }}/pf.conf
        - user: root
        - group: wheel
        - file_mode: 440
      pf:
        - running
        - watch:
          - file: /etc/pf.conf.new

A more advanced configuration example, storing the files in a directory 
(for example when managing a lot of sourced anchors)
.. code-block:: yaml

    /etc/pf.conf.new:
      file.recurse:
        - source: salt://files/pf_openbsd/{{ grains['nodename'] }}
        - user: root
        - group: wheel
        - clean: True
        - file_mode: 440
        - dir_mode: 440
        - template: jinja
        - context:
          base_dir: /etc/pf.conf.new
      pf:
        - running
        - watch:
          - file: /etc/pf.conf.new
'''

# Import python libs
import logging
from salt import exceptions

log = logging.getLogger(__name__)

def __virtual__():
    '''
    Check for pfctl.
    '''
    return 'pf'
    if __salt__['cmd.has_exec']('pfctl'):
        return 'pf'
    return False


def running(name):
    '''
    Ensure the pf service is running.

    name
        The pf configuration location. This can be a file, or a directory
        that has pf.conf in it.
    '''
    ret = {'name': name, 'result': True, 'comment': '', 'changes': {}}

    #in case we got a folder, try to save the day looking for a
    #pf.conf file in it
    if __salt__['file.directory_exists'](name):
      name = '{0}/pf.conf'.format(name)
    if not __salt__['file.file_exists'](name):
      ret['result'] = False
      ret['comment'] = '{0} is not a file!'.format(name)
      return ret

    if __salt__['pf.status']:
        log.debug('Pf is running')
    else:
        log.debug('Pf is not running, enabling it')
        try: 
            __salt__['pf.enable']
        except exceptions.CommandExecutionError as e:
            ret['comment'] = str(e)
            ret['result'] = False
            return ret
    
    ret['comment'] = 'Pf is up and running'

    return ret

def mod_watch(name, good_rules='/etc/pf.conf'):
    '''
    The service watcher, called to invoke the watch command.

    name
        The temporary pf configuration location.  This can be a file, or a directory
        that has pf.conf in it.

    good_rules
        The place where good rules should be copied afer verification with pf.confirm_ok.
        This can be a file, or a directory that has pf.conf in it.
    '''

    result = True
    #in case we got a folder, try to save the day looking for a
    #pf.conf file in it
    if __salt__['file.directory_exists'](name):
      name = '{0}/pf.conf'.format(name)
    if not __salt__['file.file_exists'](name):
      ret['result'] = False
      ret['comment'] = '{0} is not a file!'.format(name)
      return ret

    try: 
        __salt__['pf.reload'](rules=name)
        comment = 'Pf restarted'

        __salt__['pf.safeguard'](good_rules=good_rules, delay='10 min')
        comment += ', SAFEGUARD ON - PLEASE RUN pf.confirm_ok TO SAVE CHANGES (10 min)!'

        print 'NAME: {0}'.format(name)
    except exceptions.CommandExecutionError as e:
        comment = str(e)
        result = False

    return {'name': name,
            'changes': {name: result},
            'result': result,
            'comment': comment
           }
