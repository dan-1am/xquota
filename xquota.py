#!/usr/bin/env python

__version__ = '1.12.01'
created = '2023.06.17'

import re
import sys
import os
from pathlib import Path
import subprocess
import pwd
from time import sleep
from datetime import datetime,date,time,timedelta
import logging,logging.handlers



appname = sys.argv[0].rpartition('/')[2]
conffile='/usr/local/etc/xquota.conf'
statefile='/var/tmp/xquota.state'
logfile='/var/log/xquota.log'

markerfile = Path("xquota.conf")
debug = markerfile.exists()

if debug:
    conffile = conffile.rpartition('/')[2]
    statefile = statefile.rpartition('/')[2]
    logfile = logfile.rpartition('/')[2]

savedelay = 30 if debug else 300
watchdelay = 5 if debug else 15



################ tools

def loadfile(path):
    try:
        with open(path) as f:
            data = f.read()
    except FileNotFoundError:
        return
    log.info(f'Loaded file {path}')
    return data


def savefile(path, data):
    log.info(f'Saving {path}')
    try:
        with open(path, 'w') as f:
            f.write(data)
    except OSError:
        log.error(f'unable to save file [{statefile}]')
    else:
        return True



################ logging

def startlog():
    global log
    global consolelog
    log = logging.getLogger()
    log.setLevel(logging.DEBUG)

    consolelog = logging.StreamHandler()
    fmt = logging.Formatter('%(levelname)s: %(message)s')
    consolelog.setFormatter(fmt)
    log.addHandler(consolelog)

    try:
        filelog = logging.handlers.RotatingFileHandler(logfile, maxBytes=pow(10,6), backupCount=1)
    except Exception:
        log.warning(f'Can not open log file [{logfile}]')
    else:
        fmt = logging.Formatter('%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        filelog.setFormatter(fmt)
        log.addHandler(filelog)


def daemonlog():
    if debug: return
    syslog = logging.handlers.SysLogHandler(address = '/dev/log')
    fmt = logging.Formatter(appname + ': %(levelname)s: %(message)s')
    syslog.setFormatter(fmt)
    syslog.setLevel(logging.ERROR)
    log.addHandler(syslog)
    log.removeHandler(consolelog)



################ os

def userid(name):
    return pwd.getpwnam(name).pw_uid

def gethomedir(uid):
    return pwd.getpwuid(uid).pw_dir



################ bash commands

def notifyuser(user, txt):
    uid = userid(user)      #todo: use uid instead of user
    env = {'DISPLAY':':0', 'HOME':gethomedir(uid)}
    for k in 'PATH',:
        env[k] = os.environ[k]
    # seteuid is not enough for notify-send, need fork+setuid
    try:
        if not os.fork():    # Child process
            log.debug(f'child uid={os.getpid()}')
            try:
                log.debug(f'switching to {uid=}')
                os.setuid(uid)
                subprocess.run(['notify-send', txt],env=env)
            except PermissionError:
                log.warning('need root to notify other users.')
            except FileNotFoundError:
                log.warning('notify-send not found, can not send warnings.')
            os._exit(0)
    except OSError:
        log.error('fork() failed, unable to notify user')



################ process list

def kill(pid):
    log.info(f'Killing {pid}')
    if not debug:
        os.kill(pid, 15)        #15=term


def psfullname(procdir):
    try:
        with open(procdir / 'cmdline') as f:
            args = f.read()
            return args.partition('\x00')[0]
    except OSError:
        return ''


class process:
    def __init__(self, procdir):
        self.procdir = procdir
        self.pid = int(procdir.name)
        self.fullname = psfullname(procdir)
        self.name = self.fullname.rpartition('/')[2]

    def uid(self):
        uid = getattr(self,'_uid',None)
        if uid != None:
            return uid
        try:
            with open(self.procdir / 'loginuid') as f:
                self._uid = int( f.read() )
                return self._uid
        except OSError:
            pass

    def exists(self):
        return self.procdir.exists()


def psiterate():
    for ps in Path('/proc').iterdir():
        if ps.name.isdigit() and ps.is_dir():
            yield process(ps)


def killall(pslist):
    for ps in pslist:
        try:
            kill(ps.pid)
        except ProcessLookupError:
            pass



################ date


datechars = set('0123456789.')
timechars = set('0123456789:')

def parsedate(txt, now=None):
    if not now:
        now = date.today()
    if txt.isdigit():
        if len(txt) <= 2:
            return date( now.year, now.month, int(txt) )
        if len(txt) == 4:
            return date( now.year, int(txt[:2]), int(txt[2:]) )
        if len(txt) == 6:
            return date( int(str(now.year)[0:2]+txt[:2]), int(txt[2:4]), int(txt[4:]) )
    elif set(txt) <= datechars:
        if len(txt) == 5:
            return date( now.year, int(txt[:2]), int(txt[3:]) )
        if len(txt) == 8:
            return date( int(str(now.year)[:2]+txt[:2]), int(txt[3:5]), int(txt[6:]) )
        if len(txt) == 10:
            return date( int(txt[:4]), int(txt[5:7]), int(txt[8:]) )



def parsetime(txt):
    if txt.isdigit():
        if len(txt) == 4:
            return time( int(txt[:2]), int(txt[2:]), 0 )
        if len(txt) == 6:
            return time( int(txt[:2]), int(txt[2:4]), int(txt[4:]) )
    elif set(txt) <= timechars:
        if len(txt) == 5:
            return time( int(txt[:2]), int(txt[3:]), 0 )
        if len(txt) == 8:
            return date( int(txt[:2]), int(txt[3:5]), int(txt[6:]) )



################ rules

class RuleInfo:
    def __init__(self, start, add, end, ruleid=None):
        self.start = start
        self.add = add
        self.end = end
        if ruleid is None:
            ruleid = f'{start.isoformat()}+{add}'
        self.id = ruleid
        self.spent = 0

    def spend(self,sec):
        global statechanged
        self.spent += sec/60
        statechanged = True

    def ended(self, now):
        return self.spent >= self.add or self.end > now

    def __repr__(self):
        start = self.start.strftime('%Y.%m.%d %H:%M')
        end = self.end.strftime('%Y.%m.%d %H:%M')
        return f'{start} - {end} +{self.spent}/{self.add}'



################ rules list

class RulesList:

    def __init__(self):
        self.list = []
        self.hash = {}
        self.changed = False
        self.lastsave = None
        self.lost = {}

    def add(self, rule):
        self.list.append(rule)
        self.hash[rule.id] = rule
        return self

    def sort(self):
        self.list.sort(key=lambda r: r.end)
        return self

    def update(self, newrules):
        for new in newrules:
            if old := self.hash.pop(new.id, None) :
                new.spent = old.spent
            elif time := self.lost.pop(new.id, None) :
                new.spent = time
        for old in self.hash.values():
            self.lost[old.id] = old.spent
        self.hash = {r.id: r for r in newrules}
        self.list = newrules
        self.sort()
        return self

    def active(self, time):
        for r in self.list:
            if time >= r.start and time < r.end:
                if r.spent < r.add:
                    return r
        return None

    def saved(self, now=None):
        if not now:
            now = datetime.now()
        self.changed = False
        self.lastsave = now

    def time_to_text(self):
        parts = []
        for r in self.list:
            parts.append(f'{r.id}={r.spent:.2f}\n')
        for k,v in self.lost:
            parts.append(f'{k}={v:.2f}\n')
        return ''.join(parts)

    def time_from_text(self, text):
        for line in text.splitlines():
            ruleid,equal,spent = line.partition('=')
            if equal:
                rule = self.hash.get(ruleid, None)
                if rule:
                    rule.spent = float(spent)
                else:
                    self.lost[ruleid] = spent

    def savetime(self, force=False):
        if not (force or self.changed):
            return
        now = datetime.now()
        if not force and self.lastsave and (now-self.lastsave).total_seconds() < savedelay:
            return
        if savefile(statefile, self.time_to_text()):
            self.saved(now)

    def loadtime(self):
        self.saved()
        text = loadfile(statefile)
        if text is None:
            return
        self.time_from_text(text)



################ parserules

users = {}


def parserules(txt):

    def users(*names):
        global users
        for name in names:
            users[ userid(name) ] = name

    def add(add, day=None):
        nonlocal totaladd
        if(not day or parsedate(day, datenow) == datenow):
            totaladd += add

    def addequal(n):
        nonlocal addparts
        addparts = n

    def rule(start, length, maxlen=0, day=None):
        nonlocal rules, totaladd, addparts
        if(day):
            day = parsedate(day, datenow)
            if day != datenow:
                return
        else:
            day = datenow
        left = length

        add = totaladd // addparts
        if addparts > 1:
            addparts -= 1
        if add:
            if -add >= left:
                totaladd += left
                return
            left += add
            totaladd -= add
            if add > 0:
                maxlen += add
        start = datetime.combine(day, parsetime(start))
        if maxlen:
            end = start + timedelta(minutes=maxlen)
        else:
            end = start + timedelta(minutes=left)
        rules.append( RuleInfo(start, left, end) )

    now = datetime.now()
    datenow = now.date()
    rules = []
    totaladd = 0
    addparts = 1
    try:
        exec(txt)
    except Exception:
        log.error('Error in configuration file')
        log.info('', exc_info=True)
        return
    if totaladd:
        log.info(f'Unused add time={totaladd}')
    return rules


def newrules(rules):
    new = parserules(rulestext)
    if new:
        rules.update(new)
    return rules


def displayrules(rules):
    active = rules.active(datetime.now())
    for r in rules.list:
        if r == active:
            print('> ', end='')
        print(r)



################ conf file

rulestext = ''


def confreload():
    global confloadedat,rulestext
    name = conffile
    try:
        with open(name) as f:
            txt = f.read()
    except OSError:
        log.error(f'unable to load configuration from [{name}]')
    else:
        if txt != rulestext:
            log.info(f'Configuration loaded from [{name}]')
            rulestext = txt
            return True



################ watch

def pscheck():
    found = []
    for ps in psiterate():
        if ps.name == 'X':
            uid = ps.uid()
            if uid in users:
                return True


def control():
    found = []
    for ps in psiterate():
        if ps.name == 'X':
            uid = ps.uid()
            if uid in users:
                found.append(ps)
                if not debug:
                    notifyuser(users[uid], 'Ограничение по времени, выход в консоль через 30 секунд.')
    if found:
        if debug:
            log.debug(f'simulate killing {found[0].pid} + {len(found)-1} other')
        else:
            sleep(60)
            killall(found)


def daemon():
    log.info('Daemon started.')
    now = datetime.now()
    lastrule = None
    rules = newrules( RulesList() )
    rules.loadtime()
    while True:
        last,now = now,datetime.now()
        if confreload() or last.day != now.day:
            lastrule = None
            newrules(rules)
        if not lastrule or lastrule.ended(now):
            lastrule = rules.active(now)
        if lastrule:
            if pscheck():
                dt = (now-last).total_seconds()
                lastrule.spend(dt)
        else:
            control()
        rules.savetime()
        sleep(watchdelay)



################ main

def showhelp():
    print('''\
Display current rules:
xquota

Run daemon as root:
xquota -d''')



def main():
    startlog()
#    asroot = os.getuid() == 0
    if len(sys.argv) > 1:
        if sys.argv[1] == '-d':
            if not debug:
                daemonlog()
            if not confreload(): return
            daemon()
        else:
            print('Wrong arguments.\n')
            showhelp()
            return
    else:
        if not confreload(): return
        rules = newrules( RulesList() )
        rules.loadtime()
        displayrules(rules)



if __name__ == '__main__':
    try:
        main()
    except Exception:
        log.critical('Exception in main', exc_info=True)
        sys.exit(1)
