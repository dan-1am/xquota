#!/usr/bin/env python

from datetime import datetime,date,time,timedelta
import os
import logging #,logging.handlers
import unittest

import xquota as xq



def setUpModule():
    global log
    log = logging.getLogger()
    log.setLevel(logging.DEBUG)
    consolelog = logging.StreamHandler()
    fmt = logging.Formatter('%(levelname)s: %(message)s')
    consolelog.setFormatter(fmt)
    log.addHandler(consolelog)
    xq.log = log



class TestTools(unittest.TestCase):

    def test_savefile(self):
        path = "/tmp/~testing_savefile.tmp"
        text = "Test file content\nwith 3 lines\nend"
        xq.savefile(path, text)
        read = xq.loadfile(path)
        os.remove(path)
        self.assertEqual(text, read)



class TestProcess(unittest.TestCase):

    def test_psiterate(self):
        print("Testing...")
        count = 0
        for ps in xq.psiterate():
            count += 1
            if ps.name == 'login':
                break
        else:
            raise Exception('no login process found')
        self.assertTrue(count > 0)



class TestRulesList(unittest.TestCase):

    def rules(self, now):
        d10=timedelta(minutes=10)
        d30=timedelta(minutes=30)
        new = [xq.RuleInfo(*d) for d in (
            (now,30,now+d30+d10),
            (now+d30*2,20,now+d30*3),
            (now+d30*4,25,now+d30*5),
        )]
        rules = xq.RulesList()
        rules.update(new)
        return rules

    def test_time_to_text(self):
        now = datetime(2023,10,20,14,0,0)
        rules = self.rules(now)
        for r in rules.list:
            r.spent = r.add-5
        got = rules.time_to_text()
        need = """\
2023-10-20T14:00:00+30=25.00
2023-10-20T15:00:00+20=15.00
2023-10-20T16:00:00+25=20.00
"""
        self.assertEqual(got, need)
        rules2 = self.rules(now)
        rules2.time_from_text(got)
        for r in rules.list:
            self.assertEqual(r.spent, rules2.hash[r.id].spent)

    def test_get_active(self):
        now = datetime(2023,10,20,14,0,0)
        rules = self.rules(now)
        self.assertEqual( rules.active(now), rules.list[0] )
        self.assertEqual( rules.active(now+timedelta(minutes=41)), None )
        self.assertEqual( rules.active(now+timedelta(minutes=60)), rules.list[1] )
        self.assertEqual( rules.active(now+timedelta(hours=3)), None )



if __name__ == '__main__':
    unittest.main()
