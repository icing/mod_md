# test mod_md acme terms-of-service handling

import shutil
import subprocess
import sys
import time

class BaseTest:

    def exec_sub(self, args):
        print "execute: ", " ".join(args)
        p = subprocess.Popen(args, stdout=subprocess.PIPE)
        (outdata, errdata) = p.communicate()
        assert p.wait() == 0
        print "result:  ", outdata
        return outdata

    def exec_sub_err(self, args, errCode):
        print "execute: ", " ".join(args)
        p = subprocess.Popen(args, stdout=subprocess.PIPE)
        (outdata, errdata) = p.communicate()
        assert p.wait() == errCode
        print "result:  (", errCode, ") ", outdata
        return outdata
