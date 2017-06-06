# test mod_md acme terms-of-service handling

import shutil
import subprocess
import sys
import time

class BaseTest:

    def exec_sub(self, args):
        print "execute: ", " ".join(args)
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (outdata, errdata) = p.communicate()
        errCode = p.wait()
        if errCode != 0:
            print "error: ", errdata if errdata else "[no message]"
        print "result:  (", errCode, ")\n", outdata
        assert errCode == 0
        return outdata

    def exec_sub_err(self, args, expCode):
        print "execute: ", " ".join(args)
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (outdata, errdata) = p.communicate()
        errCode = p.wait()
        if errCode != 0:
            print "error: ", errdata if errdata else "[no message]"
        print "result:  (", errCode, ") ", outdata
        assert errCode == expCode
        return outdata
