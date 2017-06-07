# test mod_md acme terms-of-service handling

import shutil
import subprocess
import sys
import time
import json

class TestUtil:

    _a2md_stdargs = []
    
    @classmethod
    def run( cls, args ) :
        print "execute: ", " ".join(args)
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (output, errput) = p.communicate()
        rv = p.wait()
        try:
            jout = json.loads(output)
        except:
            jout = None
        return { 
            "rv": rv, 
            "stdout": output, 
            "stderr": errput,
            "jout" : jout 
        }

    @classmethod
    def a2md_stdargs( cls, args ) :
        cls._a2md_stdargs = [] + args 

    @classmethod
    def a2md( cls, args ) :
        return cls.run( cls._a2md_stdargs + args )
