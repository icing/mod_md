#!/usr/bin/env python

import os
import sys

def main(argv):
    if len(argv) > 2:
        f1 = open(argv[1], 'a+')
        f1.write('%s\n' % (argv))
        if 'MD_VERSION' in os.environ:
            f1.write('MD_VERSION=%s\n' % (os.environ['MD_VERSION']))
        if 'MD_STORE' in os.environ:
            f1.write('MD_STORE=%s\n' % (os.environ['MD_STORE']))
        if 'PATH' in os.environ:
            f1.write('PATH=%s\n' % (os.environ['PATH']))
        f1.close()
        sys.stderr.write("done, all fine.\n")
        sys.exit(0)
    else:
        sys.stderr.write("%s without arguments" % (argv[0]))
        sys.exit(7)
    
if __name__ == "__main__":
    main(sys.argv)


