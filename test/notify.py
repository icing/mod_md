#!/usr/bin/env python

import os
import sys

def main(argv):
    if len(argv) > 2:
        f1 = open(argv[1], 'w+')
        f1.write('%s' % (argv))
        f1.close()
        sys.exit(0)
    else:
        sys.stderr.write("%s without arguments" % (argv[0]))
        sys.exit(7)
    
if __name__ == "__main__":
    main(sys.argv)

