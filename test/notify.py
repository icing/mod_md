#!/usr/bin/env python

import os
import sys

def main(argv):
    sys.stderr.write("%s %s" % (argv[0], argv))
    sys.exit(7)
    
if __name__ == "__main__":
    main(sys.argv)

