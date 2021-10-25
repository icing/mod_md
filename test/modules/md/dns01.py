#!/usr/bin/env python

import subprocess
import sys

curl = "curl"
challtestsrv = "localhost:8055"


def run(args):
    sys.stderr.write("run: %s\n" % (' '.join(args)))
    p = subprocess.Popen(args, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, errput = p.communicate(None)
    rv = p.wait()
    if rv != 0:
        sys.stderr.write(errput.decode())
    sys.stdout.write(output.decode())
    return rv


def teardown(domain):
    return run([curl, "-s", "-X", "POST",
                "-d", "{\"host\":\"_acme-challenge.%s.\"}" % domain,
                "%s/clear-txt" % challtestsrv])


def setup(domain, challenge):
    teardown(domain)
    return run([curl, "-s", "-X", "POST",
                "-d", "{\"host\":\"_acme-challenge.%s.\", \"value\":\"%s\"}" % (domain, challenge),
                "%s/set-txt" % challtestsrv])


def main(argv):
    if len(argv) > 1:
        if argv[1] == 'setup':
            if len(argv) != 4:
                sys.stderr.write("wrong number of arguments: dns01.py setup <domain> <challenge>")
                sys.exit(2)
            rv = setup(argv[2], argv[3])
        elif argv[1] == 'teardown':
            if len(argv) != 3:
                sys.stderr.write("wrong number of arguments: dns01.py teardown <domain>")
                sys.exit(1)
            rv = teardown(argv[2])
        else:
            sys.stderr.write("unknown option %s" % (argv[1]))
            rv = 2
    else:
        sys.stderr.write("dns01.py wrong number of arguments")
        rv = 2
    sys.exit(rv)
    

if __name__ == "__main__":
    main(sys.argv)
