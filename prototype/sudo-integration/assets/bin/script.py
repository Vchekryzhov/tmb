# PROTOTYPE target script for the explicit-interpreter case (throwaway):
# run as /usr/bin/python3 script.py <args>; deliberately NOT executable.
import os
import sys

print("SCRIPT pid=%d euid=%d executable=%s" % (os.getpid(), os.geteuid(), sys.executable))
for i, a in enumerate(sys.argv):
    print("argv[%d]=%r" % (i, a))
try:
    data = os.read(0, 1)
    print("stdin=%s" % ("EOF (closed/null)" if data == b"" else "DATA %r" % data))
except OSError as e:
    print("stdin=ERROR %s" % e)
