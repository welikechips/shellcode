#!/usr/bin/env python
import fileinput

# Does a list of files, and
# redirects STDOUT to the file in question
for line in fileinput.input('php-reverse-shell.php', inplace = 1): 
      print line.replace("127.0.0.1", "bar"),