import sys
import re
from string import split
from string import strip

def failure(pos, token, line, msg):
	print "line " + str(pos) + ": EXPECT ERROR: " + token + " " + msg  + " " + line
	sys.exit()


def testFile(file):
	pfile = open(file, 'r')	
	
	content = pfile.readlines()
	
	test_counter = 0;
	
	for x in range (0, len(content)-1, 2):
		pattern = content[x+1].strip("\n")
		tokens = pattern.split(",")
		test_counter += 1
		for token in tokens:
			if token[0] == "!":
				if re.search(token[1:], content[x]):
					failure(x+1, token[1:], content[x], "IS IN")
			else:
				if not re.search(token, content[x]):
					failure(x+1, token, content[x], "IS NOT IN")


	print str(test_counter) + " tests"
	print "PASS OK!"

if __name__ == '__main__':
	testFile(sys.argv[1])

	    
