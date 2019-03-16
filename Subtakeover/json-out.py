import sys
data = open(sys.argv[1],"r").read().splitlines()
output_data = {}
for i in data:
        output_data.update([tuple(i.split(','))])
print str(output_data).replace("'","\"")
