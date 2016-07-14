# output a file that maps instruction mneumonic to its metadata including the flag(s) it sets
# x86data.json is from https://github.com/asmjit/asmdb/blob/master/x86data.js


import json

with open('./x86data.json') as fp:
	data = json.load(fp)
	prev_mn = None
	regs = {}
	for arr in data['instructions']:
		if arr[0] != prev_mn:
			mn_arr = arr[0].split('/')
			for mn in mn_arr:
				regs[mn] = arr[-1]
			prev_mn = arr[0]
	

	outfile = open('../x86registers.json', 'w')
	json.dump(regs, outfile)

