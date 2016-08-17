# output a file that maps instruction mneumonic to its metadata including the flag(s) it sets
# x86data.json is from https://github.com/asmjit/asmdb/blob/master/x86data.js


import json

def get_x86registers():
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
        

        with open('./x86registers.json', 'w') as outfile
            json.dump(regs, outfile)

def parse_ops(op, i):
    if op[0] in ('W', 'R', 'X'):
        return op[0]
    elif i == 0 :
        return 'X'
    else: 
        return 'R'

def get_x86ops():
    operands = {}
    with open('./x86data.json') as fp:
        data = json.load(fp)
        prev_mn = None
        prev_numOps = None
        for arr in data['instructions']:
            # filter out implicit regs, map to R/W
            ops = arr[1].split(", ")
            ops = filter(lambda op: ("<" not in op or ">" not in op) and len(op) > 0, ops)
            ops = [parse_ops(op, i) for i, op in enumerate(ops)]
            if arr[0] != prev_mn:
                mn_arr = arr[0].split('/')
                for mn in mn_arr:
                    operands[mn] = {len(ops): ops}
                prev_mn = arr[0]
            else:
                mn_arr = arr[0].split('/')
                for mn in mn_arr:
                    operands[mn][len(ops)] = ops
        
        with open('./x86operands.json', 'w') as outfile
            json.dump(operands, outfile)

get_x86ops()


