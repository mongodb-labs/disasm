# Copyright 2016 MongoDB Inc.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#    http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections
from elftools.dwarf.descriptions import ExprDumper, describe_reg_name

DwarfOp = collections.namedtuple('DwarfOp', 'opcode opcode_name args')
OpPiece = collections.namedtuple('OpPiece', 'format key value size')

_DWARF_EXPR_DUMPER_CACHE = {}
_MACHINE_ARCH = None

# fake enums for types of dwarf expr return values
REG = "REG"
VALUE = "VALUE"
ADDR = "ADDR"

def set_global_machine_arch(arch):
    global _MACHINE_ARCH
    _MACHINE_ARCH = arch

# adapted from pyelftool's version of describe_DWARF_expr
def describe_DWARF_expr(expr, structs):
    """ Textual description of a DWARF expression encoded in 'expr'.
        structs should come from the entity encompassing the expression - it's
        needed to be able to parse it correctly.
    """
    # Since this function can be called a lot, initializing a fresh new
    # ExprDumper per call is expensive. So a rudimentary caching scheme is in
    # place to create only one such dumper per instance of structs.
    cache_key = id(structs)
    if cache_key not in _DWARF_EXPR_DUMPER_CACHE:
        _DWARF_EXPR_DUMPER_CACHE[cache_key] = \
            ExprParser(structs)
    dwarf_expr_dumper = _DWARF_EXPR_DUMPER_CACHE[cache_key]

    dwarf_expr_dumper.clear()
    dwarf_expr_dumper.process_expr(expr)
    op = dwarf_expr_dumper.parse_stack()
    return op

# inherits from ExprDumper in pyelftools description.py to 
# override _after_visit and execute dwarf expression stack operations
class ExprParser(ExprDumper):
    def __init__(self, structs):
        super(ExprDumper, self).__init__(structs)
        self._parts = []
        self.opcode_dividers = {
            "DW_OP_and": "&",
            "DW_OP_div": "/",
            "DW_OP_minus": "-",
            "DW_OP_mod": "%",
            "DW_OP_mul": "*",
            "DW_OP_or": "|",
            "DW_OP_plus": "+",
            "DW_OP_xor": "^"
        }

    def clear(self):
        self._parts = []

    def _after_visit(self, opcode, opcode_name, args):
        self._parts.append(DwarfOp(opcode, opcode_name, args))

    # called after a call to process_expr. 
    # takes _parts and executes/parses it into an intelligible result.
    def parse_stack(self, parts=None):
        if not parts:
            parts = self._parts

        stack = [] # stack of DwarfOps
        for part in parts:
            try: # fail with unimplemented dwarf expressions
                stack, terminate = self._handle_stack(part, stack)
                if terminate:
                    return stack
            except:
                return None
        return stack

    # Given a "most recent" dwarf expression operation and the stack so far,
    # apply the operation (top)
    # not everything is implemented (aka things that return None, True)
    # GNU has some specific DWARF ops that pyelftools doesn't handle. 
    # https://github.com/tomhughes/libdwarf/blob/master/libdwarf/dwarf.h seems to be an exhaustive list
    #
    # ret: stack, is_terminated   
    def _handle_stack(self, top, stack):
        opcode_name = top.opcode_name
        args = top.args

        # register location
        if opcode_name[:9] == "DW_OP_reg":
            regnum = opcode_name[9:] if opcode_name[9:] != 'x' else args[0]
            regname = describe_reg_name(int(regnum), _MACHINE_ARCH)
            stack.append(OpPiece(REG, regname, regname, None))

        # register + computation
        elif opcode_name[:10] == "DW_OP_breg":
            regnum = opcode_name[10:] if opcode_name[10:] != 'x' else args[0]
            offset = args[0] if regnum != 'x' else args[1]
            regname = describe_reg_name(int(regnum), _MACHINE_ARCH)
            separator = "+" if offset >= 0 else ""
            stack.append(OpPiece(REG, regname, regname + separator + hex(offset), None))

        # frame base offset
        elif opcode_name == "DW_OP_fbreg":
            offset = args[0]
            separator = "+" if offset >= 0 else ""
            stack.append(OpPiece(ADDR, "frame base", "frame base" + separator + hex(offset), None))

        # address location
        elif opcode_name[:10] == "DW_OP_addr":
            addr = args[0]
            stack.append(OpPiece(ADDR, hex(addr), hex(addr), None))

        # composite locations
        elif opcode_name == "DW_OP_piece":
            size = args[0]
            prev_piece = stack.pop()
            new_piece = OpPiece(prev_piece.format, prev_piece.key, prev_piece.value, size)
            stack.append(new_piece)
        elif opcode_name == "DW_OP_bit_piece":
            return None, True

        # known value, not location
        elif opcode_name == "DW_OP_implicit_value":
            length = args[0]
            for i in range(length):
                stack.push(OpPiece(VALUE, args[i+1], args[i+1], None))
        elif opcode_name == "DW_OP_stack_value" or opcode_name == "OP:0x9f":
            prev_piece = stack.pop()
            # prev_piece.format = VALUE
            stack.append(prev_piece)
            return stack, True # terminate


        ## literal encodings; DWARF4 2.5.1.1
        elif opcode_name[:9] == "DW_OP_lit":
            stack.append(opcode_name[9])
        elif opcode_name[:11] == "DW_OP_const":
            const = args[0]
            stack.append(const)

        ## stack ops; 2.5.1.3
        elif opcode_name == "DW_OP_dup":
            stack.append(stack[-1])
        elif opcode_name == "DW_OP_drop":
            stack.pop()
        elif opcode_name == "DW_OP_pick":
            index = args[0]
            stack.append(stack[index])
        elif opcode_name == "DW_OP_over":
            stack.append(stack[-2])
        elif opcode_name == "DW_OP_swap":
            old_order = stack[-2:]
            for piece in old_order[::-1]:
                stack.append(piece)
        elif opcode_name == "DW_OP_rot":
            old_order = stack[-3:]
            for piece in old_order[::-1]:
                stack.append(piece)
        elif opcode_name == "DW_OP_deref":
            return None, True
        elif opcode_name == "DW_OP_deref_size":
            return None, True
        elif opcode_name == "DW_OP_xderef":
            return None, True
        elif opcode_name == "DW_OP_xderef_size":
            return None, True
        elif opcode_name == "DW_OP_push_object_address":
            return None, True
        elif opcode_name == "DW_OP_form_tls_address":
            return None, True
        elif opcode_name == "DW_OP_call_frame_cfa":
            return None, True

        # DW_OP_GNU_entry_value
        # pyelftools doesn't know how to parse its args
        elif opcode_name == "OP:0xf3":
            return None, True

        ## arithmetic/logical ops
        elif opcode_name == "DW_OP_abs":
            old = stack.pop()
            try:
                stack.append(abs(old))
            except:
                stack.append(OpPiece(old.format, old.key, "|" + old.value + "|", old.size))
        elif opcode_name == "DW_OP_and":
            first = stack.pop()
            second = stack.pop()
            try:
                stack.append(first & second)
            except: 
                new = self._handle_2arg_exception(opcode_name, first, second)
                stack.append(new)
        elif opcode_name == "DW_OP_div":
            first = stack.pop()
            second = stack.pop()           
            try:
                stack.append(second/first)
            except:
                new = self._handle_2arg_exception(opcode_name, second, first)
                stack.append(new)
        elif opcode_name == "DW_OP_minus":
            first = stack.pop()
            second = stack.pop()          
            try: 
                stack.append(second-first)
            except:
                new = self._handle_2arg_exception(opcode_name, second, first)
                stack.append(new)     
        elif opcode_name == "DW_OP_mod":
            first = stack.pop()
            second = stack.pop()
            try:
                stack.append(second % first)
            except:
                new = self._handle_2arg_exception(opcode_name, second, first)
                stack.append(new)    
        elif opcode_name == "DW_OP_mul":
            first = stack.pop()
            second = stack.pop()           
            try:
                stack.append(second*first)
            except:
                new = self._handle_2arg_exception(opcode_name, first, second)
                stack.append(new)   
        elif opcode_name == "DW_OP_neg":
            first = stack.pop()
            try:
                stack.append( -first )
            except:
                stack.append(OpPiece(first.format, first.key, '-'+first.value, first.size))
        elif opcode_name == "DW_OP_not":
            first = stack.pop()
            try:
                stack.append( ~first )            
            except:
                stack.append(OpPiece(first.format, first.key, '~'+first.value, first.size))
        elif opcode_name == "DW_OP_or":
            first = stack.pop()
            second = stack.pop() 
            try:   
                stack.append(second|first) 
            except:
                new = self._handle_2arg_exception(opcode_name, first, second)
                stack.append(new)                   
        elif opcode_name == "DW_OP_plus":
            first = stack.pop()
            second = stack.pop()
            try:        
                stack.append(second + first)
            except:
                new = self._handle_2arg_exception(opcode_name, first, second)
                stack.append(new)                  
        elif opcode_name == "DW_OP_plus_uconst":
            first = stack.pop()
            second = args[0]
            try: 
                stack.append(first + second)
            except:
                stack.append(OpPiece(first.format, first.key, first.value + "+" + second, first.size))
        elif opcode_name == "DW_OP_shl":
            return None, True
        elif opcode_name == "DW_OP_shr":
            return None, True
        elif opcode_name == "DW_OP_shra":
            return None, True
        elif opcode_name == "DW_OP_xor":
            first = stack.pop()
            second = stack.pop()           
            try:
                stack.append(second^first)
            except:
                new = self._handle_2arg_exception(opcode_name, first, second)
                stack.append(new)

        ## control flow ops
        elif opcode_name == "DW_OP_le":
            first = stack.pop()
            second = stack.pop()
            if second <= first:
                stack.append(1)
            else:
                stack.append(0)
        elif opcode_name == "DW_OP_ge":
            first = stack.pop()
            second = stack.pop()
            if second >= first:
                stack.append(1)
            else:
                stack.append(0)
        elif opcode_name == "DW_OP_eq":
            first = stack.pop()
            second = stack.pop()
            if second == first:
                stack.append(1)
            else:
                stack.append(0)
        elif opcode_name == "DW_OP_lt":
            first = stack.pop()
            second = stack.pop()
            if second < first:
                stack.append(1)
            else:
                stack.append(0)
        elif opcode_name == "DW_OP_gt":
            first = stack.pop()
            second = stack.pop()
            if second > first:
                stack.append(1)
            else:
                stack.append(0)
        elif opcode_name == "DW_OP_ne":
            first = stack.pop()
            second = stack.pop()
            if second != first:
                stack.append(1)
            else:
                stack.append(0)
        elif opcode_name == "DW_OP_skip":
            return None, True
        elif opcode_name == "DW_OP_bra":
            return None, True

        # OP:0xf3 
        else: 
            return None, True

        return stack, False

    def _handle_2arg_exception(self, opcode, arg1, arg2):
        divider = self.opcode_dividers[opcode]
        new = OpPiece(arg1.format, 
                [arg1.key, arg2.key], arg1.value + divider + arg2.value, arg1.size)
        return new




