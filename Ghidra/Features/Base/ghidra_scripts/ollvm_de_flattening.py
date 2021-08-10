## ###
#  IP: GHIDRA
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
##
# Ghidra script for OLLVM control flow de flattening
# This script can restore the obfuscated code compiled by the -fla parameter.
#
# Usage:
#
# 1.You need to select a state variable, usually at the head before the start of the loop.
#
# 2.The state variable is mainly used in the distributor, and then it is shown as assigning and judging the same
# variable in the loop, e.g. local_14 = 0x6e36350b, then in the loop, local_14 will be judged and local_14 will be
# assigned.
#
# 3.Run the script after selecting the state variable.
# @category Repair

import os
import logging
import ghidra
from array import *

try:
    from ghidra.ghidra_builtins import *
except:
    pass

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.mem import *
from ghidra.program.model.pcode import RawPcode
from ghidra.program.model.pcode import RawPcodeImpl
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.pcode import Varnode
from ghidra.app.plugin.assembler import Assemblers

logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s][%(levelname)s] - %(message)s',
                    datefmt='%m/%d/%Y %H:%M:%S %p')

arch = currentProgram.getLanguage().getProcessor().toString()
addrs = currentProgram.getAddressFactory()

orig_hex = hex


def hex(x):
    if orig_hex(x)[-1] == 'L':
        return orig_hex(x)[:-1]
    else:
        return orig_hex(x)


def get_last_pcode(block):
    pcode_iterator = block.getIterator()
    while pcode_iterator.hasNext():
        pcode = pcode_iterator.next()
        if not pcode_iterator.hasNext():
            return pcode


# check if the var is state_var
def is_state_var(state_var, var, depth=0):
    logging.debug('comparing %s to state var %s, depth %d' % (var, state_var, depth))
    if depth > 1:
        logging.warning('reach max depth for is_state_var: %s' % var)
        return False
    # for temp var, find its definition
    if var.isUnique():
        var_def = var.getDef()
        logging.debug('temp var def: %s' % var_def)
        if var_def.getOpcode() == PcodeOp.COPY:
            var = var_def.getInput(0)
            logging.debug('update var to %s' % var)
        elif var_def.getOpcode() == PcodeOp.MULTIEQUAL:
            # include phi node inputs
            for input_var in var_def.getInputs().tolist():
                if is_state_var(state_var, input_var, depth + 1):
                    return True
    return state_var.getAddress() == var.getAddress()


# value of state var may need to be updated before compared to const
def const_update(const):
    # signed to unsigned
    return const & 0xffffffff


# find blocks setting state var to consts
def find_const_def_blocks(mem, state_var_size, pcode, depth, res, def_block):
    if depth > 3:
        logging.warning('reaching max depth in find_const_def_blocks')

    elif pcode is None:
        logging.warning('pcode is None')

    else:
        logging.debug('finding state var def in pcode %s of block %s, depth %d' % (pcode, pcode.getParent(), depth))
        if pcode.getOpcode() == PcodeOp.COPY:
            input_var = pcode.getInput(0)
            if def_block is None:
                # the block of COPY is the def block
                def_block = pcode.getParent()
                logging.debug('find COPY in block %s' % def_block)
            # is copying const to var?
            if input_var.isConstant():
                logging.debug('%s defines state var to const: %s' % (def_block, input_var))
                if def_block not in res:
                    res[def_block] = input_var.getOffset()
                else:
                    logging.warning('%s already defines state var to const %s, skipped' % (def_block, res[def_block]))
            else:
                # if input var is in ram, read its value
                if input_var.getAddress().getAddressSpace().getName() == u'ram':
                    if input_var.isAddress():
                        if state_var_size == 4:
                            ram_value = mem.getInt(input_var.getAddress())
                            res[def_block] = ram_value
                        elif state_var_size == 8:
                            ram_value = mem.getLong(input_var.getAddress())
                            res[def_block] = ram_value
                        else:
                            logging.warning('state var size %d not supported' % state_var_size)
                    else:
                        logging.warning('def of non-const input_var %s not found' % input_var)
                # not ram or const, trace back to const def
                else:
                    find_const_def_blocks(mem, state_var_size, input_var.getDef(), depth + 1, res, def_block)

        elif pcode.getOpcode() == PcodeOp.MULTIEQUAL:
            for input_var in pcode.getInputs().tolist():
                find_const_def_blocks(mem, state_var_size, input_var.getDef(), depth + 1, res, def_block)
        else:
            logging.warning('unsupported pcode %s, depth %d' % (pcode, depth))


class Patcher(object):
    def __init__(self, current_program):
        self.listing_db = current_program.getListing()
        self.asm = Assemblers.getAssembler(current_program)

    def patch_unconditional_jump(self, addr, target_addr):
        inputs = array(Varnode, [Varnode(target_addr, 8)])
        patch_pcode_data = RawPcodeImpl(PcodeOp.BRANCH, inputs, None)
        patch_pcode = array(RawPcode, [patch_pcode_data])
        inst = getInstructionAt(addr)
        inst.patchPcode(patch_pcode)

    def patch_conditional_jump(self, ins, true_block, false_block, target_block):
        true_addr = true_block.getStart()
        false_addr = false_block.getStart()
        p_code = ins.getPcode()

        reg_datas = []
        # get CBRANCH register value
        branch_reg = 0
        reg_data_idx = 1
        pcode_len = len(p_code)
        for index in range(pcode_len):
            if p_code[index].opcode == 37 and index != 0:
                branch_reg = p_code[index].getInput(0)
            # aarch64 csel
            if pcode_len >= 4 and index < pcode_len - 3:
                if p_code[index].opcode == PcodeOp.COPY and p_code[index + 1].opcode == PcodeOp.BRANCH and \
                        p_code[index + 2].opcode == PcodeOp.COPY and p_code[index + 3].opcode == PcodeOp.INT_ZEXT:
                    reg_data_idx = index
                # ppc64le
                if p_code[index].opcode == PcodeOp.COPY and p_code[index + 1].opcode == PcodeOp.INT_SUB and \
                        p_code[index + 2].opcode == PcodeOp.INT_RIGHT and p_code[index + 3].opcode == PcodeOp.INT_AND:
                    reg_data_idx = index + 4

        # mips display patch
        if arch == "MIPS":
            if p_code[0].opcode == PcodeOp.INT_NOTEQUAL and p_code[1].opcode == PcodeOp.CBRANCH:
                branch_reg = p_code[0].getOutput()
            value = None

            target_start_addr = target_block.getStart()
            target_end_addr = target_block.getStop()
            # patch xori to li
            while target_start_addr <= target_end_addr:
                current_inst = getInstructionAt(target_start_addr)
                current_pcode = current_inst.getPcode()[0]
                if current_pcode.opcode == PcodeOp.INT_XOR and current_pcode.getInput(1).isConstant() is True:
                    value_inputs = array(Varnode, [current_pcode.getInput(1)])
                    # (register,0x10,8) v0
                    value_output = Varnode(addrs.getAddress(addrs.registerSpace.spaceID, 0x10), 8)
                    value = RawPcodeImpl(PcodeOp.COPY, value_inputs, value_output)
                    current_inst.patchPcode(array(RawPcode, [value]))
                target_start_addr = target_start_addr.add(4)

            inst_before = getInstructionBefore(ins)
            inst_before_pcode = inst_before.getPcode()[0]
            # patch ori to li
            if inst_before_pcode.getInput(0).offset == 0x18 and value is not None:
                inst_before.patchPcode(array(RawPcode, [value]))
            elif inst_before_pcode.getInput(0).offset == 0x18 and value is None:
                value_inputs = array(Varnode, [Varnode(addrs.getAddress(addrs.constantSpace.spaceID, 0), 8)])
                value_output = Varnode(addrs.getAddress(addrs.registerSpace.spaceID, 0x10), 8)
                value = RawPcodeImpl(PcodeOp.COPY, value_inputs, value_output)
                inst_before.patchPcode(array(RawPcode, [value]))

        if branch_reg == 0:
            for var in p_code[0].getInputs():
                if var.isRegister():
                    branch_reg = var

        for idx in range(reg_data_idx):
            reg_inputs = p_code[idx].getInputs()
            reg_outs = p_code[idx].getOutput()
            reg_opcode = p_code[idx].getOpcode()
            # construct beq v0,at,address
            if arch == "MIPS" and reg_opcode == PcodeOp.INT_NOTEQUAL:
                reg_inputs = array(Varnode, [Varnode(addrs.getAddress(addrs.registerSpace.spaceID, 0x8), 8),
                                             Varnode(addrs.getAddress(addrs.registerSpace.spaceID, 0x10), 8)])
                reg_opcode = PcodeOp.INT_EQUAL
            reg_data = RawPcodeImpl(reg_opcode, reg_inputs, reg_outs)
            reg_datas.append(reg_data)
        raw_pcode = [reg for reg in reg_datas]

        if p_code[0].opcode == PcodeOp.INT_ZEXT or p_code[0].opcode == PcodeOp.COPY:
            # construct true data
            true_inputs = array(Varnode, [Varnode(true_addr, 8), branch_reg])
            true_branch = RawPcodeImpl(PcodeOp.CBRANCH, true_inputs, None)

            # construct false data
            false_inputs = array(Varnode, [Varnode(false_addr, 8)])
            false_branch = RawPcodeImpl(PcodeOp.BRANCH, false_inputs, None)

            # ppc64le iseleq
            if pcode_len > 6 and p_code[5].opcode == PcodeOp.BOOL_NEGATE:
                raw_pcode.append(true_branch)
                raw_pcode.append(false_branch)
                patch_pcode = array(RawPcode, raw_pcode)
            else:
                patch_pcode = array(RawPcode, [true_branch, false_branch])
        else:

            # construct true data
            true_inputs = array(Varnode, [Varnode(true_addr, 8), branch_reg])
            true_branch = RawPcodeImpl(PcodeOp.CBRANCH, true_inputs, None)

            # construct false data
            false_inputs = array(Varnode, [Varnode(false_addr, 8)])
            false_branch = RawPcodeImpl(PcodeOp.BRANCH, false_inputs, None)

            raw_pcode.append(true_branch)
            raw_pcode.append(false_branch)

            patch_pcode = array(RawPcode, raw_pcode)

        # patch
        ins.patchPcode(patch_pcode)

    # patch the binary for updated CFG
    def do_patch(self, link):
        logging.debug('patching block for CFG %s' % str(link))

        block = link[0]
        ins = self.listing_db.getInstructions(block.getStop(), True).next()
        logging.debug('last ins in block to patch at %s: %s' % (block.getStop(), ins))

        patch_addr = ins.getMinAddress()

        # unconditional jump
        if len(link) == 2:
            target_addr = link[1].getStart()
            self.patch_unconditional_jump(patch_addr, target_addr)
            logging.debug('patching unconditional jump at %s to %s' % (patch_addr, target_addr))

        # conditional jump
        else:
            true_block = link[1]
            false_block = link[2]
            self.patch_conditional_jump(ins, true_block, false_block, block)


def get_high_function(current_program, current_address):
    decomplib = DecompInterface()
    decomplib.openProgram(current_program)

    current_function = getFunctionContaining(current_address)
    decompile_res = decomplib.decompileFunction(current_function, 30, getMonitor())

    high_function = decompile_res.getHighFunction()
    return high_function


def get_state_var(high_function, current_address):
    pcode_iterator = high_function.getPcodeOps(current_address)
    pcode = None

    # find the pcode for COPYing const
    while pcode_iterator.hasNext():
        pcode = pcode_iterator.next()
        logging.debug('finding COPY const pcode: %s' % pcode)
        if pcode.getOpcode() == PcodeOp.COPY and pcode.getInput(0).isConstant():
            break

    logging.info('COPY const pcode: %s' % pcode)

    # find the state var in phi node
    depth = 0
    while pcode is not None and pcode.getOpcode() != PcodeOp.MULTIEQUAL:
        logging.debug('finding phi node: %s, depth %d' % (pcode, depth))
        if pcode.getOutput() is None:
            logging.warning('output is None in %s' % pcode)
            break
        pcode = pcode.getOutput().getLoneDescend()
        if depth > 5:
            break
        depth += 1

    if pcode is None or pcode.getOpcode() != PcodeOp.MULTIEQUAL:
        logging.error('cannot find phi node')
        return None
    else:
        logging.info('phi node: %s' % pcode)

    state_var = pcode.getOutput()
    logging.info('state var is %s' % state_var)
    return state_var


# map const values of state var to blocks
def compute_const_map(high_function, state_var):
    const_map = {}

    for block in high_function.getBasicBlocks():
        # search for conditional jump
        if block.getOutSize() != 2:
            continue

        last_pcode = get_last_pcode(block)
        if last_pcode.getOpcode() != PcodeOp.CBRANCH:
            continue

        condition = last_pcode.getInput(1)

        condition_pcode = condition.getDef()
        logging.debug('condition pcode: %s' % condition_pcode)

        condition_type = condition_pcode.getOpcode()

        if not condition_type in (PcodeOp.INT_NOTEQUAL, PcodeOp.INT_EQUAL):
            continue

        in0 = condition_pcode.getInput(0)
        in1 = condition_pcode.getInput(1)

        if in0.isConstant():
            const_var = in0
            compared_var = in1
        elif in1.isConstant():
            const_var = in1
            compared_var = in0
        else:
            logging.debug('not const var in comparision, skipped')
            continue

        if is_state_var(state_var, compared_var):
            if condition_type == PcodeOp.INT_NOTEQUAL:
                target_block = block.getFalseOut()
            else:
                target_block = block.getTrueOut()
            const_map[const_var.getOffset()] = target_block
        else:
            logging.debug('state_var not involved in %s' % condition_pcode)

    logging.info('const_map map:\n%s' % '\n'.join('0x%x: %s' % kv for kv in const_map.items()))
    return const_map


def find_state_var_defs(mem, state_var):
    phi_node = state_var.getDef()

    state_var_defs = {}

    for state_var_def in phi_node.getInputs().tolist():
        if state_var_def == state_var:
            continue
        pcode = state_var_def.getDef()
        logging.debug('output %s of pcode %s in block %s defines state var' % (state_var_def, pcode, pcode.getParent()))

        find_const_def_blocks(mem, state_var.getSize(), pcode, 0, state_var_defs, None)

    logging.info(
        'blocks defining state var:\n%s' % '\n'.join('%s: %s' % (b, hex(v)) for b, v in state_var_defs.items()))
    return state_var_defs


def gen_cfg(const_map, state_var_defs):
    links = []

    # basic blocks for CMOVXX
    cmovbb = []

    for def_block, const in state_var_defs.items():
        # unconditional jump
        if def_block.getOutSize() == 1:
            const = const_update(const)
            if const in const_map:
                link = (def_block, const_map[const])
                logging.debug('unconditional jump link: %s' % str(link))
                links.append(link)
            else:
                logging.warning('cannot find const 0x%x in const_map' % const)

        # conditional jump
        elif def_block.getOutSize() == 2:
            const = const_update(const)
            true_out = def_block.getTrueOut()
            false_out = def_block.getFalseOut()
            logging.debug('%s true out: %s, false out %s' % (def_block, true_out, false_out))

            # true out block has state var def
            if true_out in state_var_defs:
                true_out_const = const_update(state_var_defs[true_out])
                if true_out_const not in const_map:
                    logging.warning('true out cannot find map from const 0x%x to block' % true_out_const)
                    continue
                true_out_block = const_map[true_out_const]
                logging.debug('true out to block: %s' % true_out_block)

                if false_out in state_var_defs:
                    false_out_const = const_update(state_var_defs[false_out])
                    if false_out_const not in const_map:
                        logging.warning('false out cannot find map from const 0x%x to block' % false_out_const)
                        continue
                    else:
                        false_out_block = const_map[false_out_const]
                        logging.debug('false out to block: %s' % false_out_block)

                # false out doesn't have const def, then use the def in current block for the false out
                elif const in const_map:
                    false_out_block = const_map[const]
                else:
                    logging.warning('mapping of const %s in block %s not found' % (const, def_block))
                    continue

                link = (def_block, true_out_block, false_out_block)
                logging.debug('conditional jump link: %s' % str(link))

                # the link from CMOVXX should be ignored since the current conditional jump would do it
                cmovbb.append(true_out)
                links.append(link)

            # false out block has state var def
            elif false_out in state_var_defs:
                false_out_const = const_update(state_var_defs[false_out])
                if false_out_const not in const_map:
                    logging.warning('false out cannot find map from const 0x%x to block' % false_out_const)
                    continue
                false_out_block = const_map[false_out_const]
                logging.debug('false out to block: %s' % false_out_block)

                # true out doesn't have const def, then use the def in current block for the true out
                if const in const_map:
                    true_out_block = const_map[const]
                    link = (def_block, true_out_block, false_out_block)
                    logging.debug('conditional jump link: %s' % str(link))
                    links.append(link)
                else:
                    logging.warning('mapping of const %s in block %s not found' % (const, def_block))
            else:
                logging.warning('no state var def in either trueout or falseout of block %s' % def_block)
        else:
            logging.warning('output block counts %d not supported' % def_block.getOutSize())

    # skip the link for CMOVXX
    links_res = []
    for link in links:
        if link[0] not in cmovbb:
            links_res.append(link)
        else:
            logging.debug('skip %s as CMOVXX' % str(link))

    logging.info('generated CFG links:\n%s' % '\n'.join(str(link) for link in links_res))
    return links_res


def patch_cfg(current_program, cfg_links):
    patcher = Patcher(current_program)
    for link in cfg_links:
        try:
            patcher.do_patch(link)
        except Exception as e:
            logging.warning('failed to patch %s' % str(link))
            logging.warning(e)


def save_patched(current_program, mem, patches):
    fpath = current_program.getExecutablePath()
    patched_pach = '%s-patched' % fpath

    file_data = None

    if os.path.exists(patched_pach):
        fpath = patched_pach

    with open(fpath, 'rb') as fin:
        file_data = bytearray(fin.read())

    for addr, patch_bytes in patches:
        offset = mem.getAddressSourceInfo(addr).getFileOffset()
        file_data[offset:offset + len(patch_bytes)] = patch_bytes

    with open(patched_pach, 'wb') as fout:
        fout.write(file_data)
        logging.info('save patched file as %s' % patched_pach)


if __name__ == '__main__':
    current_mem = currentProgram.getMemory()

    current_high_function = get_high_function(currentProgram, currentAddress)
    current_state_var = get_state_var(current_high_function, currentAddress)
    current_const_map = compute_const_map(current_high_function, current_state_var)
    current_state_var_defs = find_state_var_defs(current_mem, current_state_var)
    current_cfg_links = gen_cfg(current_const_map, current_state_var_defs)

    patch_cfg(currentProgram, current_cfg_links)
