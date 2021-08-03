/* ###
 * IP: BinCraft
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.pcode.pcodetruffle;

import java.util.HashMap;
import java.util.Vector;

import com.oracle.truffle.api.CallTarget;
import com.oracle.truffle.api.Truffle;
import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.nodes.RootNode;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emulate.EmulateMemoryStateBuffer;
import ghidra.pcode.emulate.UnimplementedCallOtherException;
import ghidra.pcode.memstate.MemoryState;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.InstructionBlock;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitorAdapter;

public class PcodeOpRootNode extends RootNode {

    private Address currentAddress;
    private Disassembler disassembler;
    private Register pcRegister;
    private SleighLanguage lang;
    private PcodeOpLanguage pcodeOpLanguage;
    private AddressFactory addrFactory;
    private MemoryState state;
    private HashMap<Address, PcodeOpBlockNode> blocks;
    private PcodeOpContext context;


    public PcodeOpRootNode(PcodeOpLanguage pcodeOpLanguage, SleighLanguage lang, Address entry, PcodeOpContext context) {
        super(pcodeOpLanguage);
        this.context = context;
        this.pcodeOpLanguage = pcodeOpLanguage;

        this.addrFactory = getContext().getAddressFactory();
        this.state = getContext().getMemoryState();
        this.blocks = getContext().getBlockCache();
        this.disassembler = Disassembler.getDisassembler(lang, addrFactory, TaskMonitorAdapter.DUMMY, null);
        this.lang = lang;
        this.currentAddress = entry;
        this.pcRegister = lang.getProgramCounter();
    }

    public PcodeOpRootNode(PcodeOpLanguage pcodeOpLanguage, SleighLanguage lang, Address entry) {
        this(pcodeOpLanguage, lang, entry, null);
    }

    private PcodeOpContext getContext() {
        if (context != null) {
            return context;
        } else {
            return lookupContextReference(PcodeOpLanguage.class).get();
        }
    }

    private PcodeOpBlockNode newBlockNode(Address blockEntry) {
        EmulateMemoryStateBuffer memBuffer = new EmulateMemoryStateBuffer(state, blockEntry);
        InstructionBlock instBlock = disassembler.pseudoDisassembleBlock(memBuffer, null, Integer.MAX_VALUE);
        Vector<PcodeOpNode> ops = new Vector<PcodeOpNode>();
        for (var inst : instBlock) {
            for (var pcode : inst.getPcode()) {
                PcodeOpNode node = PcodeOpNodeFactory.createNodeFromPcodeOp(pcode, getContext());
                ops.add(node);
            }
        }

        return new PcodeOpBlockNode(ops, getContext());
    }

    private void setCurrentAddress(Address addr) {
        currentAddress = addr;
        state.setValue(pcRegister, currentAddress.getAddressableWordOffset());
    }

    private void executeBranch(PcodeOp op) {
        Address dest = op.getInput(0).getAddress();
        if (dest.getAddressSpace().isConstantSpace()) {
            throw new RuntimeException("trying to branch relatively out of block node");
        } else {
            setCurrentAddress(dest);
        }
    }

    private void doCall(Address targetAddr) {
        try {
            CallTarget target = Truffle.getRuntime()
                    .createCallTarget(new PcodeOpRootNode(
                        pcodeOpLanguage,
                        lang,
                        targetAddr,
                        context));

            target.call();
        }
        catch (PcodeOpReturnException returnException) {
        }
    }

    private void executeCall(PcodeOp op) {
        Address targetAddr = op.getInput(0).getAddress();
        doCall(targetAddr);
    }

    private void executeCallind(PcodeOp op) {
        long offset = state.getValue(op.getInput(0));
		AddressSpace space = op.getSeqnum().getTarget().getAddressSpace();
        Address targetAddr = space.getTruncatedAddress(offset, true);
        doCall(targetAddr);
    }

    private void executeBranchind(PcodeOp op) {
        long offset = state.getValue(op.getInput(0));
		AddressSpace space = op.getSeqnum().getTarget().getAddressSpace();
		setCurrentAddress(space.getTruncatedAddress(offset, true));
    }

    private void executeReturn(PcodeOp op) {
        long offset = state.getValue(op.getInput(0));
		AddressSpace space = op.getSeqnum().getTarget().getAddressSpace();
		throw new PcodeOpReturnException(space.getTruncatedAddress(offset, true));
    }

    @Override
    public Object execute(VirtualFrame frame) {
        while (true) {
            PcodeOpBlockNode block = blocks.get(currentAddress);
            if (block == null) {
                block = newBlockNode(currentAddress);
                blocks.put(currentAddress, block);
            }

            try {
                block.execute(frame);

            } catch (PcodeOpBranchException e) {
                PcodeOp op = e.getOp();

                switch (op.getOpcode()) {
                    case PcodeOp.BRANCH: {
                        executeBranch(op);
                        break;
                    }

                    case PcodeOp.CBRANCH: {
                        // only taken branch should throw branch exception
                        executeBranch(op);
                        break;
                    }

                    case PcodeOp.BRANCHIND: {
                        executeBranchind(op);
                        break;
                    }

                    case PcodeOp.CALL: {
                        executeCall(op);
                        break;
                    }

                    case PcodeOp.CALLIND: {
                        executeCallind(op);
                        break;
                    }

                    case PcodeOp.CALLOTHER: {
                        // TODO
                        throw new UnimplementedCallOtherException(new PcodeOpRaw(op), lang.getUserDefinedOpName((int) op.getInput(0).getOffset()));
                    }

                    case PcodeOp.RETURN: {
                        executeReturn(op);
                        break;
                    }

                    default: {
                        throw new RuntimeException("unknown branch pcode " + op.toString());
                    }
                }
            }
        }
    }
}
