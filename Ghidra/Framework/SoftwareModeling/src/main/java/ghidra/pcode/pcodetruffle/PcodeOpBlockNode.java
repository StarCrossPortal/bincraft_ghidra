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

import java.util.Vector;

import com.oracle.truffle.api.frame.VirtualFrame;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;

public class PcodeOpBlockNode extends PcodeOpNode {


    PcodeOpNode[] ops;
    private int currentIndex = 0;

    public PcodeOpBlockNode(Vector<PcodeOpNode> ops, PcodeOpContext context) {
        super(context);
        this.ops = ops.toArray(PcodeOpNode[]::new);
    }

    public PcodeOpBlockNode(Vector<PcodeOpNode> ops) {
        this(ops, null);
    }

    private boolean executeBranch(PcodeOp op) {
        Address dest = op.getInput(0).getAddress();
        if (dest.getAddressSpace().isConstantSpace()) {
            long id = dest.getOffset();
            currentIndex += id;

            if (currentIndex < 0 || currentIndex >= ops.length) {
                throw new RuntimeException("invalid relative branch");
            }

            return true;
        } else {
            return false;
        }
    }

    @Override
    public void execute(VirtualFrame frame) {
        currentIndex = 0;
        while (currentIndex < ops.length) {
            try {
                ops[currentIndex].execute(frame);
            } catch (PcodeOpBranchException e) {
                PcodeOp op = e.getOp();
                switch (op.getOpcode()) {

                    case PcodeOp.BRANCH: {
                        if (!executeBranch(op)) {
                            throw e;
                        }
                    }

                    default:
                        throw e;
                }
            }
            currentIndex += 1;
        }
    }
    
}
