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

import java.math.BigInteger;

import com.oracle.truffle.api.frame.VirtualFrame;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class PcodeOpBranchNode extends PcodeOpNode {

    final PcodeOp pcodeOp;

    public PcodeOpBranchNode(final PcodeOp pcodeOp, PcodeOpContext context) {
        super(context);
        this.pcodeOp = pcodeOp;
    }

    public PcodeOpBranchNode(final PcodeOp pcodeOp) {
        this(pcodeOp, null);
    }

    private void executeCbranch() {
        Varnode condVar = pcodeOp.getInput(1);
        boolean takeBranch = false;
        if (condVar.getSize() > 8) {
            takeBranch = !state.getBigInteger(condVar, false).equals(BigInteger.ZERO);
        } else {
            takeBranch = state.getValue(condVar) != 0;
        }

        if (takeBranch) {
            throw new PcodeOpBranchException(pcodeOp);
        }
    }

    @Override
    public void execute(VirtualFrame frame) {
        switch (pcodeOp.getOpcode()) {
            case PcodeOp.CBRANCH: {
                executeCbranch();
                break;
            }
            case PcodeOp.MULTIEQUAL: {
                throw new RuntimeException("MULTIEQUAL appeared in unheritaged code");
            }
            case PcodeOp.INDIRECT: {
                throw new RuntimeException("MULTIEQUAL appeared in unheritaged code");
            }
            default: {
                throw new PcodeOpBranchException(pcodeOp);
            }
        }
    }
    
}
