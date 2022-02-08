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

import ghidra.pcode.opbehavior.BinaryOpBehavior;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class PcodeOpBinaryNode extends PcodeOpNode {

    private BinaryOpBehavior behavior;
    private PcodeOp pcodeOp;


    public PcodeOpBinaryNode(final PcodeOp pcodeOp, BinaryOpBehavior behavior, PcodeOpContext context) {
        super(context);
        this.pcodeOp = pcodeOp;
        this.behavior = behavior;
    }

    public PcodeOpBinaryNode(final PcodeOp pcodeOp, BinaryOpBehavior behavior) {
        this(pcodeOp, behavior, null);
    }

    private BigInteger doExecute(int sizeOut, int sizeIn, BigInteger in1, BigInteger in2) {
        return behavior.evaluateBinary(sizeOut, sizeIn, in1, in2);
    }

    private long doExecute(int sizeOut, int sizeIn, long in1, long in2) {
        return behavior.evaluateBinary(sizeOut, sizeIn, in1, in2);
    }

    @Override
    public void execute(VirtualFrame frame) {
        Varnode v1 = pcodeOp.getInput(0);
        Varnode v2 = pcodeOp.getInput(1);
        Varnode vOut = pcodeOp.getOutput();

        if (v1.getSize() > 8 || v2.getSize() > 8 || vOut.getSize() > 8) {
            BigInteger in1 = state.getBigInteger(v1, false);
            BigInteger in2 = state.getBigInteger(v2, false);
            BigInteger out = doExecute(vOut.getSize(), v1.getSize(), in1, in2);
            state.setValue(vOut, out);
        } else {
            long in1 = state.getValue(v1);
            long in2 = state.getValue(v2);
            long out = doExecute(vOut.getSize(), v1.getSize(), in1, in2);
            state.setValue(vOut, out);
        }
    }
}
