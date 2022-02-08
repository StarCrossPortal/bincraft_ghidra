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

import ghidra.pcode.opbehavior.BinaryOpBehavior;
import ghidra.pcode.opbehavior.OpBehavior;
import ghidra.pcode.opbehavior.OpBehaviorFactory;
import ghidra.pcode.opbehavior.UnaryOpBehavior;
import ghidra.program.model.pcode.PcodeOp;

public class PcodeOpNodeFactory {
    static public PcodeOpNode createNodeFromPcodeOp(PcodeOp op, PcodeOpContext context) {
        OpBehavior behavior = OpBehaviorFactory.getOpBehavior(op.getOpcode());
        if (behavior instanceof BinaryOpBehavior) {
            return new PcodeOpBinaryNode(op, (BinaryOpBehavior) behavior, context);
        } else if (behavior instanceof UnaryOpBehavior) {
            return new PcodeOpUnaryNode(op, (UnaryOpBehavior) behavior, context);
        } else {
            switch (op.getOpcode()) {
                case PcodeOp.STORE:
                    return new PcodeOpStoreNode(op, context);
                case PcodeOp.LOAD:
                    return new PcodeOpLoadNode(op, context);
                default:
                    return new PcodeOpBranchNode(op, context);
            }
        }
    }
}
