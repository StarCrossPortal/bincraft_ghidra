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

import ghidra.pcode.memstate.MemoryState;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class PcodeOpStoreNode extends PcodeOpNode {

    final PcodeOp pcodeOp;

	public PcodeOpStoreNode(PcodeOp pcodeOp, PcodeOpContext context) {
        super(context);
        this.pcodeOp = pcodeOp;
    }

    public PcodeOpStoreNode(PcodeOp pcodeOp) {
		this(pcodeOp, null);
    }

    @Override
    public void execute(VirtualFrame frame) {
        PcodeOp op = pcodeOp;
        MemoryState memstate = state;

        AddressSpace space =
			addrFactory.getAddressSpace((int) op.getInput(0).getAddress().getOffset()); // Space to store in

		long offset = memstate.getValue(op.getInput(1)); // Offset to store at
		long byteOffset =
			space.truncateAddressableWordOffset(offset) * space.getAddressableUnitSize();

		Varnode storedVar = op.getInput(2); // Value being stored
		if (storedVar.getSize() > 8) {
			BigInteger val = memstate.getBigInteger(storedVar, false);
			memstate.setValue(space, byteOffset, op.getInput(2).getSize(), val);
		}
		else {
			long val = memstate.getValue(storedVar);
			memstate.setValue(space, byteOffset, op.getInput(2).getSize(), val);
		}
    }
}
