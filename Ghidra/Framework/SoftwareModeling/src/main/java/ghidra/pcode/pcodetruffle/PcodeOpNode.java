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

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.instrumentation.GenerateWrapper;
import com.oracle.truffle.api.instrumentation.InstrumentableNode;
import com.oracle.truffle.api.instrumentation.ProbeNode;
import com.oracle.truffle.api.nodes.Node;
import com.oracle.truffle.api.nodes.NodeInfo;

import ghidra.pcode.memstate.MemoryState;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.pcode.PcodeOp;

@GenerateWrapper
@NodeInfo(description = "The abstract base node for all pcode ops")
public abstract class PcodeOpNode extends Node implements InstrumentableNode {

    protected MemoryState state;
    protected AddressFactory addrFactory;
    private PcodeOpContext context;

    public PcodeOpNode(PcodeOpContext context) {
        this.context = context;
        this.state = getContext().getMemoryState();
        this.addrFactory = getContext().getAddressFactory();
    }

    public PcodeOpNode(PcodeOpNode copyFrom) {
        this(copyFrom.context);
    }

    protected PcodeOpContext getContext() {
        if (this.context == null) {
            return lookupContextReference(PcodeOpLanguage.class).get();
        } else {
            return this.context;
        }
    }

    @Override
    public boolean isInstrumentable() {
        return true;
    }

    @Override
    public WrapperNode createWrapper(ProbeNode probe) {
        return new PcodeOpNodeWrapper(this, this, probe);
    }

    public abstract void execute(final VirtualFrame frame);
}
