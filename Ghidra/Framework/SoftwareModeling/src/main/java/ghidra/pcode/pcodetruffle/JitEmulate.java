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

import com.oracle.truffle.api.CallTarget;
import com.oracle.truffle.api.Truffle;
import com.oracle.truffle.api.TruffleRuntime;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.memstate.MemoryState;
import ghidra.pcode.memstate.UniqueMemoryBank;
import ghidra.program.model.address.Address;

public class JitEmulate {

    private SleighLanguage sleighLang;
    private MemoryState state;
    private TruffleRuntime runtime;
    private PcodeOpContext context;
    private UniqueMemoryBank uniqueBank;

    public JitEmulate(SleighLanguage sleighLang, MemoryState state) {
        this.sleighLang = sleighLang;
        this.state = state;
        this.context = new PcodeOpContext(sleighLang, state);
        this.runtime = Truffle.getRuntime();

        uniqueBank =
            new UniqueMemoryBank(
                sleighLang.getAddressFactory().getUniqueSpace(),
                sleighLang.isBigEndian());
        state.setMemoryBank(uniqueBank);
    }

    public JitEmulate(PcodeOpContext context) {
        this.context = context;
        this.sleighLang = context.getSleighLanguage();
        this.state = context.getMemoryState();
        this.runtime = Truffle.getRuntime();
    }

    public void run(Address entry) {
        CallTarget target = runtime.createCallTarget(new PcodeOpRootNode(null, sleighLang, entry, context));
        target.call();
    }
}
