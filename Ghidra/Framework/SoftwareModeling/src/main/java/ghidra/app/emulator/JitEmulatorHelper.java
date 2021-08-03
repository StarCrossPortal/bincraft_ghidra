/* ###
 * IP: GHIDRA
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
package ghidra.app.emulator;

import ghidra.app.emulator.memory.EmulatorLoadData;
import ghidra.app.emulator.memory.MemoryLoadImage;
import ghidra.app.emulator.memory.ProgramMappedMemory;
import ghidra.app.emulator.memory.ProgramMappedLoadImage;
import ghidra.app.emulator.state.DumpMiscState;
import ghidra.app.emulator.state.RegisterState;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

public class JitEmulatorHelper implements MemoryFaultHandler, EmulatorConfiguration {

    private final Program program;
    
    public JitEmulatorHelper(Program program) {
        this.program = program;
    }

    @Override
    public Language getLanguage() {
        return program.getLanguage();
    }

    @Override
    public EmulatorLoadData getLoadData() {
		return new EmulatorLoadData() {

			@Override
			public MemoryLoadImage getMemoryLoadImage() {
				return new ProgramMappedLoadImage(
					new ProgramMappedMemory(program, JitEmulatorHelper.this));
			}

			@Override
			public RegisterState getInitialRegisterState() {
				return new DumpMiscState(getLanguage());
			}
		};
    }

    @Override
    public MemoryFaultHandler getMemoryFaultHandler() {
        return this;
    }

    @Override
    public boolean uninitializedRead(Address address, int size, byte[] buf, int bufOffset) {
        Register reg = program.getRegister(address, size);

        if (reg != null) {
			Msg.warn(this, "Uninitialized register read at " + reg);
            return true;
        }
        Msg.warn(this,
			"Uninitialized memory read at " + address.toString(true) + ":" + size);
        return true;
    }

    @Override
    public boolean unknownAddress(Address address, boolean write) {
        return false;
    }
    
}
