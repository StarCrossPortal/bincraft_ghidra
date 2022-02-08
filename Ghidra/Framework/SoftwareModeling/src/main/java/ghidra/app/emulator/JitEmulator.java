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
package ghidra.app.emulator;

import java.util.List;
import java.util.Set;
import java.util.Arrays;

import ghidra.app.emulator.memory.CompositeLoadImage;
import ghidra.app.emulator.memory.EmulatorLoadData;
import ghidra.app.emulator.memory.MemoryImage;
import ghidra.app.emulator.state.FilteredMemoryPageOverlay;
import ghidra.app.emulator.state.FilteredRegisterBank;
import ghidra.app.emulator.state.RegisterState;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.pcode.memstate.MemoryPageBank;
import ghidra.pcode.memstate.MemoryState;
import ghidra.pcode.pcodetruffle.JitEmulate;
import ghidra.pcode.pcodetruffle.PcodeOpReturnException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.util.DataConverter;
import ghidra.util.Msg;

/**
 * TODO: stay closer to Emulator instead of write everything our own
 */
public class JitEmulator {

    private SleighLanguage language;
    private JitEmulate emulate;

    private AddressFactory addrFactory;

    private FilteredMemoryState memState;
    private boolean writeBack = false;
    private int pageSize;
    private final MemoryFaultHandler faultHandler;

    private String pcName;
    private long initialPC;

    private RegisterState registerState;
    private MemoryPageBank registerStateBank;
    private CompositeLoadImage loadImage = new CompositeLoadImage();

    private void initMemState(RegisterState rstate) {

		memState = new FilteredMemoryState(language);

		for (AddressSpace space : addrFactory.getPhysicalSpaces()) {
			if (!space.isLoadedMemorySpace()) {
				continue;
			}
			FilteredMemoryPageOverlay ramBank = getMemoryBank(space, getValidPageSize(space));
			memState.setMemoryBank(ramBank);
		}

		AddressSpace registerSpace = addrFactory.getRegisterSpace();
		registerStateBank = new FilteredRegisterBank(registerSpace, pageSize, rstate, language,
			writeBack, faultHandler);

		memState.setMemoryBank(registerStateBank);

		initRegisters(false);
	}

    private void initRegisters(boolean restore) {
		DataConverter conv = DataConverter.getInstance(language.isBigEndian());
		Set<String> keys = registerState.getKeys();
		for (String key : keys) {
			List<byte[]> vals = registerState.getVals(key);
			List<Boolean> initiailizedVals = registerState.isInitialized(key);
			for (int i = 0; i < vals.size(); i++) {
				String useKey = "";
				if (key.equals("GDTR") || key.equals("IDTR") || key.equals("LDTR")) {
					if (i == 0) {
						useKey = key + "_Limit";
					}
					if (i == 1) {
						useKey = key + "_Address";
					}
				}
				else if (key.equals("S.base")) {
					Integer lval = conv.getInt(vals.get(i));
					if (lval != 0 && i < vals.size() - 1) {
						useKey = "FS_OFFSET"; // Colossal hack
						memState.setValue("FS", (i + 2) * 0x8);
					}
				}
				else {
					useKey = (vals.size() > 1) ? key + i : key;
				}
				Register register = language.getRegister(useKey);
				if (register == null) {
					useKey = useKey.toUpperCase();
					register = language.getRegister(useKey);
				}
				if (register != null) {
					if (restore && !register.getAddress().isRegisterAddress()) {
						continue; // only restore registers within register space
					}
					byte[] valBytes = vals.get(i);
					boolean initializedValue = initiailizedVals.get(i);

					Address regAddr = register.getAddress();

					if (restore) {
						byte[] curVal = new byte[valBytes.length];
						memState.getChunk(curVal, regAddr.getAddressSpace(), regAddr.getOffset(),
							register.getMinimumByteSize(), false);
						if (Arrays.equals(curVal, valBytes)) {
							continue;
						}
                        /*
						System.out.println(
							"resetRegisters : " + useKey + "=" + dumpBytesAsSingleValue(valBytes) +
								"->" + dumpBytesAsSingleValue(curVal));
                        */
					}

					memState.setChunk(valBytes, regAddr.getAddressSpace(), regAddr.getOffset(),
						register.getMinimumByteSize());

					if (!initializedValue) {
						memState.setInitialized(false, regAddr.getAddressSpace(),
							regAddr.getOffset(), register.getMinimumByteSize());
					}

					if (register.isProgramCounter() ||
						register.getName().equalsIgnoreCase(pcName)) {
						initialPC = conv.getValue(valBytes, valBytes.length);
					}
				}
			}
		}
	}

    public FilteredMemoryPageOverlay getMemoryBank(AddressSpace space, int ps) {
		MemoryImage image =
			new MemoryImage(space, language.isBigEndian(), ps, loadImage, faultHandler);
		return new FilteredMemoryPageOverlay(space, image, writeBack);
	}

    /**
	 * Get the page size to use with a specific AddressSpace. The page containers (MemoryBank)
	 * assume page size is always power of 2. Any address space is assigned at least 8-bits of
	 * addressable locations, so at the very least, the size is divisible by 256. Starting with this
	 * minimum, this method finds the power of 2 that is closest to the preferred page size (pageSize)
	 * but that still divides the size of the space.
	 * @param space is the specific AddressSpace
	 * @return the page size to use
	 */
	private int getValidPageSize(AddressSpace space) {
		int ps = 256;	// Minimum page size supported
		long spaceSize = space.getMaxAddress().getOffset() + 1;	// Number of bytes in the space (0 if 2^64 bytes)
		if ((spaceSize & 0xff) != 0) {
			Msg.warn(this, "Emulator using page size of 256 bytes for " + space.getName() +
				" which is NOT a multiple of 256");
			return ps;
		}
		spaceSize >>>= 8;	// Divide required size by 256 (evenly)
		while (ps < pageSize) {	// If current page size is smaller than preferred page size
			if ((spaceSize & 1) != 0) {
				break;			// a bigger page size does not divide the space size evenly, so use current size
			}
			ps <<= 1;	// Bump up current page size to next power of 2
			spaceSize >>>= 1;	// Divide (evenly) by 2
		}

		return ps;
	}

    public JitEmulator(EmulatorConfiguration config) {

        this.faultHandler = config.getMemoryFaultHandler();

        pcName = config.getProgramCounterName();
        writeBack = config.isWriteBackEnabled();
        pageSize = config.getPreferredMemoryPageSize();

        Language lang = config.getLanguage();
		if (!(lang instanceof SleighLanguage)) {
			throw new IllegalArgumentException("Invalid configuartion language [" +
				lang.getLanguageID() + "]: only Sleigh languages are supported by emulator");
		}

        language = (SleighLanguage) lang;
        addrFactory = lang.getAddressFactory();

        EmulatorLoadData load = config.getLoadData();
		loadImage.addProvider(load.getMemoryLoadImage(), load.getView());
		registerState = load.getInitialRegisterState();

        initMemState(registerState);

        emulate = new JitEmulate(language, memState);
    }

    public void run(Address entry) {
        emulate.run(entry);
    }

    public void call(Address entry) {
        try {
            run(entry);
        } catch (PcodeOpReturnException e) {
        }
    }
}

