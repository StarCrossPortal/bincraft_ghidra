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

import com.oracle.truffle.api.instrumentation.ProvidedTags;
import com.oracle.truffle.api.instrumentation.StandardTags;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.memstate.MemoryState;

import com.oracle.truffle.api.TruffleLanguage;

@ProvidedTags({ StandardTags.StatementTag.class })
@TruffleLanguage.Registration(
    id = PcodeOpLanguage.ID,
    name = "PcodeOp",
    defaultMimeType = PcodeOpLanguage.MIME_TYPE,
    characterMimeTypes = PcodeOpLanguage.MIME_TYPE,
    contextPolicy = TruffleLanguage.ContextPolicy.SHARED
)
public class PcodeOpLanguage extends TruffleLanguage<PcodeOpContext> {
    public static final String ID = "pcode";
    public static final String MIME_TYPE = "application/x-pcode";

    private static MemoryState state;
    private static SleighLanguage lang;

    public static void setMmeoryState(MemoryState state) {
        PcodeOpLanguage.state = state;
    }

    public static void setSleighLanguage(SleighLanguage lang) {
        PcodeOpLanguage.lang = lang;
    }

    @Override
    protected PcodeOpContext createContext(Env env) {
        return new PcodeOpContext(this, env, lang, state);
    }
}
