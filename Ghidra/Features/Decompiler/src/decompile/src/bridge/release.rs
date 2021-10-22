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
use super::{Patches, new_patches};

#[cxx::bridge]
pub(crate) mod ffi {
    
    extern "Rust" {
        type Patches;
        unsafe fn new_patches(arch: *mut Architecture) -> Box<Patches>;
        fn add_patch(self: &mut Patches, space: &CxxString, offset: u64, size: i32, payload: &CxxString);
        unsafe fn resolve_patch(self: &Patches, addr: &Address, emit: *mut PcodeEmit) -> i32;
    }

    unsafe extern "C++" {
        include!("fspec.hh");
        include!("varnode.hh");
        include!("pcoderaw.hh");
        include!("architecture.hh");
        include!("space.hh");
        include!("address.hh");
        include!("translate.hh");
        include!("libdecomp.hh");
        include!("interface.hh");
        include!("consolemain.hh");
        include!("ifacedecomp.hh");
        include!("ruststream.hh");
        include!("ghidra_process.hh");

        type OpCode = pcodecraft::OpCode;
        type Address;
        type AddrSpace;
        type VarnodeData;
        type AddrSpaceManager;
        type Architecture;
        type PcodeEmit;
        type StreamReader;

        fn ghidra_process_main();

        fn getName(self: &AddrSpace) -> &CxxString;

        unsafe fn new_address(space: *mut AddrSpace, off: u64) -> UniquePtr<Address>;
        fn getSpace(self: &Address) -> *mut AddrSpace;
        fn getOffset(self: &Address) -> u64;

        unsafe fn new_varnode_data(
            space: *mut AddrSpace,
            offset: u64,
            size: u32,
        ) -> UniquePtr<VarnodeData>;

        fn getAddrSpaceManager(self: &Architecture) -> &AddrSpaceManager;

        fn getSpaceByName(self: &AddrSpaceManager, name: &CxxString) -> *mut AddrSpace;

        unsafe fn dump_rust(
            emit: *mut PcodeEmit,
            addr: &Address,
            opcode: OpCode,
            out_var: UniquePtr<VarnodeData>,
            input_vars: &[UniquePtr<VarnodeData>],
            size: i32,
        );

        fn read(self: Pin<&mut StreamReader>, buf: &mut [u8]) -> usize;

        // opcode
        fn get_opcode(s: &CxxString) -> OpCode;
    }
}
pub use ffi::*;