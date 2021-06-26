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

use crate::bridge::ffi;
use crate::model::Address;
use cxx::{let_cxx_string, CxxString, UniquePtr};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::pin::Pin;

#[derive(Debug, Serialize, Deserialize)]
pub struct Patches {
    #[serde(rename = "patch")]
    patches: Vec<Patch>,
    #[serde(skip)]
    #[serde(default = "std::ptr::null_mut")]
    arch: *mut ffi::Architecture,
}

impl Patches {
    pub(crate) fn new(arch: *mut ffi::Architecture) -> Self {
        Self {
            patches: Vec::new(),
            arch,
        }
    }

    pub(crate) fn add_patch(&mut self, space: &CxxString, offset: usize, payload: &CxxString) {
        let space = space.to_string();
        let payload = payload.to_string();

        self.patches.push(Patch {
            addr: Address { space, offset },
            payload,
        })
    }

    fn space_id_by_name(&self, name: &str) -> *mut ffi::AddrSpace {
        let addr_manager = unsafe { self.arch.as_ref().unwrap().getAddrSpaceManager() };
        let_cxx_string!(space = name);
        let space = addr_manager.getSpaceByName(&space);
        space
    }

    // parses (space, offset, size) into varnode data
    fn parse_varnode_data(&self, s: &str) -> UniquePtr<ffi::VarnodeData> {
        let s = s.trim().trim_matches(|c| c == '(' || c == ')');
        let parts: Vec<_> = s.split(",").collect();
        let space = parts[0];
        let offset = parse_int::parse(parts[1]).unwrap();
        let size = parse_int::parse(parts[2]).unwrap();

        if space == "null" {
            return UniquePtr::null();
        }

        let space = self.space_id_by_name(&space);

        unsafe { ffi::new_varnode_data(space, offset, size) }
    }

    pub(crate) fn resolve_patch(
        &self,
        addr: &ffi::Address,
        emit: *mut ffi::PcodeEmit,
    ) -> bool {
        let patch = self
            .patches
            .iter()
            .filter(|patch| {
                let space_name = unsafe { addr.getSpace().as_ref().unwrap().getName().to_string() };
                space_name == patch.addr.space && addr.getOffset() == patch.addr.offset
            })
            .next();
        let patch = match patch {
            Some(p) => p,
            None => return false,
        };

        let space = self.space_id_by_name(&patch.addr.space);
        let addr = unsafe { ffi::new_address(space, patch.addr.offset) };

        for payload in patch.payload.split("\n").into_iter() {

            if payload.trim().len() == 0 {
                continue;
            }

            let (lhs, rest) = if payload.find(" = ").is_some() {
                let parts: Vec<_> = payload.split(" = ").collect();

                let lhs = self.parse_varnode_data(&parts[0]);

                (lhs, parts[1])
            } else {
                (UniquePtr::null(), payload)
            };

            
            let opcode = rest.split(" ").next().unwrap();
            let_cxx_string!(opcode = opcode);

            let opcode = ffi::get_opcode(&opcode);

            let mut inputs = vec![];
            let input_str: Vec<_> = rest.split(" ").collect();
            let input_str = input_str[1..].join("");

            for input_varnode in input_str.split("),").into_iter() {

                if input_varnode.trim().len() == 0 {
                    continue
                }

                unsafe {
                    inputs.push(self.parse_varnode_data(input_varnode));
                }
            }

            unsafe {
                ffi::dump_rust(
                    emit,
                    addr.as_ref().unwrap(),
                    opcode,
                    lhs,
                    &inputs,
                    inputs.len().try_into().unwrap(),
                );
            }
        }

        true
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "patch")]
pub struct Patch {
    addr: Address,
    payload: String,
}

#[test]
fn test_parse_patch() {
    let s = r#"
    <patches>
    <patch>
  <addr space="ram" offset="0x2069ef"/>
  <payload><![CDATA[
(register, 0x206, 1) = COPY (const, 0x1, 1)
CBRANCH (ram, 0x2075ba, 8), (register, 0x206, 1)
]]></payload>
</patch>
<patch>
  <addr space="ram" offset="0x2075ff"/>
  <payload><![CDATA[
CBRANCH (ram, 0x2077ce, 8), (register, 0x206, 1)
BRANCH (ram, 0x20782d, 8)
]]></payload>
</patch>
<patch>
  <addr space="ram" offset="0x2077d5"/>
  <payload><![CDATA[
CBRANCH (ram, 0x2070fc, 8), (register, 0x206, 1)
BRANCH (ram, 0x206fdf, 8)
]]></payload>
</patch>
<patch>
  <addr space="ram" offset="0x207035"/>
  <payload><![CDATA[
CBRANCH (ram, 0x2074f5, 8), (register, 0x206, 1)
BRANCH (ram, 0x2074b5, 8)
]]></payload>
</patch>
<patch>
  <addr space="ram" offset="0x2074fe"/>
  <payload><![CDATA[
CBRANCH (ram, 0x20796b, 8), (register, 0x206, 1)
BRANCH (ram, 0x206bf9, 8)
]]></payload>
</patch>
<patch>
  <addr space="ram" offset="0x206c7e"/>
  <payload><![CDATA[
CBRANCH (ram, 0x20706a, 8), (register, 0x206, 1)
BRANCH (ram, 0x206fd9, 8)
]]></payload>
</patch>
<patch>
  <addr space="ram" offset="0x207073"/>
  <payload><![CDATA[
CBRANCH (ram, 0x207171, 8), (register, 0x206, 1)
BRANCH (ram, 0x206a0c, 8)
]]></payload>
</patch>
<patch>
  <addr space="ram" offset="0x206a1b"/>
  <payload><![CDATA[
CBRANCH (ram, 0x206eaa, 8), (register, 0x206, 1)
BRANCH (ram, 0x2073ca, 8)
]]></payload>
</patch>
<patch>
  <addr space="ram" offset="0x206ef9"/>
  <payload><![CDATA[
CBRANCH (ram, 0x206efb, 8), (register, 0x206, 1)
BRANCH (ram, 0x206ed1, 8)
]]></payload>
</patch>
<patch>
  <addr space="ram" offset="0x206f0a"/>
  <payload><![CDATA[
CBRANCH (ram, 0x207093, 8), (register, 0x206, 1)
BRANCH (ram, 0x206cf6, 8)
]]></payload>
</patch>
<patch>
  <addr space="ram" offset="0x206d09"/>
  <payload><![CDATA[
CBRANCH (ram, 0x206acd, 8), (register, 0x206, 1)
BRANCH (ram, 0x206b87, 8)
]]></payload>
</patch>
<patch>
  <addr space="ram" offset="0x2070df"/>
  <payload><![CDATA[
CBRANCH (ram, 0x206efb, 8), (register, 0x206, 1)
BRANCH (ram, 0x206e10, 8)
]]></payload>
</patch>
<patch>
  <addr space="ram" offset="0x207185"/>
  <payload><![CDATA[
CBRANCH (ram, 0x207940, 8), (register, 0x206, 1)
BRANCH (ram, 0x2072bb, 8)
]]></payload>
</patch>
<patch>
  <addr space="ram" offset="0x2072dd"/>
  <payload><![CDATA[
CBRANCH (ram, 0x206a0c, 8), (register, 0x206, 1)
BRANCH (ram, 0x20696e, 8)
]]></payload>
</patch>
<patch>
  <addr space="ram" offset="0x207969"/>
  <payload><![CDATA[
CBRANCH (ram, 0x20706a, 8), (register, 0x206, 1)
BRANCH (ram, 0x2070ee, 8)
]]></payload>
</patch>
<patch>
  <addr space="ram" offset="0x20716f"/>
  <payload><![CDATA[
CBRANCH (ram, 0x207774, 8), (register, 0x206, 1)
BRANCH (ram, 0x207544, 8)
]]></payload>
</patch>
<patch>
  <addr space="ram" offset="0x20754c"/>
  <payload><![CDATA[
CBRANCH (ram, 0x2079a4, 8), (register, 0x206, 1)
BRANCH (ram, 0x206c80, 8)
]]></payload>
</patch>
<patch>
  <addr space="ram" offset="0x206c88"/>
  <payload><![CDATA[
CBRANCH (ram, 0x207187, 8), (register, 0x206, 1)
BRANCH (ram, 0x206f32, 8)
]]></payload>
</patch>
<patch>
  <addr space="ram" offset="0x206f3a"/>
  <payload><![CDATA[
CBRANCH (ram, 0x207851, 8), (register, 0x206, 1)
BRANCH (ram, 0x206b2a, 8)
]]></payload>
</patch>
<patch>
  <addr space="ram" offset="0x206b40"/>
  <payload><![CDATA[
CBRANCH (ram, 0x2077ce, 8), (register, 0x206, 1)
BRANCH (ram, 0x207778, 8)
]]></payload>
</patch>
<patch>
  <addr space="ram" offset="0x207799"/>
  <payload><![CDATA[
CBRANCH (ram, 0x207544, 8), (register, 0x206, 1)
BRANCH (ram, 0x207634, 8)
]]></payload>
</patch>
<patch>
  <addr space="ram" offset="0x207879"/>
  <payload><![CDATA[
CBRANCH (ram, 0x206b2a, 8), (register, 0x206, 1)
BRANCH (ram, 0x206ab2, 8)
]]></payload>
</patch>
<patch>
  <addr space="ram" offset="0x2071a9"/>
  <payload><![CDATA[
CBRANCH (ram, 0x206f32, 8), (register, 0x206, 1)
BRANCH (ram, 0x206e5b, 8)
]]></payload>
</patch>
<patch>
  <addr space="ram" offset="0x2079c5"/>
  <payload><![CDATA[
CBRANCH (ram, 0x206c80, 8), (register, 0x206, 1)
BRANCH (ram, 0x206c70, 8)
]]></payload>
</patch>
<patch>
  <addr space="ram" offset="0x2079a2"/>
  <payload><![CDATA[
CBRANCH (ram, 0x2074f5, 8), (register, 0x206, 1)
BRANCH (ram, 0x207555, 8)
]]></payload>
</patch>
</patches>
    "#;
    use serde_xml_rs::from_str;

    let patches: Patches = from_str(s).unwrap();
    println!("{:?}", patches);
}