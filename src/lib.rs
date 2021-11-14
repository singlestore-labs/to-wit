extern crate libc;

use anyhow::{anyhow, Result};
use core::slice;
use core::slice::Iter;
use core::iter::Iterator;
use libc::c_char;
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::ptr;
use std::rc::Rc;
use std::str;
use parser::TypeDefKind;
use parser::abi;
use parser::{Interface, Field, Type, SizeAlign};

thread_local! {
    pub static LAST_ERR: RefCell<Option<WAIError>> = RefCell::new(None);
}

//////////////////////////////////////////////////////////////////////////
//
// WasmType
//
//////////////////////////////////////////////////////////////////////////

#[allow(non_camel_case_types)]
#[repr(C)]
pub enum WASMType {
    I32,
    I64,
    F32,
    F64,
}
impl From<abi::WasmType> for WASMType {
    fn from(t: abi::WasmType) -> Self {
        match t {
            abi::WasmType::I32 => WASMType::I32,
            abi::WasmType::I64 => WASMType::I64,
            abi::WasmType::F32 => WASMType::F32,
            abi::WasmType::F64 => WASMType::F64,
        }
    }
}

//////////////////////////////////////////////////////////////////////////
//
// WasmSignature
//
//////////////////////////////////////////////////////////////////////////

pub struct WAI {
    iface: Rc<Interface>,
    funcs: HashMap<String, WAIFunction>,    // Function name to index
    align: Rc<SizeAlign>
}
impl<'a> WAI {
    fn new(wai: &str) -> Result<WAI> {
        let iface = Rc::new(Interface::parse("wai", &wai)?);
        let mut align = SizeAlign::default();
        align.fill(abi::AbiVariant::GuestExport, &iface);
        Ok(
            WAI { 
                iface,
                funcs: HashMap::new(),
                align: Rc::new(align)
            }
        )
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub enum WAISigPart {
    Params,
    Results,
    RetPtr
}

pub struct WAISignature {
    sig: abi::WasmSignature,
}

pub struct WAIFunction {
    iface: Rc<Interface>,
    align: Rc<SizeAlign>,
    name:  CString,
    sig:   WAISignature,
    index: usize,  // function index
}

pub struct WAITypeDefIter<'a> {
    iface:       Rc<Interface>,
    align:       Rc<SizeAlign>,
    inner_iter:  Iter<'a, (String, Type)>,
    item:        Option<WAITypeDef<'a>>
}

pub struct WAIFieldIter<'a> {
    iface:       Rc<Interface>,
    align:       Rc<SizeAlign>,
    inner_iter:  Iter<'a, Field>,
    item:        Option<WAITypeDef<'a>>
}

pub struct WAITypeDef<'a> {
    iface:       Rc<Interface>,
    align:       Rc<SizeAlign>,
    name:        CString,
    ty:          &'a Type,
    subty:       Option<Box<WAITypeDef<'a>>>,
    //align:       usize
}

#[allow(non_camel_case_types)]
#[derive(PartialEq)]
#[repr(C)]
pub enum WAIType {
    U8,
    U16,
    U32,
    U64,
    S8,
    S16,
    S32,
    S64,
    F32,
    F64,
    Char,
    CChar,
    Usize,
    Record,
    List,
    Unknown
}

pub struct WAIError {
    c_msg: CString
}

//////////////////////////////////////////////////////////////////////////

#[no_mangle]
pub extern "C" fn wai_error_get() -> *const c_char {
    LAST_ERR.with(
        |e| 
        match &*e.borrow()
        {
            Some(e) => e.c_msg.as_ptr(),
            _ => ptr::null()
        }
    )
}

fn error_set(err: anyhow::Error) -> bool { 
    let err_res = CString::new(err.to_string());
    match err_res {
        Ok(msg) => 
        {
            LAST_ERR.with(
                |e| 
                e.replace(
                    Some(
                        WAIError{ 
                            c_msg: msg
                        }
                    )
                )
            );
            true
        },
        Err(_) =>
            false
        }
}

// Checks the result for an error.  If present, sets the thread-local
// error slot and returns false.  If no error, true is returned.
fn check(r: Result<()>) -> bool {
    if let Err(err) = r {
        error_set(err);
        false
    } else {
        true
    }
}

#[no_mangle]
pub extern "C" fn wai_parse(content: *const u8, len: usize, res: *mut *mut WAI) -> bool {
    check(_wai_parse(content, len, res))
}
fn _wai_parse(content: *const u8, len: usize, res: *mut *mut WAI) -> Result<()> {
    if content.is_null() || res.is_null() {
        return Err(anyhow!("Invalid arguments"))
    }
    let content = unsafe {
        str::from_utf8(slice::from_raw_parts(content, len))?
    };

    // Extract the WASM signature for each function.
    let mut safe_res = WAI::new(content)?;

    // Create a map of each function's name to its index into the interface.
    let funcs = &safe_res.iface.functions;
    for i in 0..funcs.len() {
        let sig = WAISignature {
            sig: safe_res.iface.wasm_signature(abi::AbiVariant::GuestExport, &funcs[i]),
        };
        safe_res.funcs.insert(
            funcs[i].name.clone(), 
            WAIFunction {
                iface: safe_res.iface.clone(),
                align: safe_res.align.clone(),
                name:  CString::new(funcs[i].name.as_str())?,
                sig,
                index: i,
            }
        );
    }

    let safe_res = Box::into_raw(Box::new(safe_res));
    unsafe {
        *res = safe_res;
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn wai_delete(wai: *mut WAI) {
    if wai.is_null() {
        return;
    }
    unsafe {
        Box::from_raw(wai);
    }
}

#[no_mangle]
pub extern "C" fn wai_func_name_get(func: *const WAIFunction, res: *mut *const c_char) -> bool {
    check(_wai_func_name_get(func, res))
}
fn _wai_func_name_get(func: *const WAIFunction, res: *mut *const c_char) -> Result<()> {
    if func.is_null() || res.is_null() {
        return Err(anyhow!("Invalid arguments"))
    }
    let func = unsafe {
        &*func
    };
    unsafe {
        *res = func.name.as_ptr();
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn wai_func_count_get(wai: *const WAI, res: *mut usize) -> bool {
    check(_wai_func_count_get(wai, res))
}
fn _wai_func_count_get(wai: *const WAI, res: *mut usize) -> Result<()> {
    if wai.is_null() || res.is_null() {
        return Err(anyhow!("Invalid arguments"))
    }
    let wai  = unsafe {
        &*wai
    };
    unsafe {
        *res = wai.iface.functions.len();
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn wai_func_get_by_index(wai: *const WAI, index: usize, res: *mut *const WAIFunction) -> bool {
    check(_wai_func_get_by_index(wai, index, res))
}
fn _wai_func_get_by_index(wai: *const WAI, index: usize, res: *mut *const WAIFunction) -> Result<()> {
    if wai.is_null() || res.is_null() {
        return Err(anyhow!("Invalid arguments"))
    }
    let wai  = unsafe {
        &*wai
    };
    let name = &wai.iface.functions[index].name;
    let func = wai.funcs.get(name);
    if let Some(func) = func {
        unsafe {
            *res = func as *const WAIFunction;
        }
        Ok(())
    } else {
        Err(anyhow!("Function `{}` not found", &name))
    }
}

#[no_mangle]
pub extern "C" fn wai_func_get_by_name(wai: *const WAI, fname: *const c_char, res: *mut *const WAIFunction) -> bool {
    check(_wai_func_get_by_name(wai, fname, res))
}
fn _wai_func_get_by_name(wai: *const WAI, fname: *const c_char, res: *mut *const WAIFunction) -> Result<()> {
    if wai.is_null() || fname.is_null() || res.is_null() {
        return Err(anyhow!("Invalid arguments"))
    }
    let wai  = unsafe {
        &*wai
    };
    let fname = unsafe {
        CStr::from_ptr(fname)
    };
    let fname_str = fname.to_str()?;
    if let Some(func) = wai.funcs.get(&fname_str.to_string()) {
        unsafe {
            *res = func as *const WAIFunction;
        }
        Ok(())
    } else {
        Err(anyhow!("Function `{}` not found", &fname_str))
    }
}

#[no_mangle]
pub extern "C" fn wai_func_param_walk<'a>(func: *const WAIFunction, res: *mut *mut WAITypeDefIter<'a>) -> bool {
    check(_wai_func_param_walk(func, res))
}
fn _wai_func_param_walk<'a>(func: *const WAIFunction, res: *mut *mut WAITypeDefIter<'a>) -> Result<()> {
    func_typedef_walk(func, false, res)
}

#[no_mangle]
pub extern "C" fn wai_func_result_walk<'a>(func: *const WAIFunction, res: *mut *mut WAITypeDefIter<'a>) -> bool {
    check(_wai_func_result_walk(func, res))
}
fn _wai_func_result_walk<'a>(func: *const WAIFunction, res: *mut *mut WAITypeDefIter<'a>) -> Result<()> {
    func_typedef_walk(func, true, res)
}

// Helper for the above two functions.
fn func_typedef_walk<'a> (func: *const WAIFunction, is_result: bool, res: *mut *mut WAITypeDefIter<'a>) -> Result<()> {
    if func.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let func  = unsafe {
        &*func
    };
    let mut inner_iter = {
        if is_result {
            func.iface.functions[func.index].results.iter()
        } else {
            func.iface.functions[func.index].params.iter()
        }
    };
    let next = inner_iter.next();
    let item: Option<WAITypeDef> = match next {
        Some(n) => {
            Some(
                WAITypeDef{ 
                    iface: func.iface.clone(), 
                    align: func.align.clone(),
                    name:  CString::new(n.0.as_str())?,
                    ty:    &n.1,
                    subty: subtypedef_get_maybe(&func.iface, &func.align, &n.1)?,
                }
            )
        },
        _ => None
    };
    let res_safe = 
        Box::into_raw(
            Box::new(
                WAITypeDefIter {
                    iface:      func.iface.clone(),
                    align:      func.align.clone(),
                    inner_iter,
                    item,
                }
            )
        );
    unsafe {
        *res = res_safe;
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn wai_typedef_iter_off(iter: *const WAITypeDefIter) -> bool {
    if iter.is_null() {
        return true;
    }
    let iter = unsafe {
        &*iter
    };
    iter.item.is_none()
}

#[no_mangle]
pub extern "C" fn wai_typedef_iter_next(iter: *mut WAITypeDefIter) -> bool {
    check(_wai_typedef_iter_next(iter))
}
fn _wai_typedef_iter_next(iter: *mut WAITypeDefIter) -> Result<()> {
    if iter.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    if wai_typedef_iter_off(iter) {
        return Err(anyhow!("Iterator out of bounds!"));
    }
    let iter = unsafe {
        &mut *iter
    };
    let next = iter.inner_iter.next();
    iter.item = {
        if let Some(next) = next {
            Some(
                WAITypeDef{ 
                    iface: iter.iface.clone(), 
                    align: iter.align.clone(),
                    name:  CString::new(next.0.as_str())?, 
                    ty:    &next.1,
                    subty: subtypedef_get_maybe(&iter.iface, &iter.align, &next.1)?
                }
            )
        } else {
            None
        }
    };
    Ok(())
}

fn subtypedef_get_maybe<'a>(iface: &'a Rc<Interface>, align: &'a Rc<SizeAlign>, ty: &'a Type) 
    -> Result<Option<Box<WAITypeDef<'a>>>> 
{
    if let Type::Id(id) = ty {
        if let TypeDefKind::List(subty) = &iface.types[*id].kind {
            Ok(
                Some(
                    Box::new(
                        WAITypeDef {
                            iface: iface.clone(),
                            align: align.clone(),
                            name:  CString::new("").unwrap(),
                            ty:    &subty,
                            subty: subtypedef_get_maybe(iface, align, &subty)?
                        }
                    )
                )
            )
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

#[no_mangle]
pub extern "C" fn wai_typedef_iter_at<'a>(iter: *const WAITypeDefIter<'a>, res: *mut *const WAITypeDef<'a>) -> bool {
    check(_wai_typedef_iter_at(iter, res))
}
fn _wai_typedef_iter_at<'a>(iter: *const WAITypeDefIter<'a>, res: *mut *const WAITypeDef<'a>) -> Result<()> {
    if iter.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let iter = unsafe {
        &*iter
    };
    if let Some(item) = &iter.item {
        unsafe {
            *res = item as *const WAITypeDef;
        }
        Ok(())
    } else {
        Err(anyhow!("Iterator out of bounds!"))
    }
}

#[no_mangle]
pub extern "C" fn wai_typedef_iter_delete(iter: *mut WAITypeDefIter) {
    if !iter.is_null() {
        unsafe {
            Box::from_raw(iter);
        }
    }
}

#[no_mangle]
pub extern "C" fn wai_record_field_walk<'a>(td: *const WAITypeDef<'a>, res: *mut *mut WAIFieldIter<'a>) -> bool {
    check(_wai_record_field_walk(td, res))
}
fn _wai_record_field_walk<'a>(td: *const WAITypeDef<'a>, res: *mut *mut WAIFieldIter<'a>) -> Result<()> {
    if td.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let td = unsafe {
        &*td
    };
    if let Type::Id(id) = &td.ty {
        if let TypeDefKind::Record(rec) = &td.iface.types[*id].kind {
            let mut inner_iter = rec.fields.iter();
            let next = inner_iter.next();
            let item: Option<WAITypeDef> = match next {
                Some(f) => 
                    Some(
                        WAITypeDef{ 
                            iface: td.iface.clone(), 
                            align: td.align.clone(),
                            name:  CString::new(f.name.as_str())?, 
                            ty:    &f.ty,
                            subty: subtypedef_get_maybe(&td.iface, &td.align, &f.ty)?
                        }
                    ),
                _ => None
            };
            let safe_res = 
                Box::into_raw(
                    Box::new(
                        WAIFieldIter {
                            iface:      td.iface.clone(),
                            align:      td.align.clone(),
                            inner_iter,
                            item
                        }
                    )
                );
            unsafe {
                *res = safe_res;
            }
            Ok(())
        } else {
            Err(anyhow!("Invalid parameter.  Must be record type!"))
        }
    } else {
        Err(anyhow!("Iterator out of bounds!"))
    }
}

#[no_mangle]
pub extern "C" fn wai_field_iter_off(iter: *const WAIFieldIter) -> bool {
    if iter.is_null() {
        return true;
    }
    let iter = unsafe {
        &*iter
    };
    iter.item.is_none()
}

#[no_mangle]
pub extern "C" fn wai_field_iter_next(iter: *mut WAIFieldIter) -> bool {
    check(_wai_field_iter_next(iter))
}
fn _wai_field_iter_next(iter: *mut WAIFieldIter) -> Result<()> {
    if iter.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    if wai_field_iter_off(iter) {
        return Err(anyhow!("Iterator out of bounds"));
    }
    let iter = unsafe {
        &mut *iter
    };
    let next = iter.inner_iter.next();
    iter.item = {
        if let Some(next) = next {
            Some(
                WAITypeDef{ 
                    iface: iter.iface.clone(), 
                    align: iter.align.clone(),
                    name:  CString::new(next.name.as_str())?,
                    ty:    &next.ty,
                    subty: subtypedef_get_maybe(&iter.iface, &iter.align, &next.ty)?
                }
            )
        } else {
            None
        }
    };
    Ok(())
}

#[no_mangle]
pub extern "C" fn wai_field_iter_at<'a>(iter: *const WAIFieldIter<'a>, res: *mut *const WAITypeDef<'a>) -> bool {
    check(_wai_field_iter_at(iter, res))
}
fn _wai_field_iter_at<'a>(iter: *const WAIFieldIter<'a>, res: *mut *const WAITypeDef<'a>) -> Result<()> {
    if iter.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let iter = unsafe {
        &*iter
    };
    if let Some(item) = &iter.item {
        unsafe {
            *res = item as *const WAITypeDef;
            Ok(())
        }
    } else {
        Err(anyhow!("Iterator out of bounds!"))
    }
}

#[no_mangle]
pub extern "C" fn wai_field_iter_delete(iter: *mut WAIFieldIter) {
    if !iter.is_null() {
        unsafe {
            Box::from_raw(iter);
        }
    }
}

#[no_mangle]
pub extern "C" fn wai_array_elem_typedef_get<'a>(td: *const WAITypeDef<'a>, res: *mut *const WAITypeDef<'a>) -> bool {
    check(_wai_array_elem_typedef_get(td, res))
}
fn _wai_array_elem_typedef_get<'a>(td: *const WAITypeDef<'a>, res: *mut *const WAITypeDef<'a>) -> Result<()> {
    if td.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let td = unsafe {
        &*td
    };
    if let Type::Id(id) = &td.ty {
        if let TypeDefKind::List(_) = &td.iface.types[*id].kind {
            // Return cached subtype, if it exists.
            match &td.subty {
                Some(subty) => {
                    unsafe {
                        *res = &**subty as *const WAITypeDef;
                    }
                    Ok(())
                },
                _ => {
                    Err(anyhow!("Could not determine array element type!"))
                }
            }
        } else {
            Err(anyhow!("Invalid parameter.  Must be list type!"))
        }
    } else {
        Err(anyhow!("Invalid parameter.  Must be list type!"))
    }
}

#[no_mangle]
pub extern "C" fn wai_typedef_name_get(td: *const WAITypeDef, res: *mut *const c_char) -> bool {
    check(_wai_typedef_name_get(td, res))
}
fn _wai_typedef_name_get(td: *const WAITypeDef, res: *mut *const c_char) -> Result<()> {
    if td.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let td = unsafe {
        &*td
    };
    unsafe {
        *res = td.name.as_ptr()
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn wai_typedef_align_get(td: *const WAITypeDef, res: *mut usize) -> bool {
    check(_wai_typedef_align_get(td, res))
}
fn _wai_typedef_align_get(td: *const WAITypeDef, res: *mut usize) -> Result<()> {
    if td.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let td = unsafe {
        &*td
    };
    let a = td.align.align(&td.ty);
    unsafe {
        *res = a;
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn wai_typedef_type_get(td: *const WAITypeDef, res: *mut WAIType) -> bool {
    check(_wai_typedef_type_get(td, res))
}
fn _wai_typedef_type_get(td: *const WAITypeDef, res: *mut WAIType) -> Result<()> {
    if td.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let td = unsafe {
        &*td
    };
    let ty = 
        match td.ty {
            Type::U8 => WAIType::U8,
            Type::U16 => WAIType::U16,
            Type::U32 => WAIType::U32,
            Type::U64 => WAIType::U64,
            Type::S8 => WAIType::S8,
            Type::S16 => WAIType::S16,
            Type::S32 => WAIType::S32,
            Type::S64 => WAIType::S64,
            Type::F32 => WAIType::F32,
            Type::F64 => WAIType::F64,
            Type::Char => WAIType::Char,
            Type::CChar => WAIType::CChar,
            Type::Usize => WAIType::Usize,
            Type::Handle(_) => WAIType::Unknown,  // Unsupported for now
            Type::Id(id) => {
                // Looking for a list or record type.
                match td.iface.types[*id].kind {
                    TypeDefKind::Record(_) => WAIType::Record,
                    TypeDefKind::List(_) => WAIType::List,
                    _ => WAIType::Unknown
                }
            },
        };
    if ty == WAIType::Unknown {
        return Err(anyhow!("Unsupported type"));
    }
    unsafe {
        *res = ty;
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn wai_func_sig_get(func: *const WAIFunction, res: *mut *const WAISignature) -> bool {
    check(_wai_func_sig_get(func, res))
}
fn _wai_func_sig_get(func: *const WAIFunction, res: *mut *const WAISignature) -> Result<()> {
    if func.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let func  = unsafe {
        &*func
    };
    unsafe {
        *res = &func.sig as *const WAISignature; 
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn wai_sig_length_get(sig: *const WAISignature, part: WAISigPart, res: *mut usize) -> bool {
    check(_wai_sig_length_get(sig, part, res))
}
fn _wai_sig_length_get(sig: *const WAISignature, part: WAISigPart, res: *mut usize) -> Result<()> {
    if sig.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let sig  = unsafe {
        &*sig
    };
    let len =
        match part {
            WAISigPart::Params  => sig.sig.params.len(),
            WAISigPart::Results => sig.sig.results.len(),
            WAISigPart::RetPtr  => 
                match &sig.sig.retptr {
                    Some(retptr) => retptr.len(),
                    _ => 0
                }
        };
    unsafe { 
        *res = len; 
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn wai_sig_type_get_by_index(sig: *const WAISignature, part: WAISigPart, idx: usize, res: *mut WASMType) -> bool {
    check(_wai_sig_type_get_by_index(sig, part, idx, res))
}
fn _wai_sig_type_get_by_index(sig: *const WAISignature, part: WAISigPart, idx: usize, res: *mut WASMType) -> Result<()> {
    if sig.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let sig  = unsafe {
        &*sig
    };
    let v = 
        match part {
            WAISigPart::Params => &sig.sig.params,
            WAISigPart::Results => &sig.sig.results,
            WAISigPart::RetPtr => 
                match &sig.sig.retptr {
                    Some(retptr) => retptr,
                    _ => panic!("retptr has 0 elements!")
                }
        };
    unsafe { 
        *res = From::from(v[idx]);
    }
    Ok(())
}

