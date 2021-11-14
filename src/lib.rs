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
use witx2::TypeDefKind;
use witx2::abi;
use witx2::{Interface, Field, Type, SizeAlign};

thread_local! {
    pub static LAST_ERR: RefCell<Option<WITXError>> = RefCell::new(None);
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

pub struct WITX {
    iface: Rc<Interface>,
    funcs: HashMap<String, WITXFunction>,    // Function name to index
    align: Rc<SizeAlign>
}
impl<'a> WITX {
    fn new(witx: &str) -> Result<WITX> {
        let iface = Rc::new(Interface::parse("witx", &witx)?);
        let mut align = SizeAlign::default();
        align.fill(abi::Direction::Export, &iface);
        Ok(
            WITX { 
                iface,
                funcs: HashMap::new(),
                align: Rc::new(align)
            }
        )
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub enum WITXSigPart {
    Params,
    Results,
    RetPtr
}

pub struct WITXSignature {
    sig: abi::WasmSignature,
}

pub struct WITXFunction {
    iface: Rc<Interface>,
    align: Rc<SizeAlign>,
    name:  CString,
    sig:   WITXSignature,
    index: usize,  // function index
}

pub struct WITXTypeDefIter<'a> {
    iface:       Rc<Interface>,
    align:       Rc<SizeAlign>,
    inner_iter:  Iter<'a, (String, Type)>,
    item:        Option<WITXTypeDef<'a>>
}

pub struct WITXFieldIter<'a> {
    iface:       Rc<Interface>,
    align:       Rc<SizeAlign>,
    inner_iter:  Iter<'a, Field>,
    item:        Option<WITXTypeDef<'a>>
}

pub struct WITXTypeDef<'a> {
    iface:       Rc<Interface>,
    align:       Rc<SizeAlign>,
    name:        CString,
    ty:          &'a Type,
    subty:       Option<Box<WITXTypeDef<'a>>>,
    //align:       usize
}

#[allow(non_camel_case_types)]
#[derive(PartialEq)]
#[repr(C)]
pub enum WITXType {
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

pub struct WITXError {
    c_msg: CString
}

//////////////////////////////////////////////////////////////////////////

#[no_mangle]
pub extern "C" fn witx_error_get() -> *const c_char {
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
                        WITXError{ 
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
pub extern "C" fn witx_parse(content: *const u8, len: usize, res: *mut *mut WITX) -> bool {
    check(_witx_parse(content, len, res))
}
fn _witx_parse(content: *const u8, len: usize, res: *mut *mut WITX) -> Result<()> {
    if content.is_null() || res.is_null() {
        return Err(anyhow!("Invalid arguments"))
    }
    let content = unsafe {
        str::from_utf8(slice::from_raw_parts(content, len))?
    };

    // Extract the WASM signature for each function.
    let mut safe_res = WITX::new(content)?;

    // Create a map of each function's name to its index into the interface.
    let funcs = &safe_res.iface.functions;
    for i in 0..funcs.len() {
        let sig = WITXSignature {
            sig: safe_res.iface.wasm_signature(abi::Direction::Export, &funcs[i]),
        };
        safe_res.funcs.insert(
            funcs[i].name.clone(), 
            WITXFunction {
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
pub extern "C" fn witx_delete(witx: *mut WITX) {
    if witx.is_null() {
        return;
    }
    unsafe {
        Box::from_raw(witx);
    }
}

#[no_mangle]
pub extern "C" fn witx_func_name_get(func: *const WITXFunction, res: *mut *const c_char) -> bool {
    check(_witx_func_name_get(func, res))
}
fn _witx_func_name_get(func: *const WITXFunction, res: *mut *const c_char) -> Result<()> {
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
pub extern "C" fn witx_func_count_get(witx: *const WITX, res: *mut usize) -> bool {
    check(_witx_func_count_get(witx, res))
}
fn _witx_func_count_get(witx: *const WITX, res: *mut usize) -> Result<()> {
    if witx.is_null() || res.is_null() {
        return Err(anyhow!("Invalid arguments"))
    }
    let witx  = unsafe {
        &*witx
    };
    unsafe {
        *res = witx.iface.functions.len();
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn witx_func_get_by_index(witx: *const WITX, index: usize, res: *mut *const WITXFunction) -> bool {
    check(_witx_func_get_by_index(witx, index, res))
}
fn _witx_func_get_by_index(witx: *const WITX, index: usize, res: *mut *const WITXFunction) -> Result<()> {
    if witx.is_null() || res.is_null() {
        return Err(anyhow!("Invalid arguments"))
    }
    let witx  = unsafe {
        &*witx
    };
    let name = &witx.iface.functions[index].name;
    let func = witx.funcs.get(name);
    if let Some(func) = func {
        unsafe {
            *res = func as *const WITXFunction;
        }
        Ok(())
    } else {
        Err(anyhow!("Function `{}` not found", &name))
    }
}

#[no_mangle]
pub extern "C" fn witx_func_get_by_name(witx: *const WITX, fname: *const c_char, res: *mut *const WITXFunction) -> bool {
    check(_witx_func_get_by_name(witx, fname, res))
}
fn _witx_func_get_by_name(witx: *const WITX, fname: *const c_char, res: *mut *const WITXFunction) -> Result<()> {
    if witx.is_null() || fname.is_null() || res.is_null() {
        return Err(anyhow!("Invalid arguments"))
    }
    let witx  = unsafe {
        &*witx
    };
    let fname = unsafe {
        CStr::from_ptr(fname)
    };
    let fname_str = fname.to_str()?;
    if let Some(func) = witx.funcs.get(&fname_str.to_string()) {
        unsafe {
            *res = func as *const WITXFunction;
        }
        Ok(())
    } else {
        Err(anyhow!("Function `{}` not found", &fname_str))
    }
}

#[no_mangle]
pub extern "C" fn witx_func_param_walk<'a>(func: *const WITXFunction, res: *mut *mut WITXTypeDefIter<'a>) -> bool {
    check(_witx_func_param_walk(func, res))
}
fn _witx_func_param_walk<'a>(func: *const WITXFunction, res: *mut *mut WITXTypeDefIter<'a>) -> Result<()> {
    func_typedef_walk(func, false, res)
}

#[no_mangle]
pub extern "C" fn witx_func_result_walk<'a>(func: *const WITXFunction, res: *mut *mut WITXTypeDefIter<'a>) -> bool {
    check(_witx_func_result_walk(func, res))
}
fn _witx_func_result_walk<'a>(func: *const WITXFunction, res: *mut *mut WITXTypeDefIter<'a>) -> Result<()> {
    func_typedef_walk(func, true, res)
}

// Helper for the above two functions.
fn func_typedef_walk<'a> (func: *const WITXFunction, is_result: bool, res: *mut *mut WITXTypeDefIter<'a>) -> Result<()> {
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
    let item: Option<WITXTypeDef> = match next {
        Some(n) => {
            Some(
                WITXTypeDef{ 
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
                WITXTypeDefIter {
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
pub extern "C" fn witx_typedef_iter_off(iter: *const WITXTypeDefIter) -> bool {
    if iter.is_null() {
        return true;
    }
    let iter = unsafe {
        &*iter
    };
    iter.item.is_none()
}

#[no_mangle]
pub extern "C" fn witx_typedef_iter_next(iter: *mut WITXTypeDefIter) -> bool {
    check(_witx_typedef_iter_next(iter))
}
fn _witx_typedef_iter_next(iter: *mut WITXTypeDefIter) -> Result<()> {
    if iter.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    if witx_typedef_iter_off(iter) {
        return Err(anyhow!("Iterator out of bounds!"));
    }
    let iter = unsafe {
        &mut *iter
    };
    let next = iter.inner_iter.next();
    iter.item = {
        if let Some(next) = next {
            Some(
                WITXTypeDef{ 
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
    -> Result<Option<Box<WITXTypeDef<'a>>>> 
{
    if let Type::Id(id) = ty {
        if let TypeDefKind::List(subty) = &iface.types[*id].kind {
            Ok(
                Some(
                    Box::new(
                        WITXTypeDef {
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
pub extern "C" fn witx_typedef_iter_at<'a>(iter: *const WITXTypeDefIter<'a>, res: *mut *const WITXTypeDef<'a>) -> bool {
    check(_witx_typedef_iter_at(iter, res))
}
fn _witx_typedef_iter_at<'a>(iter: *const WITXTypeDefIter<'a>, res: *mut *const WITXTypeDef<'a>) -> Result<()> {
    if iter.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let iter = unsafe {
        &*iter
    };
    if let Some(item) = &iter.item {
        unsafe {
            *res = item as *const WITXTypeDef;
        }
        Ok(())
    } else {
        Err(anyhow!("Iterator out of bounds!"))
    }
}

#[no_mangle]
pub extern "C" fn witx_typedef_iter_delete(iter: *mut WITXTypeDefIter) {
    if !iter.is_null() {
        unsafe {
            Box::from_raw(iter);
        }
    }
}

#[no_mangle]
pub extern "C" fn witx_record_field_walk<'a>(td: *const WITXTypeDef<'a>, res: *mut *mut WITXFieldIter<'a>) -> bool {
    check(_witx_record_field_walk(td, res))
}
fn _witx_record_field_walk<'a>(td: *const WITXTypeDef<'a>, res: *mut *mut WITXFieldIter<'a>) -> Result<()> {
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
            let item: Option<WITXTypeDef> = match next {
                Some(f) => 
                    Some(
                        WITXTypeDef{ 
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
                        WITXFieldIter {
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
pub extern "C" fn witx_field_iter_off(iter: *const WITXFieldIter) -> bool {
    if iter.is_null() {
        return true;
    }
    let iter = unsafe {
        &*iter
    };
    iter.item.is_none()
}

#[no_mangle]
pub extern "C" fn witx_field_iter_next(iter: *mut WITXFieldIter) -> bool {
    check(_witx_field_iter_next(iter))
}
fn _witx_field_iter_next(iter: *mut WITXFieldIter) -> Result<()> {
    if iter.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    if witx_field_iter_off(iter) {
        return Err(anyhow!("Iterator out of bounds"));
    }
    let iter = unsafe {
        &mut *iter
    };
    let next = iter.inner_iter.next();
    iter.item = {
        if let Some(next) = next {
            Some(
                WITXTypeDef{ 
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
pub extern "C" fn witx_field_iter_at<'a>(iter: *const WITXFieldIter<'a>, res: *mut *const WITXTypeDef<'a>) -> bool {
    check(_witx_field_iter_at(iter, res))
}
fn _witx_field_iter_at<'a>(iter: *const WITXFieldIter<'a>, res: *mut *const WITXTypeDef<'a>) -> Result<()> {
    if iter.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let iter = unsafe {
        &*iter
    };
    if let Some(item) = &iter.item {
        unsafe {
            *res = item as *const WITXTypeDef;
            Ok(())
        }
    } else {
        Err(anyhow!("Iterator out of bounds!"))
    }
}

#[no_mangle]
pub extern "C" fn witx_field_iter_delete(iter: *mut WITXFieldIter) {
    if !iter.is_null() {
        unsafe {
            Box::from_raw(iter);
        }
    }
}

#[no_mangle]
pub extern "C" fn witx_array_elem_typedef_get<'a>(td: *const WITXTypeDef<'a>, res: *mut *const WITXTypeDef<'a>) -> bool {
    check(_witx_array_elem_typedef_get(td, res))
}
fn _witx_array_elem_typedef_get<'a>(td: *const WITXTypeDef<'a>, res: *mut *const WITXTypeDef<'a>) -> Result<()> {
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
                        *res = &**subty as *const WITXTypeDef;
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
pub extern "C" fn witx_typedef_name_get(td: *const WITXTypeDef, res: *mut *const c_char) -> bool {
    check(_witx_typedef_name_get(td, res))
}
fn _witx_typedef_name_get(td: *const WITXTypeDef, res: *mut *const c_char) -> Result<()> {
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
pub extern "C" fn witx_typedef_align_get(td: *const WITXTypeDef, res: *mut usize) -> bool {
    check(_witx_typedef_align_get(td, res))
}
fn _witx_typedef_align_get(td: *const WITXTypeDef, res: *mut usize) -> Result<()> {
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
pub extern "C" fn witx_typedef_type_get(td: *const WITXTypeDef, res: *mut WITXType) -> bool {
    check(_witx_typedef_type_get(td, res))
}
fn _witx_typedef_type_get(td: *const WITXTypeDef, res: *mut WITXType) -> Result<()> {
    if td.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let td = unsafe {
        &*td
    };
    let ty = 
        match td.ty {
            Type::U8 => WITXType::U8,
            Type::U16 => WITXType::U16,
            Type::U32 => WITXType::U32,
            Type::U64 => WITXType::U64,
            Type::S8 => WITXType::S8,
            Type::S16 => WITXType::S16,
            Type::S32 => WITXType::S32,
            Type::S64 => WITXType::S64,
            Type::F32 => WITXType::F32,
            Type::F64 => WITXType::F64,
            Type::Char => WITXType::Char,
            Type::CChar => WITXType::CChar,
            Type::Usize => WITXType::Usize,
            Type::Handle(_) => WITXType::Unknown,  // Unsupported for now
            Type::Id(id) => {
                // Looking for a list or record type.
                match td.iface.types[*id].kind {
                    TypeDefKind::Record(_) => WITXType::Record,
                    TypeDefKind::List(_) => WITXType::List,
                    _ => WITXType::Unknown
                }
            },
        };
    if ty == WITXType::Unknown {
        return Err(anyhow!("Unsupported type"));
    }
    unsafe {
        *res = ty;
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn witx_func_sig_get(func: *const WITXFunction, res: *mut *const WITXSignature) -> bool {
    check(_witx_func_sig_get(func, res))
}
fn _witx_func_sig_get(func: *const WITXFunction, res: *mut *const WITXSignature) -> Result<()> {
    if func.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let func  = unsafe {
        &*func
    };
    unsafe {
        *res = &func.sig as *const WITXSignature; 
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn witx_sig_length_get(sig: *const WITXSignature, part: WITXSigPart, res: *mut usize) -> bool {
    check(_witx_sig_length_get(sig, part, res))
}
fn _witx_sig_length_get(sig: *const WITXSignature, part: WITXSigPart, res: *mut usize) -> Result<()> {
    if sig.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let sig  = unsafe {
        &*sig
    };
    let len =
        match part {
            WITXSigPart::Params  => sig.sig.params.len(),
            WITXSigPart::Results => sig.sig.results.len(),
            WITXSigPart::RetPtr  => 
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
pub extern "C" fn witx_sig_type_get_by_index(sig: *const WITXSignature, part: WITXSigPart, idx: usize, res: *mut WASMType) -> bool {
    check(_witx_sig_type_get_by_index(sig, part, idx, res))
}
fn _witx_sig_type_get_by_index(sig: *const WITXSignature, part: WITXSigPart, idx: usize, res: *mut WASMType) -> Result<()> {
    if sig.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let sig  = unsafe {
        &*sig
    };
    let v = 
        match part {
            WITXSigPart::Params => &sig.sig.params,
            WITXSigPart::Results => &sig.sig.results,
            WITXSigPart::RetPtr => 
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

