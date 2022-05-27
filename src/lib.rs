extern crate libc;

use anyhow::{anyhow, Result};
use core::slice;
use core::slice::Iter;
use core::iter::Iterator;
use libc::c_char;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::ptr;
use std::rc::Rc;
use std::str;
use parser::TypeDefKind;
use parser::abi;
use parser::{Interface, Int, Case, Field, Type, SizeAlign};

#[cfg(feature="catch_panics")]
use std::panic::catch_unwind;

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

pub struct WITSession {
    error: Option<WITError>,
}

pub struct WIT {
    iface: Rc<Interface>,
    funcs: HashMap<String, WITFunction>,    // Function name to index
    align: Rc<SizeAlign>
}
impl<'a> WIT {
    fn new(wit: &str) -> Result<WIT> {
        let iface = Rc::new(Interface::parse("wit", &wit)?);
        let mut align = SizeAlign::default();
        align.fill(&iface);
        Ok(
            WIT { 
                iface,
                funcs: HashMap::new(),
                align: Rc::new(align)
            }
        )
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub enum WITSigPart {
    Params,
    Results,
}

pub struct WITSignature {
    sig: abi::WasmSignature,
}

pub struct WITFunction {
    iface: Rc<Interface>,
    align: Rc<SizeAlign>,
    name:  CString,
    sig:   WITSignature,
    index: usize,  // function index
    res:   WITTypeDef,
}

pub struct WITTypeDefIter<'a> {
    iface:       Rc<Interface>,
    align:       Rc<SizeAlign>,
    inner_iter:  Iter<'a, (String, Type)>,
    item:        Option<WITTypeDef>
}

pub struct WITFieldIter<'a> {
    iface:       Rc<Interface>,
    align:       Rc<SizeAlign>,
    inner_iter:  Iter<'a, Field>,
    item:        Option<WITTypeDef>
}

pub struct WITCaseIter<'a> {
    iface:       Rc<Interface>,
    align:       Rc<SizeAlign>,
    inner_iter:  Iter<'a, Case>,
    item:        Option<WITTypeDef>
}

pub struct WITTypeDef {
    iface:       Rc<Interface>,
    align:       Rc<SizeAlign>,
    name:        CString,
    ty:          Type,
    subty1:      Option<Box<WITTypeDef>>,
    subty2:      Option<Box<WITTypeDef>>,
}

#[allow(non_camel_case_types)]
#[derive(PartialEq)]
#[repr(C)]
pub enum WITType {
    Unit,
    Bool,
    U8,
    U16,
    U32,
    U64,
    S8,
    S16,
    S32,
    S64,
    Float32,
    Float64,
    Char,
    String,
    Flags,
    Record,
    List,
    Variant,
    Tuple,
    Enum,
    Expected,
    Option,
    Union,
    Unknown,
}

pub struct WITError {
    c_msg: CString
}

//////////////////////////////////////////////////////////////////////////

#[cfg(feature="catch_panics")]
macro_rules! ffi_return {
    ($s: expr, $e:expr) => {{
        let res = catch_unwind(|| {
            check($s, $e)
        });
        match res {
            Ok(r) => r,
            Err(e) => {
                error_set(unsafe { &mut *$s }, anyhow!("Caught Rust panic: {:?}", e));
                false
            },
        }
    }}
}
#[cfg(not(feature="catch_panics"))]
macro_rules! ffi_return {
    ($s: expr, $e:expr) => {
        check($s, $e)
    }
}

//////////////////////////////////////////////////////////////////////////

#[no_mangle]
pub extern "C" fn wit_error_get(s: *const WITSession) -> *const c_char {
    if s.is_null() {
        return ptr::null()
    }
    let s = unsafe { &*s };
    match &s.error {
        Some(e) => e.c_msg.as_ptr(),
        _ => ptr::null()
    }
}

#[no_mangle]
pub extern "C" fn wit_error_clear(s: *mut WITSession) {
    if s.is_null() {
        return;
    }
    let s = unsafe { &mut *s };
    s.error.take();
}

fn error_set(s: &mut WITSession, err: anyhow::Error) -> bool { 
    let err_res = CString::new(err.to_string());
    match err_res {
        Ok(msg) => 
        {
            s.error.replace(
                WITError{ 
                    c_msg: msg
                }
            );
            true
        },
        Err(_) =>
            false
        }
}

// Checks the result for an error.  If present, sets the thread-local
// error slot and returns false.  If no error, true is returned.
fn check(s: *mut WITSession, r: Result<()>) -> bool {
    if let Err(err) = r {
        if !s.is_null() {
            error_set(unsafe { &mut *s }, err);
        }
        false
    } else {
        true
    }
}

#[no_mangle]
pub extern "C" fn wit_session_new() -> *mut WITSession {
    let s = WITSession {
        error: None,
    };
    let res = Box::new(s);
    Box::leak(res)
}

#[no_mangle]
pub extern "C" fn wit_session_delete(s: *mut WITSession) {
    if s.is_null() {
        return;
    }
    unsafe {
        Box::from_raw(s);
    }
}

#[no_mangle]
pub extern "C" fn wit_parse(s: *mut WITSession, content: *const u8, len: usize, res: *mut *mut WIT) -> bool {
    ffi_return!(s, _wit_parse(content, len, res))
}
fn _wit_parse(content: *const u8, len: usize, res: *mut *mut WIT) -> Result<()> {
    if content.is_null() || res.is_null() {
        return Err(anyhow!("Invalid arguments"))
    }
    let content = unsafe {
        str::from_utf8(slice::from_raw_parts(content, len))?
    };

    // Extract the WASM signature for each function.
    let mut safe_res = WIT::new(content)?;

    // Create a map of each function's name to its index into the interface.
    let funcs = &safe_res.iface.functions;
    for i in 0..funcs.len() {
        let sig = WITSignature {
            sig: safe_res.iface.wasm_signature(abi::AbiVariant::GuestExport, &funcs[i]),
        };
        let res_ty = funcs[i].result.clone();
        safe_res.funcs.insert(
            funcs[i].name.clone(), 
            WITFunction {
                iface: safe_res.iface.clone(),
                align: safe_res.align.clone(),
                name:  CString::new(funcs[i].name.as_str())?,
                sig,
                index: i,
                res:   WITTypeDef { 
                    iface: safe_res.iface.clone(), 
                    align: safe_res.align.clone(), 
                    name:  CString::new("")?,
                    ty:    res_ty, 
                    subty1: subtypedef_get_maybe(1, &safe_res.iface, &safe_res.align, Some(&funcs[i].result))?,
                    subty2: subtypedef_get_maybe(2, &safe_res.iface, &safe_res.align, Some(&funcs[i].result))?,
                },
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
pub extern "C" fn wit_delete(_s: *mut WITSession, wit: *mut WIT) {
    if wit.is_null() {
        return;
    }
    unsafe {
        Box::from_raw(wit);
    }
}

#[no_mangle]
pub extern "C" fn wit_func_name_get(s: *mut WITSession, func: *const WITFunction, res: *mut *const c_char) -> bool {
    ffi_return!(s, _wit_func_name_get(func, res))
}
fn _wit_func_name_get(func: *const WITFunction, res: *mut *const c_char) -> Result<()> {
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
pub extern "C" fn wit_func_count_get(s: *mut WITSession, wit: *const WIT, res: *mut usize) -> bool {
    ffi_return!(s, _wit_func_count_get(wit, res))
}
fn _wit_func_count_get(wit: *const WIT, res: *mut usize) -> Result<()> {
    if wit.is_null() || res.is_null() {
        return Err(anyhow!("Invalid arguments"))
    }
    let wit  = unsafe {
        &*wit
    };
    unsafe {
        *res = wit.iface.functions.len();
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn wit_func_get_by_index(s: *mut WITSession, wit: *const WIT, index: usize, res: *mut *const WITFunction) -> bool {
    ffi_return!(s, _wit_func_get_by_index(wit, index, res))
}
fn _wit_func_get_by_index(wit: *const WIT, index: usize, res: *mut *const WITFunction) -> Result<()> {
    if wit.is_null() || res.is_null() {
        return Err(anyhow!("Invalid arguments"))
    }
    let wit  = unsafe {
        &*wit
    };
    let name = &wit.iface.functions[index].name;
    let func = wit.funcs.get(name);
    if let Some(func) = func {
        unsafe {
            *res = func as *const WITFunction;
        }
        Ok(())
    } else {
        Err(anyhow!("Function `{}` not found", &name))
    }
}

#[no_mangle]
pub extern "C" fn wit_func_get_by_name(s: *mut WITSession, wit: *const WIT, fname: *const c_char, res: *mut *const WITFunction) -> bool {
    ffi_return!(s, _wit_func_get_by_name(wit, fname, res))
}
fn _wit_func_get_by_name(wit: *const WIT, fname: *const c_char, res: *mut *const WITFunction) -> Result<()> {
    if wit.is_null() || fname.is_null() || res.is_null() {
        return Err(anyhow!("Invalid arguments"))
    }
    let wit  = unsafe {
        &*wit
    };
    let fname = unsafe {
        CStr::from_ptr(fname)
    };
    let fname_str = fname.to_str()?;
    if let Some(func) = wit.funcs.get(&fname_str.to_string()) {
        unsafe {
            *res = func as *const WITFunction;
        }
        Ok(())
    } else {
        Err(anyhow!("Function `{}` not found", &fname_str))
    }
}

#[no_mangle]
pub extern "C" fn wit_func_param_walk<'a>(s: *mut WITSession, func: *const WITFunction, res: *mut *mut WITTypeDefIter<'a>) -> bool {
    ffi_return!(s, _wit_func_param_walk(func, res))
}
fn _wit_func_param_walk<'a>(func: *const WITFunction, res: *mut *mut WITTypeDefIter<'a>) -> Result<()> {
    if func.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let func  = unsafe {
        &*func
    };
    let mut inner_iter = func.iface.functions[func.index].params.iter();
    let next = inner_iter.next();
    let item: Option<WITTypeDef> = match next {
        Some(n) => {
            Some(
                WITTypeDef{ 
                    iface: func.iface.clone(), 
                    align: func.align.clone(),
                    name:  CString::new(n.0.as_str())?,
                    ty:    n.1.clone(),
                    subty1: subtypedef_get_maybe(1, &func.iface, &func.align, Some(&n.1))?,
                    subty2: subtypedef_get_maybe(2, &func.iface, &func.align, Some(&n.1))?,
                }
            )
        },
        _ => None
    };
    let res_safe = 
        Box::into_raw(
            Box::new(
                WITTypeDefIter {
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
pub extern "C" fn wit_func_result_get(s: *mut WITSession, func: *const WITFunction, res: *mut *const WITTypeDef) -> bool {
    ffi_return!(s, _wit_func_result_get(func, res))
}
fn _wit_func_result_get(func: *const WITFunction, res: *mut *const WITTypeDef) -> Result<()> {
    if func.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let func = unsafe {
        &*func
    };
    unsafe {
        *res = &func.res;
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn wit_typedef_iter_off(_s: *mut WITSession, iter: *const WITTypeDefIter) -> bool {
    if iter.is_null() {
        return true;
    }
    let iter = unsafe {
        &*iter
    };
    iter.item.is_none()
}

#[no_mangle]
pub extern "C" fn wit_typedef_iter_next(s: *mut WITSession, iter: *mut WITTypeDefIter) -> bool {
    ffi_return!(s, _wit_typedef_iter_next(iter))
}
fn _wit_typedef_iter_next(iter: *mut WITTypeDefIter) -> Result<()> {
    if iter.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    if wit_typedef_iter_off(ptr::null_mut(), iter) {
        return Err(anyhow!("Iterator out of bounds!"));
    }
    let iter = unsafe {
        &mut *iter
    };
    let next = iter.inner_iter.next();
    iter.item = {
        if let Some(next) = next {
            Some(
                WITTypeDef{ 
                    iface: iter.iface.clone(), 
                    align: iter.align.clone(),
                    name:  CString::new(next.0.as_str())?, 
                    ty:    next.1.clone(),
                    subty1: subtypedef_get_maybe(1, &iter.iface, &iter.align, Some(&next.1))?,
                    subty2: subtypedef_get_maybe(2, &iter.iface, &iter.align, Some(&next.1))?,
                }
            )
        } else {
            None
        }
    };
    Ok(())
}

fn subtypedef_get_maybe<'a>(which: i32, iface: &'a Rc<Interface>, align: &'a Rc<SizeAlign>, ty_opt: Option<&'a Type>) 
    -> Result<Option<Box<WITTypeDef>>> 
{
    let ty: &'a Type;
    if let Some(t) = ty_opt {
        ty = t;
    } else {
        return Ok(None);
    }
    if let Type::Id(id) = ty {
        match which {
            1 => match &iface.types[*id].kind {
                TypeDefKind::List(subty) => Ok(
                    Some(
                        Box::new(
                            WITTypeDef {
                                iface: iface.clone(),
                                align: align.clone(),
                                name:  CString::new("").unwrap(),
                                ty:    subty.clone(),
                                subty1: subtypedef_get_maybe(1, iface, align, Some(&subty))?,
                                subty2: subtypedef_get_maybe(2, iface, align, Some(&subty))?,
                            }
                        )
                    )
                ),
                TypeDefKind::Expected(exp) => Ok(
                    Some(
                        Box::new(
                            WITTypeDef { 
                                iface: iface.clone(),
                                align: align.clone(), 
                                name:  CString::new("ok").unwrap(),
                                ty:    exp.ok.clone(),
                                subty1: subtypedef_get_maybe(1, iface, align, Some(&exp.ok))?,
                                subty2: subtypedef_get_maybe(2, iface, align, Some(&exp.ok))?,
                            }
                        )
                    )
                ),
                _ => Ok(None),
            },
            2 => match &iface.types[*id].kind {
                TypeDefKind::Expected(exp) => Ok(
                    Some(
                        Box::new(
                            WITTypeDef { 
                                iface: iface.clone(),
                                align: align.clone(), 
                                name:  CString::new("err").unwrap(),
                                ty:    exp.err.clone(),
                                subty1: subtypedef_get_maybe(1, iface, align, Some(&exp.err))?,
                                subty2: subtypedef_get_maybe(2, iface, align, Some(&exp.err))?,
                            }
                        )
                    )
                ),
                _ => Ok(None),
            },
            _ => Ok(None),
        }
    } else {
        Ok(None)
    }
}

#[no_mangle]
pub extern "C" fn wit_typedef_iter_at<'a>(s: *mut WITSession, iter: *const WITTypeDefIter, res: *mut *const WITTypeDef) -> bool {
    ffi_return!(s, _wit_typedef_iter_at(iter, res))
}
fn _wit_typedef_iter_at(iter: *const WITTypeDefIter, res: *mut *const WITTypeDef) -> Result<()> {
    if iter.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let iter = unsafe {
        &*iter
    };
    if let Some(item) = &iter.item {
        unsafe {
            *res = item as *const WITTypeDef;
        }
        Ok(())
    } else {
        Err(anyhow!("Iterator out of bounds!"))
    }
}

#[no_mangle]
pub extern "C" fn wit_typedef_iter_delete(_s: *mut WITSession, iter: *mut WITTypeDefIter) {
    if !iter.is_null() {
        unsafe {
            Box::from_raw(iter);
        }
    }
}

#[no_mangle]
pub extern "C" fn wit_record_field_walk<'a>(s: *mut WITSession, td: *const WITTypeDef, res: *mut *mut WITFieldIter<'a>) -> bool {
    ffi_return!(s, _wit_record_field_walk(td, res))
}
fn _wit_record_field_walk<'a>(td: *const WITTypeDef, res: *mut *mut WITFieldIter<'a>) -> Result<()> {
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
            let item: Option<WITTypeDef> = match next {
                Some(f) => 
                    Some(
                        WITTypeDef{ 
                            iface: td.iface.clone(), 
                            align: td.align.clone(),
                            name:  CString::new(f.name.as_str())?, 
                            ty:    f.ty.clone(),
                            subty1: subtypedef_get_maybe(1, &td.iface, &td.align, Some(&f.ty))?,
                            subty2: subtypedef_get_maybe(2, &td.iface, &td.align, Some(&f.ty))?,
                        }
                    ),
                _ => None
            };
            let safe_res = 
                Box::into_raw(
                    Box::new(
                        WITFieldIter {
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
pub extern "C" fn wit_field_iter_off(_s: *mut WITSession, iter: *const WITFieldIter) -> bool {
    if iter.is_null() {
        return true;
    }
    let iter = unsafe {
        &*iter
    };
    iter.item.is_none()
}

#[no_mangle]
pub extern "C" fn wit_field_iter_next(s: *mut WITSession, iter: *mut WITFieldIter) -> bool {
    ffi_return!(s, _wit_field_iter_next(iter))
}
fn _wit_field_iter_next(iter: *mut WITFieldIter) -> Result<()> {
    if iter.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    if wit_field_iter_off(ptr::null_mut(), iter) {
        return Err(anyhow!("Iterator out of bounds"));
    }
    let iter = unsafe {
        &mut *iter
    };
    let next = iter.inner_iter.next();
    iter.item = {
        if let Some(next) = next {
            Some(
                WITTypeDef{ 
                    iface: iter.iface.clone(), 
                    align: iter.align.clone(),
                    name:  CString::new(next.name.as_str())?,
                    ty:    next.ty.clone(),
                    subty1: subtypedef_get_maybe(1, &iter.iface, &iter.align, Some(&next.ty))?,
                    subty2: subtypedef_get_maybe(2, &iter.iface, &iter.align, Some(&next.ty))?,
                }
            )
        } else {
            None
        }
    };
    Ok(())
}

#[no_mangle]
pub extern "C" fn wit_field_iter_at<'a>(s: *mut WITSession, iter: *const WITFieldIter<'a>, res: *mut *const WITTypeDef) -> bool {
    ffi_return!(s, _wit_field_iter_at(iter, res))
}
fn _wit_field_iter_at<'a>(iter: *const WITFieldIter<'a>, res: *mut *const WITTypeDef) -> Result<()> {
    if iter.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let iter = unsafe {
        &*iter
    };
    if let Some(item) = &iter.item {
        unsafe {
            *res = item as *const WITTypeDef;
            Ok(())
        }
    } else {
        Err(anyhow!("Iterator out of bounds!"))
    }
}

#[no_mangle]
pub extern "C" fn wit_field_iter_delete(_s: *mut WITSession, iter: *mut WITFieldIter) {
    if !iter.is_null() {
        unsafe {
            Box::from_raw(iter);
        }
    }
}

#[no_mangle]
pub extern "C" fn wit_variant_tag_get(s: *mut WITSession, td: *const WITTypeDef, res: *mut u8) -> bool {
    ffi_return!(s, _wit_variant_tag_get(td, res))
}
fn _wit_variant_tag_get(td: *const WITTypeDef, res: *mut u8) -> Result<()> {
    if td.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let td = unsafe {
        &*td
    };
    if let Type::Id(id) = &td.ty {
        if let TypeDefKind::Variant(v) = &td.iface.types[*id].kind {
            let bits = match v.tag() {
                Int::U8 => 1,
                Int::U16 => 2,
                Int::U32 => 4,
                Int::U64 => 8,
            };
            unsafe {
                *res = bits;
            }
            Ok(())
        } else {
            Err(anyhow!("Invalid argument; must be a Variant type"))
        }
    } else {
        Err(anyhow!("Invalid argument; must be a Variant type"))
    }
}

#[no_mangle]
pub extern "C" fn wit_variant_case_walk<'a>(s: *mut WITSession, td: *const WITTypeDef, res: *mut *mut WITCaseIter<'a>) -> bool {
    ffi_return!(s, _wit_variant_case_walk(td, res))
}
fn _wit_variant_case_walk<'a>(td: *const WITTypeDef, res: *mut *mut WITCaseIter<'a>) -> Result<()> {
    if td.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let td = unsafe {
        &*td
    };
    if let Type::Id(id) = &td.ty {
        if let TypeDefKind::Variant(v) = &td.iface.types[*id].kind {
            let mut inner_iter = v.cases.iter();
            let next = inner_iter.next();
            let item: Option<WITTypeDef> = match next {
                Some(c) => {
                    Some(
                        WITTypeDef{
                            iface: td.iface.clone(),
                            align: td.align.clone(),
                            name:  CString::new(c.name.as_str())?,
                            ty:    c.ty.clone(),
                            subty1: subtypedef_get_maybe(1, &td.iface, &td.align, Some(&c.ty))?,
                            subty2: subtypedef_get_maybe(2, &td.iface, &td.align, Some(&c.ty))?,
                        }
                    )
                },
                _ => None
            };
            let safe_res = 
                Box::into_raw(
                    Box::new(
                        WITCaseIter {
                            iface:   td.iface.clone(),
                            align:   td.align.clone(),
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
            Err(anyhow!("Invalid argument.  Must be a variant type!"))
        }
    } else {
        Err(anyhow!("Iterator out of bounds!"))
    }
}
#[no_mangle]
pub extern "C" fn wit_case_iter_off(_s: *mut WITSession, iter: *const WITCaseIter) -> bool {
    if iter.is_null() {
        return true;
    }
    let iter = unsafe {
        &*iter
    };
    iter.item.is_none()
}

#[no_mangle]
pub extern "C" fn wit_case_iter_next(s: *mut WITSession, iter: *mut WITCaseIter) -> bool {
    ffi_return!(s, _wit_case_iter_next(iter))
}
fn _wit_case_iter_next(iter: *mut WITCaseIter) -> Result<()> {
    if iter.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    if wit_case_iter_off(ptr::null_mut(), iter) {
        return Err(anyhow!("Iterator out of bounds"));
    }
    let iter = unsafe {
        &mut *iter
    };
    let next = iter.inner_iter.next();
    iter.item = {
        if let Some(next) = next {
            Some(
                WITTypeDef{ 
                    iface: iter.iface.clone(), 
                    align: iter.align.clone(),
                    name:  CString::new(next.name.as_str())?,
                    ty:    next.ty.clone(),
                    subty1: subtypedef_get_maybe(1, &iter.iface, &iter.align, Some(&next.ty))?,
                    subty2: subtypedef_get_maybe(2, &iter.iface, &iter.align, Some(&next.ty))?,
                }
            )
        } else {
            None
        }
    };
    Ok(())
}

#[no_mangle]
pub extern "C" fn wit_case_iter_at<'a>(s: *mut WITSession, iter: *const WITCaseIter<'a>, res: *mut *const WITTypeDef) -> bool {
    ffi_return!(s, _wit_case_iter_at(iter, res))
}
fn _wit_case_iter_at<'a>(iter: *const WITCaseIter<'a>, res: *mut *const WITTypeDef) -> Result<()> {
    if iter.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let iter = unsafe {
        &*iter
    };
    if let Some(item) = &iter.item {
        unsafe {
            *res = item as *const WITTypeDef;
            Ok(())
        }
    } else {
        Err(anyhow!("Iterator out of bounds!"))
    }
}

#[no_mangle]
pub extern "C" fn wit_case_iter_delete(_s: *mut WITSession, iter: *mut WITCaseIter) {
    if !iter.is_null() {
        unsafe {
            Box::from_raw(iter);
        }
    }
}

#[no_mangle]
pub extern "C" fn wit_expected_ok_typedef_get(s: *mut WITSession, td: *const WITTypeDef, res: *mut *const WITTypeDef) -> bool {
    ffi_return!(s, _wit_expected_typedef_get(true, td, res))
}
#[no_mangle]
pub extern "C" fn wit_expected_err_typedef_get(s: *mut WITSession, td: *const WITTypeDef, res: *mut *const WITTypeDef) -> bool {
    ffi_return!(s, _wit_expected_typedef_get(false, td, res))
}
fn _wit_expected_typedef_get(get_ok: bool, td: *const WITTypeDef, res: *mut *const WITTypeDef) -> Result<()> {
    if td.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"))
    }
    let td = unsafe { &*td };
    if let Type::Id(id) = &td.ty {
        if let TypeDefKind::Expected(_) = &td.iface.types[*id].kind {
            let subty_opt = {
                if get_ok {
                    &td.subty1
                } else {
                    &td.subty2
                }
            };
            match subty_opt {
                Some(subty) => {
                    unsafe {
                        *res = &**subty as *const WITTypeDef;
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
        Err(anyhow!("Invalid parameter.  Must be 'expected' type!"))
    }
}

#[no_mangle]
pub extern "C" fn wit_array_elem_typedef_get(s: *mut WITSession, td: *const WITTypeDef, res: *mut *const WITTypeDef) -> bool {
    ffi_return!(s, _wit_array_elem_typedef_get(td, res))
}
fn _wit_array_elem_typedef_get(td: *const WITTypeDef, res: *mut *const WITTypeDef) -> Result<()> {
    if td.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let td = unsafe {
        &*td
    };
    if let Type::Id(id) = &td.ty {
        if let TypeDefKind::List(_) = &td.iface.types[*id].kind {
            // Return cached subtype, if it exists.
            match &td.subty1 {
                Some(subty) => {
                    unsafe {
                        *res = &**subty as *const WITTypeDef;
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
pub extern "C" fn wit_typedef_name_get(s: *mut WITSession, td: *const WITTypeDef, res: *mut *const c_char) -> bool {
    ffi_return!(s, _wit_typedef_name_get(td, res))
}
fn _wit_typedef_name_get(td: *const WITTypeDef, res: *mut *const c_char) -> Result<()> {
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
pub extern "C" fn wit_typedef_align_get(s: *mut WITSession, td: *const WITTypeDef, res: *mut usize) -> bool {
    ffi_return!(s, _wit_typedef_align_get(td, res))
}
fn _wit_typedef_align_get(td: *const WITTypeDef, res: *mut usize) -> Result<()> {
    if td.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let td = unsafe {
        &*td
    };
    unsafe {
        *res = td.align.align(&td.ty);
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn wit_typedef_size_get(s: *mut WITSession, td: *const WITTypeDef, res: *mut usize) -> bool {
    ffi_return!(s, _wit_typedef_size_get(td, res))
}
fn _wit_typedef_size_get(td: *const WITTypeDef, res: *mut usize) -> Result<()> {
    if td.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let td = unsafe {
        &*td
    };
    unsafe {
        *res = td.align.size(&td.ty);
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn wit_typedef_type_get(s: *mut WITSession, td: *const WITTypeDef, res: *mut WITType) -> bool {
    ffi_return!(s, _wit_typedef_type_get(td, res))
}
fn _wit_typedef_type_get(td: *const WITTypeDef, res: *mut WITType) -> Result<()> {
    if td.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let td = unsafe {
        &*td
    };
    let ty = 
        match &td.ty {
            Type::Unit => WITType::Unit,
            Type::Bool => WITType::Bool,
            Type::U8 => WITType::U8,
            Type::U16 => WITType::U16,
            Type::U32 => WITType::U32,
            Type::U64 => WITType::U64,
            Type::S8 => WITType::S8,
            Type::S16 => WITType::S16,
            Type::S32 => WITType::S32,
            Type::S64 => WITType::S64,
            Type::Float32 => WITType::Float32,
            Type::Float64 => WITType::Float64,
            Type::Char => WITType::Char,
            Type::String => WITType::String,
            Type::Handle(_) => WITType::Unknown,  // Unsupported for now
            Type::Id(id) => {
                // Looking for a list or record type.
                match td.iface.types[*id].kind {
                    TypeDefKind::Flags(_) => WITType::Flags,
                    TypeDefKind::Expected(_) => WITType::Expected,
                    TypeDefKind::Option(_) => WITType::Option,
                    TypeDefKind::Union(_) => WITType::Union,
                    TypeDefKind::Enum(_) => WITType::Enum,
                    TypeDefKind::Tuple(_) => WITType::Tuple,
                    TypeDefKind::Record(_) => WITType::Record,
                    TypeDefKind::List(_) => WITType::List,
                    TypeDefKind::Variant(_) => WITType::Variant,
                    _ => WITType::Unknown
                }
            },
        };
    if ty == WITType::Unknown {
        return Err(anyhow!("Unsupported type"));
    }
    unsafe {
        *res = ty;
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn wit_func_sig_get(s: *mut WITSession, func: *const WITFunction, res: *mut *const WITSignature) -> bool {
    ffi_return!(s, _wit_func_sig_get(func, res))
}
fn _wit_func_sig_get(func: *const WITFunction, res: *mut *const WITSignature) -> Result<()> {
    if func.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let func  = unsafe {
        &*func
    };
    unsafe {
        *res = &func.sig as *const WITSignature; 
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn wit_sig_is_indirect(s: *mut WITSession, sig: *const WITSignature, part: WITSigPart, res: *mut bool) -> bool {
    ffi_return!(s, _wit_sig_is_indirect(sig, part, res))
}
fn _wit_sig_is_indirect(sig: *const WITSignature, part: WITSigPart, res: *mut bool) -> Result<()> {
    if sig.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let sig = unsafe {
        &*sig
    };
    let indirect =
        match part {
            WITSigPart::Params => sig.sig.indirect_params,
            WITSigPart::Results => sig.sig.retptr,
        };
    unsafe {
        *res = indirect;
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn wit_sig_length_get(s: *mut WITSession, sig: *const WITSignature, part: WITSigPart, res: *mut usize) -> bool {
    ffi_return!(s, _wit_sig_length_get(sig, part, res))
}
fn _wit_sig_length_get(sig: *const WITSignature, part: WITSigPart, res: *mut usize) -> Result<()> {
    if sig.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let sig  = unsafe {
        &*sig
    };
    let len =
        match part {
            WITSigPart::Params  => sig.sig.params.len(),
            WITSigPart::Results => sig.sig.results.len(),
        };
    unsafe { 
        *res = len; 
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn wit_sig_type_get_by_index(s: *mut WITSession, sig: *const WITSignature, part: WITSigPart, idx: usize, res: *mut WASMType) -> bool {
    ffi_return!(s, _wit_sig_type_get_by_index(sig, part, idx, res))
}
fn _wit_sig_type_get_by_index(sig: *const WITSignature, part: WITSigPart, idx: usize, res: *mut WASMType) -> Result<()> {
    if sig.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let sig  = unsafe {
        &*sig
    };
    let v = 
        match part {
            WITSigPart::Params => &sig.sig.params,
            WITSigPart::Results => &sig.sig.results,
        };
    unsafe { 
        *res = From::from(v[idx]);
    }
    Ok(())
}

