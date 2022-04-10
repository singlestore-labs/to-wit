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
use parser::{Interface, Int, Case, Field, Type, SizeAlign};

thread_local! {
    pub static LAST_ERR: RefCell<Option<WITError>> = RefCell::new(None);
}

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

pub struct WIT {
    iface: Rc<Interface>,
    funcs: HashMap<String, WITFunction>,    // Function name to index
    align: Rc<SizeAlign>
}
impl<'a> WIT {
    fn new(wit: &str) -> Result<WIT> {
        let iface = Rc::new(Interface::parse("wit", &wit)?);
        let mut align = SizeAlign::default();
        align.fill(abi::AbiVariant::GuestExport, &iface);
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
    RetPtr
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
}

pub struct WITTypeDefIter<'a> {
    iface:       Rc<Interface>,
    align:       Rc<SizeAlign>,
    inner_iter:  Iter<'a, (String, Type)>,
    item:        Option<WITTypeDef<'a>>
}

pub struct WITFieldIter<'a> {
    iface:       Rc<Interface>,
    align:       Rc<SizeAlign>,
    inner_iter:  Iter<'a, Field>,
    item:        Option<WITTypeDef<'a>>
}

pub struct WITCaseIter<'a> {
    iface:       Rc<Interface>,
    align:       Rc<SizeAlign>,
    inner_iter:  Iter<'a, Case>,
    item:        Option<WITTypeDef<'a>>
}

pub struct WITTypeDef<'a> {
    iface:       Rc<Interface>,
    align:       Rc<SizeAlign>,
    name:        CString,
    ty:          Option<&'a Type>,
    subty:       Option<Box<WITTypeDef<'a>>>,
    //align:       usize
}

#[allow(non_camel_case_types)]
#[derive(PartialEq)]
#[repr(C)]
pub enum WITType {
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
    Variant,
    Unknown,
    None,
}

pub struct WITError {
    c_msg: CString
}

//////////////////////////////////////////////////////////////////////////

#[no_mangle]
pub extern "C" fn wit_error_get() -> *const c_char {
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
                        WITError{ 
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
pub extern "C" fn wit_parse(content: *const u8, len: usize, res: *mut *mut WIT) -> bool {
    check(_wit_parse(content, len, res))
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
        safe_res.funcs.insert(
            funcs[i].name.clone(), 
            WITFunction {
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
pub extern "C" fn wit_delete(wit: *mut WIT) {
    if wit.is_null() {
        return;
    }
    unsafe {
        Box::from_raw(wit);
    }
}

#[no_mangle]
pub extern "C" fn wit_func_name_get(func: *const WITFunction, res: *mut *const c_char) -> bool {
    check(_wit_func_name_get(func, res))
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
pub extern "C" fn wit_func_count_get(wit: *const WIT, res: *mut usize) -> bool {
    check(_wit_func_count_get(wit, res))
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
pub extern "C" fn wit_func_get_by_index(wit: *const WIT, index: usize, res: *mut *const WITFunction) -> bool {
    check(_wit_func_get_by_index(wit, index, res))
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
pub extern "C" fn wit_func_get_by_name(wit: *const WIT, fname: *const c_char, res: *mut *const WITFunction) -> bool {
    check(_wit_func_get_by_name(wit, fname, res))
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
pub extern "C" fn wit_func_param_walk<'a>(func: *const WITFunction, res: *mut *mut WITTypeDefIter<'a>) -> bool {
    check(_wit_func_param_walk(func, res))
}
fn _wit_func_param_walk<'a>(func: *const WITFunction, res: *mut *mut WITTypeDefIter<'a>) -> Result<()> {
    func_typedef_walk(func, false, res)
}

#[no_mangle]
pub extern "C" fn wit_func_result_walk<'a>(func: *const WITFunction, res: *mut *mut WITTypeDefIter<'a>) -> bool {
    check(_wit_func_result_walk(func, res))
}
fn _wit_func_result_walk<'a>(func: *const WITFunction, res: *mut *mut WITTypeDefIter<'a>) -> Result<()> {
    func_typedef_walk(func, true, res)
}

// Helper for the above two functions.
fn func_typedef_walk<'a> (func: *const WITFunction, is_result: bool, res: *mut *mut WITTypeDefIter<'a>) -> Result<()> {
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
    let item: Option<WITTypeDef> = match next {
        Some(n) => {
            Some(
                WITTypeDef{ 
                    iface: func.iface.clone(), 
                    align: func.align.clone(),
                    name:  CString::new(n.0.as_str())?,
                    ty:    Some(&n.1),
                    subty: subtypedef_get_maybe(&func.iface, &func.align, Some(&n.1))?,
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
pub extern "C" fn wit_typedef_iter_off(iter: *const WITTypeDefIter) -> bool {
    if iter.is_null() {
        return true;
    }
    let iter = unsafe {
        &*iter
    };
    iter.item.is_none()
}

#[no_mangle]
pub extern "C" fn wit_typedef_iter_next(iter: *mut WITTypeDefIter) -> bool {
    check(_wit_typedef_iter_next(iter))
}
fn _wit_typedef_iter_next(iter: *mut WITTypeDefIter) -> Result<()> {
    if iter.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    if wit_typedef_iter_off(iter) {
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
                    ty:    Some(&next.1),
                    subty: subtypedef_get_maybe(&iter.iface, &iter.align, Some(&next.1))?
                }
            )
        } else {
            None
        }
    };
    Ok(())
}

fn subtypedef_get_maybe<'a>(iface: &'a Rc<Interface>, align: &'a Rc<SizeAlign>, ty_opt: Option<&'a Type>) 
    -> Result<Option<Box<WITTypeDef<'a>>>> 
{
    let ty: &'a Type;
    if let Some(t) = ty_opt {
        ty = t;
    } else {
        return Ok(None);
    }
    if let Type::Id(id) = ty {
        if let TypeDefKind::List(subty) = &iface.types[*id].kind {
            Ok(
                Some(
                    Box::new(
                        WITTypeDef {
                            iface: iface.clone(),
                            align: align.clone(),
                            name:  CString::new("").unwrap(),
                            ty:    Some(&subty),
                            subty: subtypedef_get_maybe(iface, align, Some(&subty))?
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
pub extern "C" fn wit_typedef_iter_at<'a>(iter: *const WITTypeDefIter<'a>, res: *mut *const WITTypeDef<'a>) -> bool {
    check(_wit_typedef_iter_at(iter, res))
}
fn _wit_typedef_iter_at<'a>(iter: *const WITTypeDefIter<'a>, res: *mut *const WITTypeDef<'a>) -> Result<()> {
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
pub extern "C" fn wit_typedef_iter_delete(iter: *mut WITTypeDefIter) {
    if !iter.is_null() {
        unsafe {
            Box::from_raw(iter);
        }
    }
}

#[no_mangle]
pub extern "C" fn wit_record_field_walk<'a>(td: *const WITTypeDef<'a>, res: *mut *mut WITFieldIter<'a>) -> bool {
    check(_wit_record_field_walk(td, res))
}
fn _wit_record_field_walk<'a>(td: *const WITTypeDef<'a>, res: *mut *mut WITFieldIter<'a>) -> Result<()> {
    if td.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let td = unsafe {
        &*td
    };
    if let Type::Id(id) = &td.ty.unwrap() {
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
                            ty:    Some(&f.ty),
                            subty: subtypedef_get_maybe(&td.iface, &td.align, Some(&f.ty))?
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
pub extern "C" fn wit_field_iter_off(iter: *const WITFieldIter) -> bool {
    if iter.is_null() {
        return true;
    }
    let iter = unsafe {
        &*iter
    };
    iter.item.is_none()
}

#[no_mangle]
pub extern "C" fn wit_field_iter_next(iter: *mut WITFieldIter) -> bool {
    check(_wit_field_iter_next(iter))
}
fn _wit_field_iter_next(iter: *mut WITFieldIter) -> Result<()> {
    if iter.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    if wit_field_iter_off(iter) {
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
                    ty:    Some(&next.ty),
                    subty: subtypedef_get_maybe(&iter.iface, &iter.align, Some(&next.ty))?
                }
            )
        } else {
            None
        }
    };
    Ok(())
}

#[no_mangle]
pub extern "C" fn wit_field_iter_at<'a>(iter: *const WITFieldIter<'a>, res: *mut *const WITTypeDef<'a>) -> bool {
    check(_wit_field_iter_at(iter, res))
}
fn _wit_field_iter_at<'a>(iter: *const WITFieldIter<'a>, res: *mut *const WITTypeDef<'a>) -> Result<()> {
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
pub extern "C" fn wit_field_iter_delete(iter: *mut WITFieldIter) {
    if !iter.is_null() {
        unsafe {
            Box::from_raw(iter);
        }
    }
}

#[no_mangle]
pub extern "C" fn wit_variant_is_bool<'a>(td: *const WITTypeDef<'a>) -> bool {
    if td.is_null() {
        return false;
    }
    let td = unsafe {
        &*td
    };
    if let Some(ty) = td.ty {
        if let Type::Id(id) = ty {
            if let TypeDefKind::Variant(v) = &td.iface.types[*id].kind {
                return v.is_bool()
            }
        }
    }
    false
}

#[no_mangle]
pub extern "C" fn wit_variant_tag_get<'a>(td: *const WITTypeDef<'a>, res: *mut u8) -> bool {
    check(_wit_variant_tag_get(td, res))
}
fn _wit_variant_tag_get<'a>(td: *const WITTypeDef<'a>, res: *mut u8) -> Result<()> {
    if td.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let td = unsafe {
        &*td
    };
    if let Some(ty) = td.ty {
        if let Type::Id(id) = ty {
            if let TypeDefKind::Variant(v) = &td.iface.types[*id].kind {
                let bits = match v.tag {
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
    } else {
        unsafe {
            *res = 0;
            Ok(())
        }
    }
}

#[no_mangle]
pub extern "C" fn wit_variant_case_walk<'a>(td: *const WITTypeDef<'a>, res: *mut *mut WITCaseIter<'a>) -> bool {
    check(_wit_variant_case_walk(td, res))
}
fn _wit_variant_case_walk<'a>(td: *const WITTypeDef<'a>, res: *mut *mut WITCaseIter<'a>) -> Result<()> {
    if td.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let td = unsafe {
        &*td
    };
    if let Type::Id(id) = &td.ty.unwrap() {  // TODO - fix this
        if let TypeDefKind::Variant(v) = &td.iface.types[*id].kind {
            let mut inner_iter = v.cases.iter();
            let next = inner_iter.next();
            let item: Option<WITTypeDef> = match next {
                Some(c) => {
                    let ty_opt = match &c.ty {
                        Some(t) => Some(t),
                        _ => None,
                    };
                    Some(
                        WITTypeDef{
                            iface: td.iface.clone(),
                            align: td.align.clone(),
                            name:  CString::new(c.name.as_str())?,
                            ty:    ty_opt,
                            subty: subtypedef_get_maybe(&td.iface, &td.align, ty_opt)?
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
pub extern "C" fn wit_case_iter_off(iter: *const WITCaseIter) -> bool {
    if iter.is_null() {
        return true;
    }
    let iter = unsafe {
        &*iter
    };
    iter.item.is_none()
}

#[no_mangle]
pub extern "C" fn wit_case_iter_next(iter: *mut WITCaseIter) -> bool {
    check(_wit_case_iter_next(iter))
}
fn _wit_case_iter_next(iter: *mut WITCaseIter) -> Result<()> {
    if iter.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    if wit_case_iter_off(iter) {
        return Err(anyhow!("Iterator out of bounds"));
    }
    let iter = unsafe {
        &mut *iter
    };
    let next = iter.inner_iter.next();
    iter.item = {
        if let Some(next) = next {
            let ty_opt = match &next.ty {
                Some(t) => Some(t),
                _ => None,
            };
            Some(
                WITTypeDef{ 
                    iface: iter.iface.clone(), 
                    align: iter.align.clone(),
                    name:  CString::new(next.name.as_str())?,
                    ty:    ty_opt,
                    subty: subtypedef_get_maybe(&iter.iface, &iter.align, ty_opt)?
                }
            )
        } else {
            None
        }
    };
    Ok(())
}

#[no_mangle]
pub extern "C" fn wit_case_iter_at<'a>(iter: *const WITCaseIter<'a>, res: *mut *const WITTypeDef<'a>) -> bool {
    check(_wit_case_iter_at(iter, res))
}
fn _wit_case_iter_at<'a>(iter: *const WITCaseIter<'a>, res: *mut *const WITTypeDef<'a>) -> Result<()> {
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
pub extern "C" fn wit_case_iter_delete(iter: *mut WITCaseIter) {
    if !iter.is_null() {
        unsafe {
            Box::from_raw(iter);
        }
    }
}

#[no_mangle]
pub extern "C" fn wit_array_elem_typedef_get<'a>(td: *const WITTypeDef<'a>, res: *mut *const WITTypeDef<'a>) -> bool {
    check(_wit_array_elem_typedef_get(td, res))
}
fn _wit_array_elem_typedef_get<'a>(td: *const WITTypeDef<'a>, res: *mut *const WITTypeDef<'a>) -> Result<()> {
    if td.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let td = unsafe {
        &*td
    };
    if let Some(ty) = td.ty {
        if let Type::Id(id) = ty {
            if let TypeDefKind::List(_) = &td.iface.types[*id].kind {
                // Return cached subtype, if it exists.
                match &td.subty {
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
    } else {
        Err(anyhow!("Type is none!"))
    }
}

#[no_mangle]
pub extern "C" fn wit_typedef_name_get(td: *const WITTypeDef, res: *mut *const c_char) -> bool {
    check(_wit_typedef_name_get(td, res))
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
pub extern "C" fn wit_typedef_align_get(td: *const WITTypeDef, res: *mut usize) -> bool {
    check(_wit_typedef_align_get(td, res))
}
fn _wit_typedef_align_get(td: *const WITTypeDef, res: *mut usize) -> Result<()> {
    if td.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let td = unsafe {
        &*td
    };
    let mut align = 0;
    if let Some(ty) = td.ty {
        align = td.align.align(ty);
    }
    unsafe {
        *res = align;
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn wit_typedef_size_get(td: *const WITTypeDef, res: *mut usize) -> bool {
    check(_wit_typedef_size_get(td, res))
}
fn _wit_typedef_size_get(td: *const WITTypeDef, res: *mut usize) -> Result<()> {
    if td.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let td = unsafe {
        &*td
    };
    let mut size = 0;
    if let Some(ty) = td.ty {
        size = td.align.size(ty);
    }
    unsafe {
        *res = size;
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn wit_typedef_type_get(td: *const WITTypeDef, res: *mut WITType) -> bool {
    check(_wit_typedef_type_get(td, res))
}
fn _wit_typedef_type_get(td: *const WITTypeDef, res: *mut WITType) -> Result<()> {
    if td.is_null() || res.is_null() {
        return Err(anyhow!("Invalid argument"));
    }
    let td = unsafe {
        &*td
    };
    if let Some(t) = td.ty {
        let ty = 
            match t {
                Type::U8 => WITType::U8,
                Type::U16 => WITType::U16,
                Type::U32 => WITType::U32,
                Type::U64 => WITType::U64,
                Type::S8 => WITType::S8,
                Type::S16 => WITType::S16,
                Type::S32 => WITType::S32,
                Type::S64 => WITType::S64,
                Type::F32 => WITType::F32,
                Type::F64 => WITType::F64,
                Type::Char => WITType::Char,
                Type::CChar => WITType::CChar,
                Type::Usize => WITType::Usize,
                Type::Handle(_) => WITType::Unknown,  // Unsupported for now
                Type::Id(id) => {
                    // Looking for a list or record type.
                    match td.iface.types[*id].kind {
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
    } else {
        unsafe {
            *res = WITType::None;
        }
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn wit_func_sig_get(func: *const WITFunction, res: *mut *const WITSignature) -> bool {
    check(_wit_func_sig_get(func, res))
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
pub extern "C" fn wit_sig_length_get(sig: *const WITSignature, part: WITSigPart, res: *mut usize) -> bool {
    check(_wit_sig_length_get(sig, part, res))
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
            WITSigPart::RetPtr  => 
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
pub extern "C" fn wit_sig_type_get_by_index(sig: *const WITSignature, part: WITSigPart, idx: usize, res: *mut WASMType) -> bool {
    check(_wit_sig_type_get_by_index(sig, part, idx, res))
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
            WITSigPart::RetPtr => 
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

