#![feature(prelude_import)]
#[prelude_import]
use std::prelude::rust_2018::*;
extern crate std;


#[allow(unused_imports)]


#[allow(dead_code)]
mod component {
    use witx2::Interface;
    use witx2::abi::{Direction, WasmSignature};

    static IN_STR: &str = r#"
record SimpleValue {
    i: s64,
}

square: function(input: SimpleValue) -> list<SimpleValue>
"#;

    #[export_name = "testme"]
//    unsafe extern "C" fn testme(witx: &str) {
    unsafe extern "C" fn testme() {
        let witx = &IN_STR;

        println!("HELLO {}", witx);

        let iface = match Interface::parse("foobar", &witx) {
            Ok(i) => i,
            Err(e) => panic!("{}", e)
        };
        for func in iface.functions.iter() {
            let sig: WasmSignature = iface.wasm_signature(Direction::Export, func);
            println!("sig={:?}", sig);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

