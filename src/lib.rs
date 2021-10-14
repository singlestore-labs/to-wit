use wasi_interface_gen::wasi_interface;

#[wasi_interface]
mod component {

    use witx2::TypeDefKind;
    use witx2::abi;
    use witx2::Interface;
    
    //////////////////////////////////////////////////////////////////////////
    //
    // WasmType
    //
    //////////////////////////////////////////////////////////////////////////
    pub enum WasmType {
        I32,
        I64,
        F32,
        F64,
    }
    impl From<abi::WasmType> for WasmType {
        fn from(t: abi::WasmType) -> Self {
            match t {
                abi::WasmType::I32 => WasmType::I32,
                abi::WasmType::I64 => WasmType::I64,
                abi::WasmType::F32 => WasmType::F32,
                abi::WasmType::F64 => WasmType::F64,
            }
        }
    }

    //////////////////////////////////////////////////////////////////////////
    //
    // WasmSignature
    //
    //////////////////////////////////////////////////////////////////////////

    /// A raw WebAssembly signature with params and results.
    pub struct WasmSignature {
        /// The WebAssembly parameters of this function.
        pub params: Vec<WasmType>,
        /// The WebAssembly results of this function.
        pub results: Vec<WasmType>,
        /// The raw types, if needed, returned through return pointer located in     
        /// `params`.
        pub retptr: Option<Vec<WasmType>>,
    }
    impl From<abi::WasmSignature> for WasmSignature {
        fn from(s: abi::WasmSignature) -> Self {
            WasmSignature {
                params: s.params.into_iter().map(|p| From::from(p)).collect(),
                results: s.results.into_iter().map(|p| From::from(p)).collect(),
                retptr: 
                    match s.retptr {
                        Some(v) => Some(v.into_iter().map(|p| From::from(p)).collect()),
                        None => None
                    }
            }
        }
    }

    //////////////////////////////////////////////////////////////////////////
    //
    // WitxType
    //
    //////////////////////////////////////////////////////////////////////////

    #[derive(Debug)]
    pub struct WitxType {
        name:   String,
        ty:     WitxTypeKind,
        //fields: Vec<WitxType>
    }

    #[derive(Debug)]
    pub enum WitxTypeKind {
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

    //////////////////////////////////////////////////////////////////////////

    static IN_STR: &str = r#"
record SimpleValue {
    i: s64,
}

square: function(input: SimpleValue) -> list<SimpleValue>
"#;

    fn testme() {
        let witx = &IN_STR;

        println!("HELLO {}", witx);

        let iface = match Interface::parse("foobar", &witx) {
            Ok(i) => i,
            Err(e) => panic!("{}", e)
        };
        for func in iface.functions.iter() {
            let sig: abi::WasmSignature = iface.wasm_signature(abi::Direction::Export, func);
            println!("sig={:?}", sig);
        }

        println!("-------------------------");
        for func in iface.functions.iter() {
            println!("{:?}", &func.name);
            println!("{:?}", &func.params);
            for p in &func.params {
                let td = &p.1;
                println!("p={:?}", p)
            }
            println!("{:?}", &func.results);
            println!("{:?}", &func.abi);
            println!("{:?}", &func.kind);
        }

        println!("-------------------------");
        for id in iface.types.iter() {
            println!("type.name={:?}", id.1.name);
            //if let TypeDefKind::Record(x) = &id.1.kind {
            //    println!("got record");
            //}
            match &id.1.kind {
                TypeDefKind::Record(r) => println!("Got record"),
                TypeDefKind::Variant(v) => println!("Got variant"),
                TypeDefKind::List(v) => println!("Got list"),
                _ => println!("unknown")
            }
        }
    }
}
