// Librería: en un binario que sólo es servidor (o sólo cliente) parte queda sin usar.
#![allow(dead_code)]

//===================================================================================//
// rawtrans: RPC "crudas" sobre mach_msg, sin MIG ni trivfs                            //
//===================================================================================//
//
// Servidor:
//
//     impl RawTranslator for Data {
//         const BASE_ID: MsgId = 45000;
//         fn services() -> Services<Self> {
//             Services::new()
//                 .add("set_value", Data::s_data_set_value)   // 45000
//                 .add("get_value", Data::s_data_get_value)   // 45001
//         }
//     }
//
// Cliente:
//
//     impl RawClient for DataClient { fn port(&self) -> mach_port_t { self.port } }
//     let v: i32 = client.call(45001, ())?;                    // tipado estático
//     let iface = client.describe()?;                          // introspección
//     let v: i32 = client.call_named(&iface, "get_value", ())?; // comprobado en ejecución
//
// Formato en el cable: el de GNU MIG para i386 y x86_64 (ver sys.rs). Verificado
// enlazando stubs C generados por MIG con este código en ambos sentidos. Un cliente C
// con stubs MIG puede hablar con un servidor rawtrans y viceversa, siempre que la .defs
// use los mismos tipos.
//
// Translator sin trivfs:
//
//     let kr = RawServer::new(Data::new(0)).run_translator(0, None);
//
// Único fichero acoplado al crate gnumach: sys.rs.

pub mod sys;
pub mod rights;
pub mod wire;
pub mod server;
pub mod client;
pub mod fsys;

// API pública del módulo; en un binario no todo se usa.
#[allow(unused_imports)]
pub use sys::{Layout, MsgBuf, MsgId, MSG_MAX};
#[allow(unused_imports)]
pub use wire::{FixedStr, Kind, Port, Wire, WireError, WireTuple};
#[allow(unused_imports)]
pub use server::{Handler, Peropen, RawServer, RawTranslator, Services};
#[allow(unused_imports)]
pub use client::{CallError, InterfaceDesc, RawClient, ServiceDesc};

/// Id del mensaje de introspección. Es fijo, y no relativo al id base, porque el
/// cliente lo usa precisamente para averiguar el id base. Revisar que no colisiona
/// con ningún subsistema de hurd/*.defs que use el translator.
pub const DESCRIBE_ID: MsgId = 44_999;

/// Convención MIG: id de respuesta = id de petición + 100.
pub const REPLY_ID_OFFSET: MsgId = 100;
