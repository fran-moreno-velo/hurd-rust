//===================================================================================//
// translator: dataserver (rawrpc, sin trivfs)                                       //
//===================================================================================//

use hurd_rs::gnumach::kern_return::kern_return_t;
use rawrpc::{MsgId, Peropen, RawTranslator, Services};

pub struct Data {
  value: i32,
}

impl Data {
  pub fn new(value: i32) -> Self {
    Data { value }
  }

  pub fn s_data_set_value(&mut self, _po: &Peropen, value: i32) -> Result<(), kern_return_t> {
    self.value = value;
    Ok(())
  }

  pub fn s_data_get_value(&mut self, _po: &Peropen) -> Result<i32, kern_return_t> {
    Ok(self.value)
  }
}

impl RawTranslator for Data {
  const BASE_ID: MsgId = 45000;

  fn services() -> Services<Self> {
    Services::new()
      .add("set_value", Data::s_data_set_value)   // 45000
      .add("get_value", Data::s_data_get_value)   // 45001
  }

  // open_root y goaway usan las implementaciones por defecto: cualquiera puede abrir
  // el nodo y settrans -g lo detiene. Sobrescribirlas para restringir.
}
