use std::fmt::Debug;

#[repr(transparent)]
#[derive(Copy, Clone, Default)]
#[allow(non_camel_case_types)]
pub struct u16_le(u16);

#[repr(transparent)]
#[derive(Copy, Clone, Default)]
#[allow(non_camel_case_types)]
pub struct u32_le(u32);

#[repr(transparent)]
#[derive(Copy, Clone, Default)]
#[allow(non_camel_case_types)]
pub struct u64_le(u64);

impl u16_le {
    pub fn val(self) -> u16 {
        self.0.to_le()
    }
}

impl Debug for u16_le {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.val().fmt(f)
    }
}

impl u32_le {
    pub fn val(self) -> u32 {
        self.0.to_le()
    }
}

impl Debug for u32_le {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.val().fmt(f)
    }
}

impl u64_le {
    pub fn val(self) -> u64 {
        self.0.to_le()
    }
}

impl Debug for u64_le {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.val().fmt(f)
    }
}