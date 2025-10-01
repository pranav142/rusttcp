// If index and index + 1 are out of bounds then this
// will lead to undefined behavior.
pub unsafe fn u16_from_buf_unchecked(buf: &[u8], index: usize) -> u16 {
    unsafe { ((*buf.get_unchecked(index) as u16) << 8) | *buf.get_unchecked(index + 1) as u16 }
}

// If index up to index + 3 are out of bounds then this
// will lead to undefined behavior
pub unsafe fn u32_from_buf_unchecked(buf: &[u8], index: usize) -> u32 {
    let mut total = 0;
    for offset in 0..4 {
        total <<= 8;
        unsafe {
            total |= *buf.get_unchecked(index + offset) as u32;
        }
    }
    total
}

// If index and index + 1 are outside of the buffers length
// then this will lead to undetermined behavior
pub unsafe fn u16_to_buf_unchecked(buf: &mut [u8], index: usize, val: u16) {
    unsafe {
        *buf.get_unchecked_mut(index) = (val >> 8) as u8;
        *buf.get_unchecked_mut(index + 1) = (val & 0xFF) as u8;
    }
}

// If index..index + 3 are outside of the buffers length
// then this will lead to undetermined behavior
pub unsafe fn u32_to_buf_unchecked(buf: &mut [u8], index: usize, val: u32) {
    for i in 0..4 {
        let shift = 24 - (i * 8);
        unsafe {
            *buf.get_unchecked_mut(index + i) = ((val >> shift) & 0xFF) as u8;
        };
    }
}

pub fn ones_complement_sum(a: u16, b: u16) -> u16 {
    let mut sum = a as u32 + b as u32;
    let is_overflow = (sum & 0x10000) > 0;

    if is_overflow {
        sum &= !(0x10000);
        sum += 1;
    }

    sum as u16
}
