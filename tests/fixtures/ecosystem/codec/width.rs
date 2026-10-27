#[cfg(target_pointer_width = "32")]
fn decode_value(input: u64) -> usize {
    input as usize
}

#[cfg(target_pointer_width = "64")]
fn decode_value(input: u64) -> usize {
    usize::try_from(input).unwrap()
}
