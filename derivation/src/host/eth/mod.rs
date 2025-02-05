use alloc::vec;
use alloc::vec::Vec;
use alloy_primitives::Address;

mod precompiles;

pub fn verify(hint_data: &[u8], expected: &[u8]) -> bool {
    let precompile_address = Address::from_slice(&hint_data[..20]);
    let precompile_input = hint_data[20..].to_vec();
    let result = precompiles::execute(precompile_address, precompile_input).map_or_else(
        |_| vec![0u8; 1],
        |raw_res| {
            let mut res = Vec::with_capacity(1 + raw_res.len());
            res.push(0x01);
            res.extend_from_slice(&raw_res);
            res
        },
    );
    &result == expected
}
