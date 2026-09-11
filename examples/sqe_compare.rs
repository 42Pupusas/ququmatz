//! Byte-for-byte SQE comparison against the io-uring crate, which compiles
//! only on `x86_64`. Elsewhere this example does nothing.

#[cfg(target_arch = "x86_64")]
use ququmatz::types::RawFd;

#[cfg(not(target_arch = "x86_64"))]
fn main() {
    println!("sqe_compare requires the io-uring crate, which is x86_64-only");
}

#[cfg(target_arch = "x86_64")]
fn main() {
    let buf = [0xABu8; 4096];

    let qq =
        unsafe { ququmatz::Sqe::write_ptr(RawFd::from_raw(3), buf.as_ptr(), 4096, 0) }.user_data(1);

    let iu = io_uring::opcode::Write::new(io_uring::types::Fd(3), buf.as_ptr(), 4096)
        .offset(0)
        .build()
        .user_data(1);

    let qq_b: &[u8] = unsafe { core::slice::from_raw_parts((&raw const qq).cast::<u8>(), 64) };
    let iu_b: &[u8] = unsafe { core::slice::from_raw_parts((&raw const iu).cast::<u8>(), 64) };

    println!("ququmatz: {qq_b:02x?}");
    println!("io_uring: {iu_b:02x?}");

    let mut qq_cmp = [0u8; 64];
    let mut iu_cmp = [0u8; 64];
    qq_cmp.copy_from_slice(qq_b);
    iu_cmp.copy_from_slice(iu_b);
    // zero out pointer-dependent fields: addr (16..24) and user_data (32..40)
    for i in 16..24 {
        qq_cmp[i] = 0;
        iu_cmp[i] = 0;
    }
    for i in 32..40 {
        qq_cmp[i] = 0;
        iu_cmp[i] = 0;
    }

    if qq_cmp == iu_cmp {
        println!("SQEs match (modulo addr + user_data)");
    } else {
        println!("SQE MISMATCH:");
        for i in 0..64 {
            if qq_cmp[i] != iu_cmp[i] {
                println!("  byte[{i:2}]: qq={:02x}  iu={:02x}", qq_cmp[i], iu_cmp[i]);
            }
        }
    }
}
