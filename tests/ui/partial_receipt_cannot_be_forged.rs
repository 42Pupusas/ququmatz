use ququmatz::owned::PartialReceipt;

fn main() {
    // Like Receipt, a PartialReceipt records what the kernel actually
    // posted; safe code must not mint one.
    let _forged = PartialReceipt {
        ring: todo!(),
        id: todo!(),
        result: 0,
        flags: todo!(),
    };
}
