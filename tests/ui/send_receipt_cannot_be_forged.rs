use ququmatz::owned::SendReceipt;

fn main() {
    // Like Receipt, a SendReceipt records what the kernel actually posted;
    // safe code must not mint one.
    let _forged = SendReceipt {
        ring: todo!(),
        id: todo!(),
        result: 0,
    };
}
