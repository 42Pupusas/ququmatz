use ququmatz::owned::Receipt;

fn main() {
    // A Receipt is proof the kernel finished; safe code must not mint one.
    let _forged = Receipt {
        ring: todo!(),
        id: todo!(),
        result: 0,
        flags: todo!(),
    };
}
