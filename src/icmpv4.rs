use crate::parse::icmpv4::{Icmpv4, Icmpv4Type};
use crate::parse::icmpv4_slice::Icmpv4Slice;

pub fn process_echo<'a>(icmp: &Icmpv4Slice<'a>) -> Icmpv4<'a> {
    assert!(
        icmp.icmp_type() == Icmpv4Type::Echo,
        "Expected to recieve a Echo message instead recieved: {:?}",
        icmp.icmp_type()
    );

    Icmpv4 {
        icmp_type: Icmpv4Type::EchoReply,
        code: icmp.code(),
        identifier: icmp.identifier(),
        sequence_number: icmp.sequence_number(),
        payload: icmp.payload(),
    }
}

pub fn process_icmpv4<'a>(icmp: &Icmpv4Slice<'a>) -> Option<Icmpv4<'a>> {
    match icmp.icmp_type() {
        Icmpv4Type::Echo => Some(process_echo(icmp)),
        Icmpv4Type::EchoReply => None,
    }
}
