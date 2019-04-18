// use super::*;

// #[test]
// fn ipv4_target_addr() {
//     let uri = "234.123.23.42:1443/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/getMe";
//     let addr: Addr = uri.parse().unwrap();
//     assert_eq!(addr.is_ssl(), false);
//     assert_eq!(addr.addr_type().unwrap(), 1u8);
//     assert_eq!(addr.host().unwrap(), "234.123.23.42");
//     assert_eq!(addr.host_vec().unwrap(), vec![234, 123, 23, 42]);
//     assert_eq!(addr.port(), vec![5u8, 163u8]);
//     assert_eq!(addr.to_vec().unwrap(), vec![1, 234, 123, 23, 42, 5, 163]);
// }

// #[test]
// fn ipv6_target_addr() {
//     let uri = "[2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d]:443/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/getMe";
//     let addr: Addr = uri.parse().unwrap();
//     assert_eq!(addr.is_ssl(), true);
//     assert_eq!(addr.addr_type().unwrap(), 4u8);
//     assert_eq!(addr.host().unwrap(), "2001:db8:11a3:9d7:1f34:8a2e:7a0:765d");
//     assert_eq!(
//         addr.host_vec().unwrap(),
//         vec![32, 1, 13, 184, 17, 163, 9, 215, 31, 52, 138, 46, 7, 160, 118, 93]
//     );
//     assert_eq!(addr.port(), vec![1u8, 187u8]);
//     assert_eq!(
//         addr.to_vec().unwrap(),
//         vec![4, 32, 1, 13, 184, 17, 163, 9, 215, 31, 52, 138, 46, 7, 160, 118, 93, 1, 187]
//     );
// }

// #[test]
// fn domain_target_addr() {
//     let uri = "api.telegram.org:443/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/getMe";
//     let addr: Addr = uri.parse().unwrap();
//     assert_eq!(addr.is_ssl(), true);
//     assert_eq!(addr.addr_type().unwrap(), 3u8);
//     assert_eq!(addr.host().unwrap(), "api.telegram.org");
//     assert_eq!(addr.host_vec().unwrap(), "api.telegram.org".as_bytes().to_vec());
//     assert_eq!(addr.port(), vec![1u8, 187u8]);
//     assert_eq!(
//         addr.to_vec().unwrap(),
//         vec![
//             3, 16, 97, 112, 105, 46, 116, 101, 108, 101, 103, 114, 97, 109, 46, 111, 114, 103, 1,
//             187
//         ]
//     );
// }
