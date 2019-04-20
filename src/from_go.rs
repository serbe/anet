// use crate::url::Url;

// #[test]
// fn no_path() {
// 	let s = Url::from("http://www.example.org").unwrap();
// 	let mut u = Url::new();
// 	u.scheme = Some("http");
// 	u.host = "www.example.org";
// 	assert_eq!(s, u);
// }

// #[test]
// fn with_path() {
// 	let s = Url::from("http://www.example.org/").unwrap();
// 	let mut u = Url::new();
// 	u.scheme = Some("http");
// 	u.host = "www.example.org";
// 	u.path = Some("/");
// 	assert_eq!(s, u);
// }

// // path with hex escaping
// { let mut u = Url::new();
// let mut u = Url::new();
// let s = Url::from("http://www.example.org/file%20one%26two").unwrap();
//
// 		u.scheme = Some("http");
// 		u.host = "www.example.org";
// 		u.path = Some("/file one&two");
// 		Rawu.path = Some("/file%20one%26two");
// assert_eq!(s, u);
//
// },
// // user
// { let mut u = Url::new();
// let s = Url::from("ftp://webmaster@www.example.org/").unwrap();
//
// 		u.scheme = Some("ftp");
// 		User:   User("webmaster"),
// 		u.host = "www.example.org";
// 		u.path = Some("/");
// assert_eq!(s, u);
//
// },
// // escape sequence in username
// { let mut u = Url::new();
// let s = Url::from("ftp://john%20doe@www.example.org/").unwrap();
//
// 		u.scheme = Some("ftp");
// 		User:   User("john doe"),
// 		u.host = "www.example.org";
// 		u.path = Some("/");
// assert_eq!(s, u);
// let s = Url::from("ftp://john%20doe@www.example.org/").unwrap();
// },
// // empty query
// { let mut u = Url::new();
// let s = Url::from("http://www.example.org/?").unwrap();
//
// 		u.scheme = Some("http");
// 		u.host = "www.example.org";
// 		u.path = Some("/");
// 		ForceQuery: true,
// assert_eq!(s, u);
//
// },
// // query ending in question mark (Issue 14573)
// { let mut u = Url::new();
// let s = Url::from("http://www.example.org/?foo=bar?").unwrap();
//
// 		u.scheme = Some("http");
// 		u.host = "www.example.org";
// 		u.path = Some("/");
// 		u.query = "foo=bar?";
// assert_eq!(s, u);
//
// },
// // query
// { let mut u = Url::new();
// let s = Url::from("http://www.example.org/?q=rust+language").unwrap();
//
// 		u.scheme = Some("http");
// 		u.host = "www.example.org";
// 		u.path = Some("/");
// 		u.query = "q=rust+language";
// assert_eq!(s, u);
//
// },
// // query with hex escaping: NOT parsed
// { let mut u = Url::new();
// let s = Url::from("http://www.example.org/?q=go%20language").unwrap();
//
// 		u.scheme = Some("http");
// 		u.host = "www.example.org";
// 		u.path = Some("/");
// 		u.query = "q=go%20language";
// assert_eq!(s, u);
//
// },
// // %20 outside query
// { let mut u = Url::new();
// let s = Url::from("http://www.example.org/a%20b?q=c+d").unwrap();
//
// 		u.scheme = Some("http");
// 		u.host = "www.example.org";
// 		u.path = Some("/a b");
// 		u.query = "q=c+d";
// assert_eq!(s, u);
//
// },
// // path without leading /, so no parsing
// { let mut u = Url::new();
// let s = Url::from("http:www.example.org/?q=rust+language").unwrap();
//
// 		u.scheme = Some("http");
// 		Opaque:   "www.example.org/",
// 		u.query = "q=rust+language";
// assert_eq!(s, u);
// let s = Url::from("http:www.example.org/?q=rust+language").unwrap();
// },
// // path without leading /, so no parsing
// { let mut u = Url::new();
// let s = Url::from("http:%2f%2fwww.example.org/?q=rust+language").unwrap();
//
// 		u.scheme = Some("http");
// 		Opaque:   "%2f%2fwww.example.org/",
// 		u.query = "q=rust+language";
// assert_eq!(s, u);
// let s = Url::from("http:%2f%2fwww.example.org/?q=rust+language").unwrap();
// },
// // non-authority with path
// { let mut u = Url::new();
// let s = Url::from("mailto:/webmaster@example.org").unwrap();
//
// 		u.scheme = Some("mailto");
// 		u.path = Some("/webmaster@example.org");
// assert_eq!(s, u);
// let s = Url::from("mailto:///webmaster@example.org").unwrap(); // unfortunate compromise
// },
// // non-authority
// { let mut u = Url::new();
// let s = Url::from("mailto:webmaster@example.org").unwrap();
//
// 		u.scheme = Some("mailto");
// 		Opaque: "webmaster@example.org",
// assert_eq!(s, u);
//
// },
// // unescaped :// in query should not create a scheme
// { let mut u = Url::new();
// let s = Url::from("/foo?query=http://bad").unwrap();
//
// 		u.path = Some("/foo");
// 		u.query = "query=http://bad";
// assert_eq!(s, u);
//
// },
// // leading // without scheme should create an authority
// { let mut u = Url::new();
// let s = Url::from("//foo").unwrap();
//
// 		u.host = "foo";
// assert_eq!(s, u);
//
// },
// // leading // without scheme, with userinfo, path, and query
// { let mut u = Url::new();
// let s = Url::from("//user@foo/path?a=b").unwrap();
//
// 		User:     User("user"),
// 		u.host = "foo";
// 		u.path = Some("/path");
// 		u.query = "a=b";
// assert_eq!(s, u);
//
// },
// // Three leading slashes isn't an authority, but doesn't return an error.
// // (We can't return an error, as this code is also used via
// // ServeHTTP -> ReadRequest -> Parse, which is arguably a
// // different URL parsing context, but currently shares the
// // same codepath)
// { let mut u = Url::new();
// let s = Url::from("///threeslashes").unwrap();
//
// 		u.path = Some("///threeslashes");
// assert_eq!(s, u);
//
// },
// { let mut u = Url::new();
// let s = Url::from("http://user:password@google.com").unwrap();
//
// 		u.scheme = Some("http");
// 		User:   UserPassword("user", "password"),
// 		u.host = "google.com";
// assert_eq!(s, u);
// let s = Url::from("http://user:password@google.com").unwrap();
// },
// // unescaped @ in username should not confuse host
// { let mut u = Url::new();
// let s = Url::from("http://j@ne:password@google.com").unwrap();
//
// 		u.scheme = Some("http");
// 		User:   UserPassword("j@ne", "password"),
// 		u.host = "google.com";
// assert_eq!(s, u);
// let s = Url::from("http://j%40ne:password@google.com").unwrap();
// },
// // unescaped @ in password should not confuse host
// { let mut u = Url::new();
// let s = Url::from("http://jane:p@ssword@google.com").unwrap();
//
// 		u.scheme = Some("http");
// 		User:   UserPassword("jane", "p@ssword"),
// 		u.host = "google.com";
// assert_eq!(s, u);
// let s = Url::from("http://jane:p%40ssword@google.com").unwrap();
// },
// { let mut u = Url::new();
// let s = Url::from("http://j@ne:password@google.com/p@th?q=@go").unwrap();
//
// 		u.scheme = Some("http");
// 		User:     UserPassword("j@ne", "password"),
// 		u.host = "google.com";
// 		u.path = Some("/p@th");
// 		u.query = "q=@go";
// assert_eq!(s, u);
// let s = Url::from("http://j%40ne:password@google.com/p@th?q=@go").unwrap();
// },
// { let mut u = Url::new();
// let s = Url::from("http://www.example.org/?q=rust+language#foo").unwrap();
//
// 		u.scheme = Some("http");
// 		u.host = "www.example.org";
// 		u.path = Some("/");
// 		u.query = "q=rust+language";
// 		u.fragment = Some("foo");
// assert_eq!(s, u);
//
// },
// { let mut u = Url::new();
// let s = Url::from("http://www.example.org/?q=rust+language#foo%26bar").unwrap();
//
// 		u.scheme = Some("http");
// 		u.host = "www.example.org";
// 		u.path = Some("/");
// 		u.query = "q=rust+language";
// 		u.fragment = Some("foo&bar");
// assert_eq!(s, u);
// let s = Url::from("http://www.example.org/?q=rust+language#foo&bar").unwrap();
// },
// { let mut u = Url::new();
// let s = Url::from("file:///home/adg/rabbits").unwrap();
//
// 		u.scheme = Some("file");
// 		host:   "",
// 		u.path = Some("/home/adg/rabbits");
// assert_eq!(s, u);
// let s = Url::from("file:///home/adg/rabbits").unwrap();
// },
// // "Windows" paths are no exception to the rule.
// // See example.org/issue/6027, especially comment #9.
// { let mut u = Url::new();
// let s = Url::from("file:///C:/FooBar/Baz.txt").unwrap();
//
// 		u.scheme = Some("file");
// 		host:   "",
// 		u.path = Some("/C:/FooBar/Baz.txt");
// assert_eq!(s, u);
// let s = Url::from("file:///C:/FooBar/Baz.txt").unwrap();
// },
// // case-insensitive scheme
// { let mut u = Url::new();
// let s = Url::from("MaIlTo:webmaster@example.org").unwrap();
//
// 		u.scheme = Some("mailto");
// 		Opaque: "webmaster@example.org",
// assert_eq!(s, u);
// let s = Url::from("mailto:webmaster@example.org").unwrap();
// },
// // Relative path
// { let mut u = Url::new();
// let s = Url::from("a/b/c").unwrap();
//
// 		u.path = Some("a/b/c");
// assert_eq!(s, u);
// let s = Url::from("a/b/c").unwrap();
// },
// // escaped '?' in username and password
// { let mut u = Url::new();
// let s = Url::from("http://%3Fam:pa%3Fsword@google.com").unwrap();
//
// 		u.scheme = Some("http");
// 		User:   UserPassword("?am", "pa?sword"),
// 		u.host = "google.com";
// assert_eq!(s, u);
//
// },
// // host subcomponent; IPv4 address in RFC 3986
// { let mut u = Url::new();
// let s = Url::from("http://192.168.0.1/").unwrap();
//
// 		u.scheme = Some("http");
// 		u.host = "192.168.0.1";
// 		u.path = Some("/");
// assert_eq!(s, u);
//
// },
// // host and port subcomponents; IPv4 address in RFC 3986
// { let mut u = Url::new();
// let s = Url::from("http://192.168.0.1:8080/").unwrap();
//
// 		u.scheme = Some("http");
// 		u.host = "192.168.0.1:8080";
// 		u.path = Some("/");
// assert_eq!(s, u);
//
// },
// // host subcomponent; IPv6 address in RFC 3986
// { let mut u = Url::new();
// let s = Url::from("http://[fe80::1]/").unwrap();
//
// 		u.scheme = Some("http");
// 		u.host = "[fe80::1]";
// 		u.path = Some("/");
// assert_eq!(s, u);
//
// },
// // host and port subcomponents; IPv6 address in RFC 3986
// { let mut u = Url::new();
// let s = Url::from("http://[fe80::1]:8080/").unwrap();
//
// 		u.scheme = Some("http");
// 		u.host = "[fe80::1]:8080";
// 		u.path = Some("/");
// assert_eq!(s, u);
//
// },
// // host subcomponent; IPv6 address with zone identifier in RFC 6874
// { let mut u = Url::new();
// let s = Url::from("http://[fe80::1%25en0]/").unwrap(); // alphanum zone identifier
//
// 		u.scheme = Some("http");
// 		u.host = "[fe80::1%en0]";
// 		u.path = Some("/");
// assert_eq!(s, u);
//
// },
// // host and port subcomponents; IPv6 address with zone identifier in RFC 6874
// { let mut u = Url::new();
// let s = Url::from("http://[fe80::1%25en0]:8080/").unwrap(); // alphanum zone identifier
//
// 		u.scheme = Some("http");
// 		u.host = "[fe80::1%en0]:8080";
// 		u.path = Some("/");
// assert_eq!(s, u);
//
// },
// // host subcomponent; IPv6 address with zone identifier in RFC 6874
// { let mut u = Url::new();
// let s = Url::from("http://[fe80::1%25%65%6e%301-._~]/").unwrap(); // percent-encoded+unreserved zone identifier
//
// 		u.scheme = Some("http");
// 		u.host = "[fe80::1%en01-._~]";
// 		u.path = Some("/");
// assert_eq!(s, u);
// let s = Url::from("http://[fe80::1%25en01-._~]/").unwrap();
// },
// // host and port subcomponents; IPv6 address with zone identifier in RFC 6874
// { let mut u = Url::new();
// let s = Url::from("http://[fe80::1%25%65%6e%301-._~]:8080/").unwrap(); // percent-encoded+unreserved zone identifier
//
// 		u.scheme = Some("http");
// 		u.host = "[fe80::1%en01-._~]:8080";
// 		u.path = Some("/");
// assert_eq!(s, u);
// let s = Url::from("http://[fe80::1%25en01-._~]:8080/").unwrap();
// },
// // alternate escapings of path survive round trip
// { let mut u = Url::new();
// let s = Url::from("http://rest.rsc.io/foo%2fbar/baz%2Fquux?alt=media").unwrap();
//
// 		u.scheme = Some("http");
// 		u.host = "rest.rsc.io";
// 		u.path = Some("/foo/bar/baz/quux");
// 		Rawu.path = Some("/foo%2fbar/baz%2Fquux");
// 		u.query = "alt=media";
// assert_eq!(s, u);
//
// },
// // issue 12036
// { let mut u = Url::new();
// let s = Url::from("mysql://a,b,c/bar").unwrap();
//
// 		u.scheme = Some("mysql");
// 		u.host = "a,b,c";
// 		u.path = Some("/bar");
// assert_eq!(s, u);
//
// },
// // worst case host, still round trips
// { let mut u = Url::new();
// let s = Url::from("scheme://!$&'()*+,;=hello!:port/path").unwrap();
//
// 		u.scheme = Some("scheme");
// 		u.host = "!$&'()*+,;=hello!:port";
// 		u.path = Some("/path");
// assert_eq!(s, u);
//
// },
// // worst case path, still round trips
// { let mut u = Url::new();
// let s = Url::from("http://host/!$&'()*+,;=:@[hello]").unwrap();
//
// 		u.scheme = Some("http");
// 		u.host = "host";
// 		u.path = Some("/!$&'()*+,;=:@[hello]");
// 		Rawu.path = Some("/!$&'()*+,;=:@[hello]");
// assert_eq!(s, u);
//
// },
// // example.org/issue/5684
// { let mut u = Url::new();
// let s = Url::from("http://example.com/oid/[order_id]").unwrap();
//
// 		u.scheme = Some("http");
// 		u.host = "example.com";
// 		u.path = Some("/oid/[order_id]");
// 		Rawu.path = Some("/oid/[order_id]");
// assert_eq!(s, u);
//
// },
// // example.org/issue/12200 (colon with empty port)
// { let mut u = Url::new();
// let s = Url::from("http://192.168.0.2:8080/foo").unwrap();
//
// 		u.scheme = Some("http");
// 		u.host = "192.168.0.2:8080";
// 		u.path = Some("/foo");
// assert_eq!(s, u);
//
// },
// { let mut u = Url::new();
// let s = Url::from("http://192.168.0.2:/foo").unwrap();
//
// 		u.scheme = Some("http");
// 		u.host = "192.168.0.2:";
// 		u.path = Some("/foo");
// assert_eq!(s, u);
//
// },
// { let mut u = Url::new();
// 	// Malformed IPv6 but still accepted.
// let s = Url::from("http://2b01:e34:ef40:7730:8e70:5aff:fefe:edac:8080/foo").unwrap();
//
// 		u.scheme = Some("http");
// 		u.host = "2b01:e34:ef40:7730:8e70:5aff:fefe:edac:8080";
// 		u.path = Some("/foo");
// assert_eq!(s, u);
//
// },
// { let mut u = Url::new();
// 	// Malformed IPv6 but still accepted.
// let s = Url::from("http://2b01:e34:ef40:7730:8e70:5aff:fefe:edac:/foo").unwrap();
//
// 		u.scheme = Some("http");
// 		u.host = "2b01:e34:ef40:7730:8e70:5aff:fefe:edac:";
// 		u.path = Some("/foo");
// assert_eq!(s, u);
//
// },
// { let mut u = Url::new();
// let s = Url::from("http://[2b01:e34:ef40:7730:8e70:5aff:fefe:edac]:8080/foo").unwrap();
//
// 		u.scheme = Some("http");
// 		u.host = "[2b01:e34:ef40:7730:8e70:5aff:fefe:edac]:8080";
// 		u.path = Some("/foo");
// assert_eq!(s, u);
//
// },
// { let mut u = Url::new();
// let s = Url::from("http://[2b01:e34:ef40:7730:8e70:5aff:fefe:edac]:/foo").unwrap();
//
// 		u.scheme = Some("http");
// 		u.host = "[2b01:e34:ef40:7730:8e70:5aff:fefe:edac]:";
// 		u.path = Some("/foo");
// assert_eq!(s, u);
//
// },
// // example.org/issue/7991 and example.org/issue/12719 (non-ascii %-encoded in host)
// { let mut u = Url::new();
// let s = Url::from("http://hello.世界.com/foo").unwrap();
//
// 		u.scheme = Some("http");
// 		u.host = "hello.世界.com";
// 		u.path = Some("/foo");
// assert_eq!(s, u);
// let s = Url::from("http://hello.%E4%B8%96%E7%95%8C.com/foo").unwrap();
// },
// { let mut u = Url::new();
// let s = Url::from("http://hello.%e4%b8%96%e7%95%8c.com/foo").unwrap();
//
// 		u.scheme = Some("http");
// 		u.host = "hello.世界.com";
// 		u.path = Some("/foo");
// assert_eq!(s, u);
// let s = Url::from("http://hello.%E4%B8%96%E7%95%8C.com/foo").unwrap();
// },
// { let mut u = Url::new();
// let s = Url::from("http://hello.%E4%B8%96%E7%95%8C.com/foo").unwrap();
//
// 		u.scheme = Some("http");
// 		u.host = "hello.世界.com";
// 		u.path = Some("/foo");
// assert_eq!(s, u);
//
// },
// // example.org/issue/10433 (path beginning with //)
// { let mut u = Url::new();
// let s = Url::from("http://example.com//foo").unwrap();
//
// 		u.scheme = Some("http");
// 		u.host = "example.com";
// 		u.path = Some("//foo");
// assert_eq!(s, u);
//
// },
// // test that we can reparse the host names we accept.
// { let mut u = Url::new();
// let s = Url::from("myscheme://authority<\"hi\">/foo").unwrap();
//
// 		u.scheme = Some("myscheme");
// 		u.host = "authority<\"hi\">";
// 		u.path = Some("/foo");
// assert_eq!(s, u);
//
// },
// // spaces in hosts are disallowed but escaped spaces in IPv6 scope IDs are grudgingly OK.
// // This happens on Windows.
// // example.org/issue/14002
// { let mut u = Url::new();
// let s = Url::from("tcp://[2020::2020:20:2020:2020%25Windows%20Loves%20Spaces]:2020").unwrap();
//
// 		u.scheme = Some("tcp");
// 		u.host = "[2020::2020:20:2020:2020%Windows Loves Spaces]:2020";
// assert_eq!(s, u);
//
// },
