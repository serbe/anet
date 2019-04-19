use url::Url;

#[test]
fn no_path() {
    assert_eq!(Url::from("http://www.example.org").unwrap(),
    Url{
        scheme: "http",
        host:   "www.example.org",
    });
}

#[test]
fn with_path() {
		assert_eq!(Url::from("http://www.example.org/").unwrap(),
		Url{
			scheme: "http",
			host:   "www.example.org",
			path:   "/",
		});
}

	// // path with hex escaping
	// {
	// 	"http://www.example.org/file%20one%26two",
	// 	&URL{
	// 		scheme:  "http",
	// 		host:    "www.example.org",
	// 		path:    "/file one&two",
	// 		RawPath: "/file%20one%26two",
	// 	},
	// 	"",
	// },
	// // user
	// {
	// 	"ftp://webmaster@www.example.org/",
	// 	&URL{
	// 		scheme: "ftp",
	// 		User:   User("webmaster"),
	// 		host:   "www.example.org",
	// 		path:   "/",
	// 	},
	// 	"",
	// },
	// // escape sequence in username
	// {
	// 	"ftp://john%20doe@www.example.org/",
	// 	&URL{
	// 		scheme: "ftp",
	// 		User:   User("john doe"),
	// 		host:   "www.example.org",
	// 		path:   "/",
	// 	},
	// 	"ftp://john%20doe@www.example.org/",
	// },
	// // empty query
	// {
	// 	"http://www.example.org/?",
	// 	&URL{
	// 		scheme:     "http",
	// 		host:       "www.example.org",
	// 		path:       "/",
	// 		ForceQuery: true,
	// 	},
	// 	"",
	// },
	// // query ending in question mark (Issue 14573)
	// {
	// 	"http://www.example.org/?foo=bar?",
	// 	&URL{
	// 		scheme:   "http",
	// 		host:     "www.example.org",
	// 		path:     "/",
	// 		RawQuery: "foo=bar?",
	// 	},
	// 	"",
	// },
	// // query
	// {
	// 	"http://www.example.org/?q=rust+language",
	// 	&URL{
	// 		scheme:   "http",
	// 		host:     "www.example.org",
	// 		path:     "/",
	// 		RawQuery: "q=rust+language",
	// 	},
	// 	"",
	// },
	// // query with hex escaping: NOT parsed
	// {
	// 	"http://www.example.org/?q=go%20language",
	// 	&URL{
	// 		scheme:   "http",
	// 		host:     "www.example.org",
	// 		path:     "/",
	// 		RawQuery: "q=go%20language",
	// 	},
	// 	"",
	// },
	// // %20 outside query
	// {
	// 	"http://www.example.org/a%20b?q=c+d",
	// 	&URL{
	// 		scheme:   "http",
	// 		host:     "www.example.org",
	// 		path:     "/a b",
	// 		RawQuery: "q=c+d",
	// 	},
	// 	"",
	// },
	// // path without leading /, so no parsing
	// {
	// 	"http:www.example.org/?q=rust+language",
	// 	&URL{
	// 		scheme:   "http",
	// 		Opaque:   "www.example.org/",
	// 		RawQuery: "q=rust+language",
	// 	},
	// 	"http:www.example.org/?q=rust+language",
	// },
	// // path without leading /, so no parsing
	// {
	// 	"http:%2f%2fwww.example.org/?q=rust+language",
	// 	&URL{
	// 		scheme:   "http",
	// 		Opaque:   "%2f%2fwww.example.org/",
	// 		RawQuery: "q=rust+language",
	// 	},
	// 	"http:%2f%2fwww.example.org/?q=rust+language",
	// },
	// // non-authority with path
	// {
	// 	"mailto:/webmaster@example.org",
	// 	&URL{
	// 		scheme: "mailto",
	// 		path:   "/webmaster@example.org",
	// 	},
	// 	"mailto:///webmaster@example.org", // unfortunate compromise
	// },
	// // non-authority
	// {
	// 	"mailto:webmaster@example.org",
	// 	&URL{
	// 		scheme: "mailto",
	// 		Opaque: "webmaster@example.org",
	// 	},
	// 	"",
	// },
	// // unescaped :// in query should not create a scheme
	// {
	// 	"/foo?query=http://bad",
	// 	&URL{
	// 		path:     "/foo",
	// 		RawQuery: "query=http://bad",
	// 	},
	// 	"",
	// },
	// // leading // without scheme should create an authority
	// {
	// 	"//foo",
	// 	&URL{
	// 		host: "foo",
	// 	},
	// 	"",
	// },
	// // leading // without scheme, with userinfo, path, and query
	// {
	// 	"//user@foo/path?a=b",
	// 	&URL{
	// 		User:     User("user"),
	// 		host:     "foo",
	// 		path:     "/path",
	// 		RawQuery: "a=b",
	// 	},
	// 	"",
	// },
	// // Three leading slashes isn't an authority, but doesn't return an error.
	// // (We can't return an error, as this code is also used via
	// // ServeHTTP -> ReadRequest -> Parse, which is arguably a
	// // different URL parsing context, but currently shares the
	// // same codepath)
	// {
	// 	"///threeslashes",
	// 	&URL{
	// 		path: "///threeslashes",
	// 	},
	// 	"",
	// },
	// {
	// 	"http://user:password@google.com",
	// 	&URL{
	// 		scheme: "http",
	// 		User:   UserPassword("user", "password"),
	// 		host:   "google.com",
	// 	},
	// 	"http://user:password@google.com",
	// },
	// // unescaped @ in username should not confuse host
	// {
	// 	"http://j@ne:password@google.com",
	// 	&URL{
	// 		scheme: "http",
	// 		User:   UserPassword("j@ne", "password"),
	// 		host:   "google.com",
	// 	},
	// 	"http://j%40ne:password@google.com",
	// },
	// // unescaped @ in password should not confuse host
	// {
	// 	"http://jane:p@ssword@google.com",
	// 	&URL{
	// 		scheme: "http",
	// 		User:   UserPassword("jane", "p@ssword"),
	// 		host:   "google.com",
	// 	},
	// 	"http://jane:p%40ssword@google.com",
	// },
	// {
	// 	"http://j@ne:password@google.com/p@th?q=@go",
	// 	&URL{
	// 		scheme:   "http",
	// 		User:     UserPassword("j@ne", "password"),
	// 		host:     "google.com",
	// 		path:     "/p@th",
	// 		RawQuery: "q=@go",
	// 	},
	// 	"http://j%40ne:password@google.com/p@th?q=@go",
	// },
	// {
	// 	"http://www.example.org/?q=rust+language#foo",
	// 	&URL{
	// 		scheme:   "http",
	// 		host:     "www.example.org",
	// 		path:     "/",
	// 		RawQuery: "q=rust+language",
	// 		Fragment: "foo",
	// 	},
	// 	"",
	// },
	// {
	// 	"http://www.example.org/?q=rust+language#foo%26bar",
	// 	&URL{
	// 		scheme:   "http",
	// 		host:     "www.example.org",
	// 		path:     "/",
	// 		RawQuery: "q=rust+language",
	// 		Fragment: "foo&bar",
	// 	},
	// 	"http://www.example.org/?q=rust+language#foo&bar",
	// },
	// {
	// 	"file:///home/adg/rabbits",
	// 	&URL{
	// 		scheme: "file",
	// 		host:   "",
	// 		path:   "/home/adg/rabbits",
	// 	},
	// 	"file:///home/adg/rabbits",
	// },
	// // "Windows" paths are no exception to the rule.
	// // See example.org/issue/6027, especially comment #9.
	// {
	// 	"file:///C:/FooBar/Baz.txt",
	// 	&URL{
	// 		scheme: "file",
	// 		host:   "",
	// 		path:   "/C:/FooBar/Baz.txt",
	// 	},
	// 	"file:///C:/FooBar/Baz.txt",
	// },
	// // case-insensitive scheme
	// {
	// 	"MaIlTo:webmaster@example.org",
	// 	&URL{
	// 		scheme: "mailto",
	// 		Opaque: "webmaster@example.org",
	// 	},
	// 	"mailto:webmaster@example.org",
	// },
	// // Relative path
	// {
	// 	"a/b/c",
	// 	&URL{
	// 		path: "a/b/c",
	// 	},
	// 	"a/b/c",
	// },
	// // escaped '?' in username and password
	// {
	// 	"http://%3Fam:pa%3Fsword@google.com",
	// 	&URL{
	// 		scheme: "http",
	// 		User:   UserPassword("?am", "pa?sword"),
	// 		host:   "google.com",
	// 	},
	// 	"",
	// },
	// // host subcomponent; IPv4 address in RFC 3986
	// {
	// 	"http://192.168.0.1/",
	// 	&URL{
	// 		scheme: "http",
	// 		host:   "192.168.0.1",
	// 		path:   "/",
	// 	},
	// 	"",
	// },
	// // host and port subcomponents; IPv4 address in RFC 3986
	// {
	// 	"http://192.168.0.1:8080/",
	// 	&URL{
	// 		scheme: "http",
	// 		host:   "192.168.0.1:8080",
	// 		path:   "/",
	// 	},
	// 	"",
	// },
	// // host subcomponent; IPv6 address in RFC 3986
	// {
	// 	"http://[fe80::1]/",
	// 	&URL{
	// 		scheme: "http",
	// 		host:   "[fe80::1]",
	// 		path:   "/",
	// 	},
	// 	"",
	// },
	// // host and port subcomponents; IPv6 address in RFC 3986
	// {
	// 	"http://[fe80::1]:8080/",
	// 	&URL{
	// 		scheme: "http",
	// 		host:   "[fe80::1]:8080",
	// 		path:   "/",
	// 	},
	// 	"",
	// },
	// // host subcomponent; IPv6 address with zone identifier in RFC 6874
	// {
	// 	"http://[fe80::1%25en0]/", // alphanum zone identifier
	// 	&URL{
	// 		scheme: "http",
	// 		host:   "[fe80::1%en0]",
	// 		path:   "/",
	// 	},
	// 	"",
	// },
	// // host and port subcomponents; IPv6 address with zone identifier in RFC 6874
	// {
	// 	"http://[fe80::1%25en0]:8080/", // alphanum zone identifier
	// 	&URL{
	// 		scheme: "http",
	// 		host:   "[fe80::1%en0]:8080",
	// 		path:   "/",
	// 	},
	// 	"",
	// },
	// // host subcomponent; IPv6 address with zone identifier in RFC 6874
	// {
	// 	"http://[fe80::1%25%65%6e%301-._~]/", // percent-encoded+unreserved zone identifier
	// 	&URL{
	// 		scheme: "http",
	// 		host:   "[fe80::1%en01-._~]",
	// 		path:   "/",
	// 	},
	// 	"http://[fe80::1%25en01-._~]/",
	// },
	// // host and port subcomponents; IPv6 address with zone identifier in RFC 6874
	// {
	// 	"http://[fe80::1%25%65%6e%301-._~]:8080/", // percent-encoded+unreserved zone identifier
	// 	&URL{
	// 		scheme: "http",
	// 		host:   "[fe80::1%en01-._~]:8080",
	// 		path:   "/",
	// 	},
	// 	"http://[fe80::1%25en01-._~]:8080/",
	// },
	// // alternate escapings of path survive round trip
	// {
	// 	"http://rest.rsc.io/foo%2fbar/baz%2Fquux?alt=media",
	// 	&URL{
	// 		scheme:   "http",
	// 		host:     "rest.rsc.io",
	// 		path:     "/foo/bar/baz/quux",
	// 		RawPath:  "/foo%2fbar/baz%2Fquux",
	// 		RawQuery: "alt=media",
	// 	},
	// 	"",
	// },
	// // issue 12036
	// {
	// 	"mysql://a,b,c/bar",
	// 	&URL{
	// 		scheme: "mysql",
	// 		host:   "a,b,c",
	// 		path:   "/bar",
	// 	},
	// 	"",
	// },
	// // worst case host, still round trips
	// {
	// 	"scheme://!$&'()*+,;=hello!:port/path",
	// 	&URL{
	// 		scheme: "scheme",
	// 		host:   "!$&'()*+,;=hello!:port",
	// 		path:   "/path",
	// 	},
	// 	"",
	// },
	// // worst case path, still round trips
	// {
	// 	"http://host/!$&'()*+,;=:@[hello]",
	// 	&URL{
	// 		scheme:  "http",
	// 		host:    "host",
	// 		path:    "/!$&'()*+,;=:@[hello]",
	// 		RawPath: "/!$&'()*+,;=:@[hello]",
	// 	},
	// 	"",
	// },
	// // example.org/issue/5684
	// {
	// 	"http://example.com/oid/[order_id]",
	// 	&URL{
	// 		scheme:  "http",
	// 		host:    "example.com",
	// 		path:    "/oid/[order_id]",
	// 		RawPath: "/oid/[order_id]",
	// 	},
	// 	"",
	// },
	// // example.org/issue/12200 (colon with empty port)
	// {
	// 	"http://192.168.0.2:8080/foo",
	// 	&URL{
	// 		scheme: "http",
	// 		host:   "192.168.0.2:8080",
	// 		path:   "/foo",
	// 	},
	// 	"",
	// },
	// {
	// 	"http://192.168.0.2:/foo",
	// 	&URL{
	// 		scheme: "http",
	// 		host:   "192.168.0.2:",
	// 		path:   "/foo",
	// 	},
	// 	"",
	// },
	// {
	// 	// Malformed IPv6 but still accepted.
	// 	"http://2b01:e34:ef40:7730:8e70:5aff:fefe:edac:8080/foo",
	// 	&URL{
	// 		scheme: "http",
	// 		host:   "2b01:e34:ef40:7730:8e70:5aff:fefe:edac:8080",
	// 		path:   "/foo",
	// 	},
	// 	"",
	// },
	// {
	// 	// Malformed IPv6 but still accepted.
	// 	"http://2b01:e34:ef40:7730:8e70:5aff:fefe:edac:/foo",
	// 	&URL{
	// 		scheme: "http",
	// 		host:   "2b01:e34:ef40:7730:8e70:5aff:fefe:edac:",
	// 		path:   "/foo",
	// 	},
	// 	"",
	// },
	// {
	// 	"http://[2b01:e34:ef40:7730:8e70:5aff:fefe:edac]:8080/foo",
	// 	&URL{
	// 		scheme: "http",
	// 		host:   "[2b01:e34:ef40:7730:8e70:5aff:fefe:edac]:8080",
	// 		path:   "/foo",
	// 	},
	// 	"",
	// },
	// {
	// 	"http://[2b01:e34:ef40:7730:8e70:5aff:fefe:edac]:/foo",
	// 	&URL{
	// 		scheme: "http",
	// 		host:   "[2b01:e34:ef40:7730:8e70:5aff:fefe:edac]:",
	// 		path:   "/foo",
	// 	},
	// 	"",
	// },
	// // example.org/issue/7991 and example.org/issue/12719 (non-ascii %-encoded in host)
	// {
	// 	"http://hello.世界.com/foo",
	// 	&URL{
	// 		scheme: "http",
	// 		host:   "hello.世界.com",
	// 		path:   "/foo",
	// 	},
	// 	"http://hello.%E4%B8%96%E7%95%8C.com/foo",
	// },
	// {
	// 	"http://hello.%e4%b8%96%e7%95%8c.com/foo",
	// 	&URL{
	// 		scheme: "http",
	// 		host:   "hello.世界.com",
	// 		path:   "/foo",
	// 	},
	// 	"http://hello.%E4%B8%96%E7%95%8C.com/foo",
	// },
	// {
	// 	"http://hello.%E4%B8%96%E7%95%8C.com/foo",
	// 	&URL{
	// 		scheme: "http",
	// 		host:   "hello.世界.com",
	// 		path:   "/foo",
	// 	},
	// 	"",
	// },
	// // example.org/issue/10433 (path beginning with //)
	// {
	// 	"http://example.com//foo",
	// 	&URL{
	// 		scheme: "http",
	// 		host:   "example.com",
	// 		path:   "//foo",
	// 	},
	// 	"",
	// },
	// // test that we can reparse the host names we accept.
	// {
	// 	"myscheme://authority<\"hi\">/foo",
	// 	&URL{
	// 		scheme: "myscheme",
	// 		host:   "authority<\"hi\">",
	// 		path:   "/foo",
	// 	},
	// 	"",
	// },
	// // spaces in hosts are disallowed but escaped spaces in IPv6 scope IDs are grudgingly OK.
	// // This happens on Windows.
	// // example.org/issue/14002
	// {
	// 	"tcp://[2020::2020:20:2020:2020%25Windows%20Loves%20Spaces]:2020",
	// 	&URL{
	// 		scheme: "tcp",
	// 		host:   "[2020::2020:20:2020:2020%Windows Loves Spaces]:2020",
	// 	},
	// 	"",
	// },