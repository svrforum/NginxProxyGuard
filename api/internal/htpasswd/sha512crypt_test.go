package htpasswd

import (
	"strings"
	"testing"
)

// Vectors from `openssl passwd -6 -salt <salt> <password>`, which agrees with
// glibc and musl crypt(). The 70-byte key crosses the 64-byte block, the
// Korean one is multibyte, and "./9Az" is a salt shorter than 16.
func TestSHA512CryptMatchesOpenSSL(t *testing.T) {
	cases := []struct{ password, salt, want string }{
		{"Hello world!", "saltstring", "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"},
		{"Hello world!", "abcdefghijklmnop", "$6$abcdefghijklmnop$QHIFY5kc1kz.IbvL93uE1dch/by2Y7vCuMbwuEBxMP1NEAB5NvpcgGSpdKQkNYQUZ54mM9gicC5bYr2OQXmkh."},
		{"Hello world!", "./9Az", "$6$./9Az$.zWoNIKfBzig2u/QQU6gaiGjTJEm0cpehQFnlr60WDn0mSNIgkzSt8.uSBSMFnZhsbEdkCQRoYosTR9GFcq5G0"},
		{"correct horse battery staple", "saltstring", "$6$saltstring$qvPJY4PeugKzKQqyIJ0gRdJnpS0uaaiZ.X1SaheFedsK/yZPwlluTLS90fJPM41sD5JxCHKgGr1..qt5HqEY8."},
		{"correct horse battery staple", "abcdefghijklmnop", "$6$abcdefghijklmnop$UY4jc6.rVibJ9tqDqiG0GMdZRHkv1j4sPRRH2eUSo3Kszltzbk30CmYcWPNRTD/KsYFHF7WTtNkAxF3dZ3zPE."},
		{"correct horse battery staple", "./9Az", "$6$./9Az$smIxQ93gPOedcLEGaGIGuCZInH/jjAx21AwXQzKptxS1ANlkk0Dwg3Y5iQFRYKa5fWO9ja91GJcF9ZdO2.CoJ."},
		{strings.Repeat("x", 70), "saltstring", "$6$saltstring$3erWN/n45R1SsGcJ7NRlQaFuHPXhHClKZQDKfh/jWEbW0llkR4iwRKYjP1Ogpd7h/U.ZdZIswbqcSiRTQaqaS1"},
		{strings.Repeat("x", 70), "abcdefghijklmnop", "$6$abcdefghijklmnop$hS6.x2w4anxWHGjXX7i28a6dY/P0WGi0KacxJzfEivO5MUSdPZX.ifrKoLvK2ajBcrtkSsyC6V.5jd5O50FYy1"},
		{strings.Repeat("x", 70), "./9Az", "$6$./9Az$S/c5ogUPN/3609Tv0CG0SGSzc84w64rJyIQxPUwQ1kIiMAUqCTgG7mHSTwznRekgsRJVUHMAhIG6GQ6R5XNfz."},
		{"pässwörd-한글", "saltstring", "$6$saltstring$xfHzMwAzKe6Rmyh3JDF81rN5W6rgKh/VbEMjqJQQaZBBr8u3wyxvqecVoyunX1RZwnRIMWvyTLyWdOB9N9ezL."},
		{"pässwörd-한글", "abcdefghijklmnop", "$6$abcdefghijklmnop$2Xt4uoBzQp5kmqkP9lYd20YcIvs65SByHtWGfDUdWKz9VCBrYlqT8VAtfQDalOM1kH.5dRF18nfJ3ZGN6hL4m/"},
		{"pässwörd-한글", "./9Az", "$6$./9Az$0pfCqDE20u8t4ZWdDWMjR60eSgosN6cgQOrKpJtWrwd6Kp714t8yBOy6vfvYaIyAjZ/2wHgPOGUjMAPYTgYsj0"},
		{"a", "saltstring", "$6$saltstring$MO53nAXQUKXVLlsbiXyPgMsR6q10N7eF7sPvanwdXnEeCj5kE3eYaRvFv0wVW1UZ4SnNTzc1v4OCOq1ASDQZY0"},
		{"a", "abcdefghijklmnop", "$6$abcdefghijklmnop$5IETrK7DfmBLCcDDd2uUkHSMDWAJF6Icsj01AxgOg03tQ1u38QhUaKCWDwYi/e/EJYW.XtfPCzI7EG7M7zlvZ."},
		{"a", "./9Az", "$6$./9Az$czgdDE5KjBLhtnUFYZb3i3fBG0bHQ4OsejxJNyTgTA3X7t6gmo6EGz07SoPm7.tXiOHd4esvvF9mAYyQHVC.z/"},
	}
	for _, tc := range cases {
		if got := sha512Crypt([]byte(tc.password), []byte(tc.salt)); got != tc.want {
			t.Errorf("sha512Crypt(%q, %q) = %q, want %q", tc.password, tc.salt, got, tc.want)
		}
	}
}

func TestHashIsSaltedAndRecognised(t *testing.T) {
	a, err := Hash("same password")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Hash("same password")
	if a == b {
		t.Error("two hashes of one password are equal: the salt is not random")
	}
	for _, h := range []string{a, b, "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"} {
		if !IsHash(h) {
			t.Errorf("IsHash(%q) = false", h)
		}
	}
	for _, h := range []string{"", "plain", "$1$abc$def", "$6$salt$short", a + "\nuser2:x", "$6$sa:t$" + strings.Repeat("a", 86)} {
		if IsHash(h) {
			t.Errorf("IsHash(%q) = true", h)
		}
	}
}
