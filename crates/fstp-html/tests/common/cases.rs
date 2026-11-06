//! Fixed documents on both sides of the subset's boundary.
//!
//! Each refused document breaks exactly one rule of `reference`, so a
//! checker that accepts it has lost that rule. Each accepted document uses
//! a spelling the subset allows but a writer may not produce, so a checker
//! that refuses it is stricter than the subset.

const HEAD: &str = "<head><meta charset=\"utf-8\"><title>T</title></head>";

/// A document with `body` as the content of `<body>`.
pub(crate) fn with_body(body: &str) -> Vec<u8> {
    format!("<!DOCTYPE html><html lang=\"en\">{HEAD}<body>{body}</body></html>").into_bytes()
}

/// A document with `head` as the content of `<head>`.
pub(crate) fn with_head(head: &str) -> Vec<u8> {
    format!("<!DOCTYPE html><html lang=\"en\"><head>{head}</head><body></body></html>").into_bytes()
}

/// Documents the subset refuses, each with the rule it breaks.
pub(crate) fn refused() -> Vec<(&'static str, Vec<u8>)> {
    let mut v: Vec<(&'static str, Vec<u8>)> = vec![
        (
            "missing doctype",
            format!("<html lang=\"en\">{HEAD}<body></body></html>").into_bytes(),
        ),
        (
            "text before html",
            format!("<!DOCTYPE html>x<html lang=\"en\">{HEAD}<body></body></html>").into_bytes(),
        ),
        (
            "leading byte order mark",
            format!("\u{feff}<!DOCTYPE html><html lang=\"en\">{HEAD}<body></body></html>")
                .into_bytes(),
        ),
        ("content after html end", {
            let mut d = with_body("");
            d.push(b'x');
            d
        }),
        ("line feed after html end", {
            let mut d = with_body("");
            d.push(b'\n');
            d
        }),
        (
            "missing lang",
            format!("<!DOCTYPE html><html>{HEAD}<body></body></html>").into_bytes(),
        ),
        (
            "lang not a language tag",
            format!("<!DOCTYPE html><html lang=\"e\">{HEAD}<body></body></html>").into_bytes(),
        ),
        (
            "missing head",
            b"<!DOCTYPE html><html lang=\"en\"><body></body></html>".to_vec(),
        ),
        (
            "two bodies",
            format!("<!DOCTYPE html><html lang=\"en\">{HEAD}<body></body><body></body></html>")
                .into_bytes(),
        ),
        ("missing meta charset", with_head("<title>T</title>")),
        (
            "wrong charset",
            with_head("<meta charset=\"latin1\"><title>T</title>"),
        ),
        ("missing title", with_head("<meta charset=\"utf-8\">")),
        (
            "two titles",
            with_head("<meta charset=\"utf-8\"><title>T</title><title>U</title>"),
        ),
        (
            "markup in title",
            with_head("<meta charset=\"utf-8\"><title><b>T</b></title>"),
        ),
        (
            "meta refresh",
            with_head(
                "<meta charset=\"utf-8\"><title>T</title><meta http-equiv=\"refresh\" content=\"0\">",
            ),
        ),
        (
            "base element",
            with_head("<meta charset=\"utf-8\"><title>T</title><base href=\"/\">"),
        ),
        (
            "script in head",
            with_head("<meta charset=\"utf-8\"><title>T</title><script src=\"/a.js\"></script>"),
        ),
        (
            "stylesheet link to another origin",
            with_head(
                "<meta charset=\"utf-8\"><title>T</title><link rel=\"stylesheet\" href=\"//cdn.example/s.css\">",
            ),
        ),
        ("script element", with_body("<script>alert(1)</script>")),
        ("style element", with_body("<style>p{}</style>")),
        ("iframe", with_body("<iframe></iframe>")),
        ("object", with_body("<object></object>")),
        // Lane j3 (ADR-015): the closed SVG subset is allowed, so a bare
        // `svg` is no longer a refusal. Foreign content outside that
        // subset still is.
        (
            "svg holding a foreign object",
            with_body("<svg><foreignobject></foreignobject></svg>"),
        ),
        (
            "svg holding a script",
            with_body("<svg><script></script></svg>"),
        ),
        ("math", with_body("<math></math>")),
        ("template", with_body("<template></template>")),
        ("noscript", with_body("<noscript></noscript>")),
        ("unknown element", with_body("<blink>a</blink>")),
        ("upper-case tag", with_body("<P>a</P>")),
        ("comment", with_body("<!-- a -->")),
        ("CDATA section", with_body("<![CDATA[a]]>")),
        (
            "processing instruction",
            with_body("<?xml version=\"1.0\"?>"),
        ),
        ("nested doctype", with_body("<!DOCTYPE html>")),
        (
            "event handler attribute",
            with_body("<p onclick=\"a()\">a</p>"),
        ),
        ("style attribute", with_body("<p style=\"color:red\">a</p>")),
        ("srcdoc attribute", with_body("<p srcdoc=\"x\">a</p>")),
        (
            "formaction attribute",
            with_body("<button formaction=\"/x\">a</button>"),
        ),
        (
            "target attribute",
            with_body("<a href=\"/\" target=\"_blank\">a</a>"),
        ),
        ("data attribute", with_body("<p data-x=\"1\">a</p>")),
        ("upper-case attribute", with_body("<p TITLE=\"a\">a</p>")),
        ("single-quoted attribute", with_body("<p title='a'>a</p>")),
        ("unquoted attribute", with_body("<p title=a>a</p>")),
        ("spaces around equals", with_body("<p title = \"a\">a</p>")),
        (
            "duplicate attribute",
            with_body("<p title=\"a\" title=\"b\">a</p>"),
        ),
        (
            "no space between attributes",
            with_body("<p title=\"a\"id=\"b\">a</p>"),
        ),
        ("unterminated attribute", with_body("<p title=\"a>a</p>")),
        ("self-closing non-void element", with_body("<div/>")),
        ("end tag of void element", with_body("<br></br>")),
        ("end tag with attribute", with_body("<p>a</p class=\"x\">")),
        ("end tag with space", with_body("<p>a</p >")),
        ("unclosed element", with_body("<div>a")),
        (
            "mismatched end tags",
            with_body("<div><span>a</div></span>"),
        ),
        ("stray end tag", with_body("a</p>")),
        ("raw less-than in text", with_body("a < b")),
        ("raw less-than before a letter", with_body("a <b")),
        ("bare ampersand", with_body("a & b")),
        ("unterminated named reference", with_body("&amp b")),
        ("unterminated numeric reference", with_body("&#60 b")),
        ("empty numeric reference", with_body("&#;")),
        ("named reference outside the five", with_body("&nbsp;")),
        ("named reference in upper case", with_body("&AMP;")),
        ("reference to NUL", with_body("&#0;")),
        ("reference to a C0 control", with_body("&#1;")),
        ("reference to CR", with_body("&#13;")),
        ("reference to DEL", with_body("&#127;")),
        ("reference to a C1 control", with_body("&#128;")),
        ("reference to a surrogate", with_body("&#xD800;")),
        ("reference beyond Unicode", with_body("&#x110000;")),
        ("overlong reference", with_body("&#99999999999999999999;")),
        ("reference to a noncharacter", with_body("&#xFFFE;")),
        ("raw NUL", with_body("a\u{0}b")),
        ("raw CR", with_body("a\rb")),
        ("raw form feed", with_body("a\u{c}b")),
        ("raw DEL", with_body("a\u{7f}b")),
        ("raw C1 control", with_body("a\u{85}b")),
        ("raw noncharacter", with_body("a\u{fdd0}b")),
        (
            "raw NUL in attribute",
            with_body("<p title=\"a\u{0}b\">a</p>"),
        ),
        ("raw CR in attribute", with_body("<p title=\"a\rb\">a</p>")),
        (
            "bare ampersand in attribute",
            with_body("<p title=\"a & b\">a</p>"),
        ),
        (
            "raw less-than in textarea",
            with_body("<textarea>a<b</textarea>"),
        ),
        (
            "end tag spelt in upper case in textarea",
            with_body("<textarea>a</TEXTAREA>"),
        ),
        (
            "javascript href",
            with_body("<a href=\"javascript:alert(1)\">a</a>"),
        ),
        (
            "javascript href by reference",
            with_body("<a href=\"&#106;avascript:alert(1)\">a</a>"),
        ),
        (
            "javascript href in upper case",
            with_body("<a href=\"JAVASCRIPT:alert(1)\">a</a>"),
        ),
        ("data href", with_body("<a href=\"data:text/html,x\">a</a>")),
        (
            "protocol-relative href",
            with_body("<a href=\"//evil.example/\">a</a>"),
        ),
        (
            "backslash href",
            with_body("<a href=\"/\\evil.example/\">a</a>"),
        ),
        (
            "tab in href",
            with_body("<a href=\"/&#9;/evil.example/\">a</a>"),
        ),
        (
            "line feed in href",
            with_body("<a href=\"/\n/evil.example/\">a</a>"),
        ),
        ("space in href", with_body("<a href=\"/a b\">a</a>")),
        ("non-ASCII href", with_body("<a href=\"/\u{e9}\">a</a>")),
        (
            "http href",
            with_body("<a href=\"http://example.org/\">a</a>"),
        ),
        ("relative href", with_body("<a href=\"x/y\">a</a>")),
        ("empty href", with_body("<a href=\"\">a</a>")),
        ("bare href", with_body("<a href>a</a>")),
        (
            "data image source",
            with_body("<img src=\"data:image/png;base64,AA\" alt=\"\">"),
        ),
        (
            "javascript form action",
            with_body("<form action=\"javascript:a()\"></form>"),
        ),
        ("block inside p", with_body("<p><div>a</div></p>")),
        ("list inside p", with_body("<p><ul><li>a</li></ul></p>")),
        ("rule inside p", with_body("<p>a<hr>b</p>")),
        (
            "p inside p through span",
            with_body("<p><span><p>a</p></span></p>"),
        ),
        ("heading inside heading", with_body("<h1><h2>a</h2></h1>")),
        (
            "nested anchors",
            with_body("<a href=\"/a\"><a href=\"/b\">x</a></a>"),
        ),
        (
            "nested forms",
            with_body("<form><div><form></form></div></form>"),
        ),
        (
            "nested buttons",
            with_body("<button><button>a</button></button>"),
        ),
        (
            "row directly in table",
            with_body("<table><tr><td>a</td></tr></table>"),
        ),
        (
            "text in table",
            with_body("<table>a<tbody></tbody></table>"),
        ),
        (
            "text in row",
            with_body("<table><tbody><tr>a</tr></tbody></table>"),
        ),
        ("cell outside a row", with_body("<td>a</td>")),
        (
            "table in caption",
            with_body("<table><caption><table></table></caption></table>"),
        ),
        ("list item outside a list", with_body("<li>a</li>")),
        ("text in list", with_body("<ul>a<li>b</li></ul>")),
        ("div in list", with_body("<ul><div></div></ul>")),
        ("term outside a definition list", with_body("<dt>a</dt>")),
        (
            "element in option",
            with_body("<select><option><b>a</b></option></select>"),
        ),
        (
            "text in select",
            with_body("<select>a<option>b</option></select>"),
        ),
        ("option outside select", with_body("<option>a</option>")),
        ("title in body", with_body("<title>a</title>")),
        ("meta in body", with_body("<meta name=\"a\" content=\"b\">")),
    ];
    v.push(("invalid UTF-8", {
        let mut d = with_body("a");
        let at = d.len() - "</body></html>".len();
        d.insert(at, 0xFF);
        d
    }));
    v.push(("truncated UTF-8", {
        let mut d = with_body("a");
        let at = d.len() - "</body></html>".len();
        d.insert(at, 0xC3);
        d
    }));
    v.push(("empty input", Vec::new()));
    v
}

/// Documents the subset accepts, each with the allowance it uses.
pub(crate) fn accepted() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("empty body", with_body("")),
        (
            "lower-case doctype and layout whitespace",
            b"<!doctype html>\n<html lang=\"fr-CA\">\n<head>\n<meta charset=\"utf-8\">\n<title>T</title>\n</head>\n<body></body>\n</html>".to_vec(),
        ),
        (
            "stylesheet and description",
            with_head(
                "<meta charset=\"utf-8\"><title>T</title><link rel=\"stylesheet\" href=\"/s.css\"><meta name=\"description\" content=\"d\">",
            ),
        ),
        (
            "every reference spelling",
            with_body("<p>&amp;&lt;&gt;&quot;&apos;&#39;&#x27;&#X27;&#0039;&#x1F600;&#10;&#9;</p>"),
        ),
        ("raw characters text allows", with_body("<p>a > b \" ' = / ` }</p>")),
        (
            "raw characters attributes allow",
            with_body("<p title=\"a<b>c'd = / &quot; &amp;\">x</p>"),
        ),
        (
            "non-ASCII text",
            with_body("<p>Gr\u{fc}\u{df}e \u{2013} \u{6771}\u{4eac} \u{1F600} \u{a0}\u{200b}\u{fffd}</p>"),
        ),
        ("tab and line feed in text", with_body("<p>a\tb\nc</p>")),
        (
            "boolean attributes bare and empty",
            with_body("<form action=\"/f\"><input required disabled=\"\"><select><option selected>a</option></select></form>"),
        ),
        ("void elements with and without slash", with_body("<p>a<br>b<br/>c<br />d<wbr></p><hr>")),
        ("pre with leading line feed", with_body("<pre>\n\nx</pre>")),
        ("pre with leading reference line feed", with_body("<pre>&#10;\nx</pre>")),
        ("textarea with leading line feed", with_body("<textarea>\n\nx &lt;/textarea&gt;</textarea>")),
        (
            "whitespace in containers",
            with_body("<ul>\n  <li>a</li>\n</ul><dl> <dt>t</dt> <dd>d</dd> </dl><select>\n<option>a</option>\n</select>"),
        ),
        (
            "full table",
            with_body("<table><caption>c</caption><thead><tr><th scope=\"col\">h</th></tr></thead><tbody>\n<tr><td>d</td></tr>\n</tbody><tfoot><tr><td>f</td></tr></tfoot></table>"),
        ),
        (
            "same-origin and https links",
            with_body("<a href=\"/\">a</a><a href=\"/p/x/calls/y?z=1#top\">b</a><a href=\"https://example.org/x\">c</a>"),
        ),
        (
            "link by references",
            with_body("<a href=\"/a&amp;b&#x3D;c\">a</a>"),
        ),
        (
            "aria and global attributes",
            with_body("<nav aria-label=\"Main\" id=\"n\" class=\"c d\" role=\"navigation\"><ul><li><a href=\"/\">Home</a></li></ul></nav>"),
        ),
        (
            "phrasing inside p",
            with_body("<p><a href=\"/\"><strong>a</strong></a><em>b</em><code>c</code><small>d</small><time datetime=\"2026-10-30\">e</time><label for=\"x\">f</label><input id=\"x\"><button type=\"submit\">g</button><select><option>h</option></select><textarea>i</textarea><img src=\"/i.png\" alt=\"j\"></p>"),
        ),
        (
            "blocks inside form, list and cell",
            with_body("<form action=\"/f\" method=\"post\"><div><p>a</p></div></form><ul><li><div><p>b</p></div></li></ul><table><tbody><tr><td><p>c</p><table><tbody><tr><td>d</td></tr></tbody></table></td></tr></tbody></table>"),
        ),
        (
            "details, figure and fieldset",
            with_body("<details open><summary>s</summary><p>a</p></details><figure><figcaption>c</figcaption></figure><fieldset><legend>l</legend></fieldset>"),
        ),
        ("whitespace inside a start tag", with_body("<p\ttitle=\"a\"\n>x</p>")),
    ]
}
