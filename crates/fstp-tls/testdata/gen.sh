#!/usr/bin/env bash
# Regenerates the TLS test certificates in this directory.
#
# Every key is ECDSA P-256 in PKCS#8 PEM. Every certificate is valid for
# 100 years (36525 days) from the time of generation. These files are test
# fixtures only. They must never be used outside tests.
#
# Files:
#   ca.pem, ca-key.pem                     trusted test CA
#   server.pem, server-key.pem             server leaf signed by the test CA,
#                                          SAN DNS:localhost, IP:127.0.0.1, IP:::1,
#                                          EKU serverAuth
#   client.pem, client-key.pem             client leaf signed by the test CA,
#                                          CN fstp-test-client, EKU clientAuth
#   untrusted-ca.pem, untrusted-ca-key.pem second CA that no test trusts
#   untrusted-server.pem, untrusted-server-key.pem
#                                          server leaf signed by the untrusted CA,
#                                          same SANs as server.pem
#   untrusted-client.pem, untrusted-client-key.pem
#                                          client leaf signed by the untrusted CA
#   role-<role>.pem, role-<role>-key.pem   database client leaf signed by the
#                                          test CA, CN <role>, EKU clientAuth,
#                                          no SAN, for each role in ROLES below
#
# The database roles are the PostgreSQL roles that fstp-pgtest creates.
# Every hostssl line in its pg_hba.conf has clientcert=verify-full, so the
# certificate CN must equal the role name (D2, R-NF-09).
#
# Usage:
#   bash gen.sh         regenerate every file, including a new CA
#   bash gen.sh roles   regenerate only the role-*.pem files, signed by the
#                       existing ca.pem and ca-key.pem; nothing else changes
# The script writes next to itself and can run from any directory.
# Requires: bash and the openssl command line tool (tested with OpenSSL 3.0).

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

MODE="${1:-all}"
case "$MODE" in
    all | roles) ;;
    *)
        echo "usage: bash gen.sh [roles]" >&2
        exit 2
        ;;
esac

# The PostgreSQL roles that tests connect as. Keep in sync with
# crates/fstp-pgtest/src/server.rs and crates/fstp-pgtest/src/tls.rs.
ROLES=(fstp_super fstp_app)

DAYS=36525
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

genkey() {
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"
}

serial() {
    # 16 random bytes with the top bit cleared, so the serial is positive.
    printf '0x%s' "$(openssl rand -hex 16 | sed 's/^./0/')"
}

make_ca() {
    local name="$1" cn="$2"
    genkey "$name-key.pem"
    cat > "$TMP/$name.ext" <<EXT
[req]
distinguished_name = dn
prompt = no
[dn]
CN = $cn
O = FSTP test fixtures
[v3_ca]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EXT
    openssl req -new -x509 -sha256 -days "$DAYS" -set_serial "$(serial)" \
        -key "$name-key.pem" -config "$TMP/$name.ext" -extensions v3_ca \
        -out "$name.pem"
}

make_leaf() {
    local name="$1" cn="$2" ca="$3" eku="$4" san="$5"
    genkey "$name-key.pem"
    cat > "$TMP/$name.ext" <<EXT
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = $eku
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EXT
    if [ -n "$san" ]; then
        echo "subjectAltName = $san" >> "$TMP/$name.ext"
    fi
    openssl req -new -sha256 -key "$name-key.pem" \
        -subj "/CN=$cn/O=FSTP test fixtures" -out "$TMP/$name.csr"
    openssl x509 -req -sha256 -days "$DAYS" -set_serial "$(serial)" \
        -in "$TMP/$name.csr" -CA "$ca.pem" -CAkey "$ca-key.pem" \
        -extfile "$TMP/$name.ext" -out "$name.pem"
}

if [ "$MODE" = all ]; then
    SERVER_SAN="DNS:localhost, IP:127.0.0.1, IP:::1"

    make_ca ca "FSTP Test CA"
    make_leaf server localhost ca serverAuth "$SERVER_SAN"
    make_leaf client fstp-test-client ca clientAuth "DNS:fstp-test-client"

    make_ca untrusted-ca "FSTP Untrusted Test CA"
    make_leaf untrusted-server localhost untrusted-ca serverAuth "$SERVER_SAN"
    make_leaf untrusted-client fstp-test-client untrusted-ca clientAuth "DNS:fstp-test-client"

    # Sanity checks: each leaf verifies against its own CA and not the other.
    openssl verify -CAfile ca.pem server.pem client.pem > /dev/null
    openssl verify -CAfile untrusted-ca.pem untrusted-server.pem untrusted-client.pem > /dev/null
    if openssl verify -CAfile ca.pem untrusted-server.pem > /dev/null 2>&1; then
        echo "untrusted-server.pem unexpectedly verifies against ca.pem" >&2
        exit 1
    fi
else
    for f in ca.pem ca-key.pem; do
        if [ ! -s "$f" ]; then
            echo "$f is missing; run 'bash gen.sh' to regenerate everything" >&2
            exit 1
        fi
    done
fi

# One client certificate per database role, CN = role name.
for role in "${ROLES[@]}"; do
    make_leaf "role-$role" "$role" ca clientAuth ""
    openssl verify -CAfile ca.pem "role-$role.pem" > /dev/null
    if openssl verify -CAfile untrusted-ca.pem "role-$role.pem" > /dev/null 2>&1; then
        echo "role-$role.pem unexpectedly verifies against untrusted-ca.pem" >&2
        exit 1
    fi
    subject="$(openssl x509 -in "role-$role.pem" -noout -subject -nameopt RFC2253)"
    if [ "$subject" != "subject=O=FSTP test fixtures,CN=$role" ]; then
        echo "role-$role.pem has an unexpected subject: $subject" >&2
        exit 1
    fi
done

chmod 0644 ./*.pem
echo "regenerated test certificates ($MODE) in $(pwd)"
