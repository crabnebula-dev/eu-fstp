//! The server side of the keyd protocol: the request decoder and the
//! response encoder. The wire form is recorded in `fstp_custody::keyd`,
//! whose client encodes requests and decodes responses with its own
//! code. Each decoder accepts exactly one spelling.

use fstp_custody::keyd::{
    self as wire, KeydFrame, MAX_AAD_LEN, MAX_HANDLE_LEN, MAX_USAGE_RECORD_LEN, MAX_USAGE_RECORDS,
    MAX_WRAPPED_LEN, REQUEST_ID_LEN, Request, RequestId, Response, RootHandle,
};
use fstp_custody::{CellId, Chain, Epoch};
use zeroize::Zeroizing;

use crate::KeydError;

/// Decodes one whole request frame. Fuzzed (`keyd_request_decode`).
///
/// # Errors
///
/// Refuses any input that is not one request in its one spelling.
pub fn decode_request(bytes: &[u8]) -> Result<Request, KeydError> {
    let frame =
        wire::decode_frame(bytes).map_err(|_| KeydError::Malformed("not one keyd frame"))?;
    let mut r = Reader::new(&frame.body);
    let id = RequestId(r.array::<REQUEST_ID_LEN>()?);
    let request = match frame.kind {
        wire::KIND_CREATE => {
            let cell = match r.u8()? {
                0 => None,
                1 => Some(CellId(r.array()?)),
                _ => return Err(KeydError::Malformed("a cell flag is neither 0 nor 1")),
            };
            let chain = r.chain()?;
            let epoch = Epoch(r.u64()?);
            Request::CreateRoot {
                id,
                cell,
                chain,
                epoch,
            }
        }
        wire::KIND_WRAP => {
            let root = r.root()?;
            let aad = r.u16_bytes(MAX_AAD_LEN)?.to_vec();
            let key = fstp_custody::key_box(r.take(32)?)
                .map_err(|_| KeydError::Malformed("a seal key is 32 bytes"))?;
            Request::Wrap { id, root, aad, key }
        }
        wire::KIND_UNWRAP => {
            let root = r.root()?;
            let aad = r.u16_bytes(MAX_AAD_LEN)?.to_vec();
            let wrapped = r.u16_bytes(MAX_WRAPPED_LEN)?.to_vec();
            Request::Unwrap {
                id,
                root,
                aad,
                wrapped,
            }
        }
        wire::KIND_DESTROY => Request::Destroy {
            id,
            root: r.root()?,
        },
        wire::KIND_SIGN => {
            let key = r.handle()?;
            let digest = r.array::<32>()?;
            Request::Sign { id, key, digest }
        }
        wire::KIND_DESTROY_SIGN_KEY => Request::DestroySignKey {
            id,
            key: r.handle()?,
        },
        wire::KIND_USAGE => {
            let root = r.root()?;
            let cursor = r.u64()?;
            Request::UsageSince { id, root, cursor }
        }
        _ => return Err(KeydError::Malformed("an unknown request kind")),
    };
    r.end()?;
    Ok(request)
}

/// Encodes `response` as the whole frame the server sends.
///
/// # Errors
///
/// Refuses a field above its limit.
pub fn encode_response(response: &Response) -> Result<Vec<u8>, KeydError> {
    let mut b = Zeroizing::new(Vec::new());
    let kind = match response {
        Response::Root(root) => {
            b.extend_from_slice(&root.encode());
            wire::KIND_ROOT
        }
        Response::Wrapped(w) => {
            put_u16_bytes(&mut b, w, MAX_WRAPPED_LEN)?;
            wire::KIND_WRAPPED
        }
        Response::Unwrapped(k) => {
            b.extend_from_slice(&k[..]);
            wire::KIND_UNWRAPPED
        }
        Response::Destroyed(r) => {
            put_u16_bytes(&mut b, r, wire::MAX_FRAME_BODY)?;
            wire::KIND_DESTROYED
        }
        Response::Signed(s) => {
            put_u16_bytes(&mut b, s, wire::MAX_FRAME_BODY)?;
            wire::KIND_SIGNED
        }
        Response::Usage { records, next } => {
            if records.len() > MAX_USAGE_RECORDS {
                return Err(KeydError::Malformed("too many usage records"));
            }
            b.extend_from_slice(&next.to_be_bytes());
            let n = u16::try_from(records.len())
                .map_err(|_| KeydError::Malformed("too many usage records"))?;
            b.extend_from_slice(&n.to_be_bytes());
            for rec in records {
                put_u16_bytes(&mut b, rec, MAX_USAGE_RECORD_LEN)?;
            }
            wire::KIND_USAGE_PAGE
        }
        Response::Refused(r) => {
            b.push(r.code());
            wire::KIND_REFUSED
        }
    };
    // The body may hold a seal key, so the frame wipes it on drop.
    let frame = KeydFrame { kind, body: b };
    wire::encode_frame(&frame).map_err(|_| KeydError::Malformed("a frame too long"))
}

fn put_u16_bytes(out: &mut Vec<u8>, bytes: &[u8], max: usize) -> Result<(), KeydError> {
    if bytes.len() > max {
        return Err(KeydError::Malformed("a field is too long"));
    }
    let n = u16::try_from(bytes.len()).map_err(|_| KeydError::Malformed("a field is too long"))?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// A cursor over a request body that never reads past the end.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { rest: bytes }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], KeydError> {
        let (head, tail) = self
            .rest
            .split_at_checked(n)
            .ok_or(KeydError::Malformed("a request is too short"))?;
        self.rest = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], KeydError> {
        self.take(N)?
            .try_into()
            .map_err(|_| KeydError::Malformed("a request is too short"))
    }

    fn u8(&mut self) -> Result<u8, KeydError> {
        Ok(u8::from_be_bytes(self.array()?))
    }

    fn u16(&mut self) -> Result<u16, KeydError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, KeydError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    /// A signing key handle: a length octet and at most
    /// [`MAX_HANDLE_LEN`] bytes.
    fn handle(&mut self) -> Result<Vec<u8>, KeydError> {
        let n = usize::from(self.u8()?);
        if n > MAX_HANDLE_LEN {
            return Err(KeydError::Malformed("a signing key handle is too long"));
        }
        Ok(self.take(n)?.to_vec())
    }

    fn u16_bytes(&mut self, max: usize) -> Result<&'a [u8], KeydError> {
        let n = usize::from(self.u16()?);
        if n > max {
            return Err(KeydError::Malformed("a field is too long"));
        }
        self.take(n)
    }

    fn chain(&mut self) -> Result<Chain, KeydError> {
        Chain::from_code(self.u8()?).ok_or(KeydError::Malformed("an unknown chain code"))
    }

    fn root(&mut self) -> Result<RootHandle, KeydError> {
        let chain = self.chain()?;
        let epoch = Epoch(self.u64()?);
        Ok(RootHandle { chain, epoch })
    }

    fn end(&self) -> Result<(), KeydError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(KeydError::Malformed("trailing bytes after a request"))
        }
    }
}
