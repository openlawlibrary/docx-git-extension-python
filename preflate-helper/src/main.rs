//! docx-preflate - the fallback compression of the docx git extension.
//!
//! When no known compression profile reproduces a document, the clean filter
//! hands every deflated part to `split`, which records what preflate-rs needs
//! to rebuild that exact deflate stream from the plain part (the
//! "corrections", typically 40-80 bytes). The smudge filter hands plain parts
//! plus corrections to `recreate` and gets the original streams back.
//!
//! USAGE
//!     docx-preflate version      prints `preflate-rs/<version>`
//!     docx-preflate split        stdin: frames of raw deflate streams
//!     docx-preflate recreate     stdin: frame pairs (plain part, corrections)
//!
//! FRAMING (all integers u32 little endian)
//!     request frame   len, bytes
//!     reply frame     status u8 (0 ok, 1 error), len, bytes
//!                     ok:    split -> corrections, recreate -> deflate stream
//!                     error: a UTF-8 message
//! One reply per request (per pair for recreate), in request order. The parts
//! of one document are processed in parallel; replies keep request order.
//!
//! `split` verifies: preflate-rs recreates each stream from its own output and
//! compares, so corrections that would not rebuild the original are reported
//! as an error instead of being recorded.

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Verify every split by recreating the stream, and never cut a part short:
/// a part is one document entry, already held in memory by the filter.
const CONFIG: preflate_rs::PreflateConfig = preflate_rs::PreflateConfig {
    max_chain_length: 4096,
    plain_text_limit: usize::MAX,
    verify_compression: true,
};

/// Must equal the preflate-rs pin in Cargo.toml. Pointers record it, and smudge
/// refuses corrections made by a different version.
const PREFLATE_VERSION: &str = "0.7.6";

fn read_frames(input: &[u8]) -> io::Result<Vec<&[u8]>> {
    let mut frames = Vec::new();
    let mut p = 0usize;
    while p < input.len() {
        if p + 4 > input.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated frame header"));
        }
        let n = u32::from_le_bytes(input[p..p + 4].try_into().unwrap()) as usize;
        p += 4;
        if p + n > input.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated frame"));
        }
        frames.push(&input[p..p + n]);
        p += n;
    }
    Ok(frames)
}

fn split(comp: &[u8]) -> Result<Vec<u8>, String> {
    let (res, _plain) = preflate_rs::preflate_whole_deflate_stream(comp, &CONFIG)
        .map_err(|e| format!("preflate could not model this stream: {e:?}"))?;
    if res.compressed_size != comp.len() {
        return Err(format!(
            "preflate modelled {} of {} bytes (trailing data after the deflate stream)",
            res.compressed_size,
            comp.len()
        ));
    }
    Ok(res.corrections)
}

fn recreate(plain: &[u8], corrections: &[u8]) -> Result<Vec<u8>, String> {
    preflate_rs::recreate_whole_deflate_stream(plain, corrections)
        .map_err(|e| format!("preflate could not recreate the stream: {e:?}"))
}

/// Run `job` over `n` items on all cores; results come back in item order.
fn parallel<F>(n: usize, job: F) -> Vec<Result<Vec<u8>, String>>
where
    F: Fn(usize) -> Result<Vec<u8>, String> + Sync,
{
    let mut out: Vec<Option<Result<Vec<u8>, String>>> = (0..n).map(|_| None).collect();
    let next = AtomicUsize::new(0);
    let threads = std::thread::available_parallelism().map(|t| t.get()).unwrap_or(1).min(n.max(1));
    let results = std::sync::Mutex::new(&mut out);
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= n {
                    break;
                }
                let r = job(i);
                results.lock().unwrap()[i] = Some(r);
            });
        }
    });
    out.into_iter().map(|r| r.unwrap()).collect()
}

fn write_replies(replies: Vec<Result<Vec<u8>, String>>) -> io::Result<()> {
    let stdout = io::stdout();
    let mut w = io::BufWriter::new(stdout.lock());
    for r in replies {
        let (status, body) = match r {
            Ok(b) => (0u8, b),
            Err(m) => (1u8, m.into_bytes()),
        };
        w.write_all(&[status])?;
        w.write_all(&(body.len() as u32).to_le_bytes())?;
        w.write_all(&body)?;
    }
    w.flush()
}

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    if cmd == "version" {
        println!("preflate-rs/{PREFLATE_VERSION}");
        return;
    }
    if cmd != "split" && cmd != "recreate" {
        eprintln!("usage: docx-preflate version | split | recreate   (frames on stdin, see source)");
        std::process::exit(2);
    }
    let mut input = Vec::new();
    if let Err(e) = io::stdin().read_to_end(&mut input) {
        eprintln!("docx-preflate: cannot read stdin: {e}");
        std::process::exit(1);
    }
    let frames = match read_frames(&input) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("docx-preflate: {e}");
            std::process::exit(1);
        }
    };
    let replies = if cmd == "split" {
        parallel(frames.len(), |i| split(frames[i]))
    } else {
        if frames.len() % 2 != 0 {
            eprintln!("docx-preflate: recreate needs (plain, corrections) frame pairs");
            std::process::exit(1);
        }
        parallel(frames.len() / 2, |i| recreate(frames[2 * i], frames[2 * i + 1]))
    };
    if let Err(e) = write_replies(replies) {
        eprintln!("docx-preflate: cannot write stdout: {e}");
        std::process::exit(1);
    }
}
