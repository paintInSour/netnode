//! The control socket: lets `netnode ctl` send commands to a running netnode.
//!
//! This is how you drive netnode when it has no terminal, for example in a
//! container: `docker exec -it <container> /netnode ctl`.
//!
//! Protocol (a Unix stream socket, one session per connection):
//! the client sends one command per line; netnode answers with the command's
//! output followed by a single NUL byte. `quit` ends the session.
//! The socket file is readable and writable by its owner only.

#![forbid(unsafe_code)]

use std::fs;
use std::io::{self, BufRead, BufReader, IsTerminal, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;

use crate::cli::{Context, Flow};

/// Ends every response.
const END_OF_RESPONSE: u8 = 0;

/// Default socket path for an interface: one netnode per interface per machine.
pub fn default_socket_path(iface: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/netnode-{iface}.sock"))
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// A listening control socket. Dropping it removes the socket file.
pub struct ControlServer {
    path: PathBuf,
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Starts listening on `path` and serves each connection on its own thread.
pub fn start(path: &Path, ctx: Arc<Context>) -> Result<ControlServer> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    if path.exists() {
        if UnixStream::connect(path).is_ok() {
            bail!(
                "another netnode is already listening on {} (use --control to pick another path)",
                path.display()
            );
        }
        fs::remove_file(path).with_context(|| format!("cannot remove stale socket {}", path.display()))?;
    }
    let listener =
        UnixListener::bind(path).with_context(|| format!("cannot listen on {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;

    thread::Builder::new().name("control".into()).spawn(move || {
        for stream in listener.incoming().flatten() {
            let ctx = ctx.clone();
            let _ = thread::Builder::new().name("control-session".into()).spawn(move || {
                let _ = serve(stream, |line| ctx.run_line(line));
            });
        }
    })?;
    Ok(ControlServer { path: path.to_owned() })
}

/// Runs one session: a command per line in, output plus NUL out.
fn serve(stream: UnixStream, mut run: impl FnMut(&str) -> (String, Flow)) -> io::Result<()> {
    let mut writer = stream.try_clone()?;
    for line in BufReader::new(stream).lines() {
        let (out, flow) = run(&line?);
        writer.write_all(out.as_bytes())?;
        writer.write_all(&[END_OF_RESPONSE])?;
        if flow != Flow::Continue {
            break;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Client (`netnode ctl`)
// ---------------------------------------------------------------------------

/// Runs `netnode ctl`: one command if `words` is non-empty, otherwise a prompt.
pub fn client(path: &Path, wait: Duration, words: &[String]) -> Result<ExitCode> {
    let stream = connect(path, wait)?;
    let mut session = Session { reader: BufReader::new(stream.try_clone()?), writer: stream };

    if !words.is_empty() {
        let line = shlex::try_join(words.iter().map(String::as_str))
            .map_err(|_| anyhow::anyhow!("command contains a NUL byte"))?;
        let out = session.send(&line)?;
        print!("{out}");
        let failed = out.starts_with("error");
        return Ok(if failed { ExitCode::FAILURE } else { ExitCode::SUCCESS });
    }

    if !io::stdin().is_terminal() {
        // Commands piped in: run each line, stop at end of input.
        for line in io::stdin().lock().lines() {
            let line = line?;
            print!("{}", session.send(&line)?);
            if ends_session(&line) {
                break;
            }
        }
        return Ok(ExitCode::SUCCESS);
    }

    let mut editor = DefaultEditor::new()?;
    println!("connected to {}. `quit` leaves, `shutdown` stops netnode.", path.display());
    loop {
        let line = match editor.readline("netnode ctl> ") {
            Ok(line) => line,
            Err(ReadlineError::Interrupted) => continue,
            Err(_) => break, // Ctrl-D
        };
        let _ = editor.add_history_entry(line.trim());
        print!("{}", session.send(&line)?);
        if ends_session(&line) {
            break;
        }
    }
    Ok(ExitCode::SUCCESS)
}

struct Session {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl Session {
    fn send(&mut self, line: &str) -> Result<String> {
        let line = line.replace('\n', " ");
        self.writer.write_all(line.as_bytes())?;
        self.writer.write_all(b"\n")?;
        let mut response = Vec::new();
        let n = self.reader.read_until(END_OF_RESPONSE, &mut response)?;
        if n == 0 {
            bail!("netnode closed the connection");
        }
        response.pop(); // the end marker
        Ok(String::from_utf8_lossy(&response).into_owned())
    }
}

fn ends_session(line: &str) -> bool {
    matches!(line.split_whitespace().next(), Some("quit" | "exit" | "shutdown"))
}

/// Connects, retrying until `wait` runs out (netnode may still be starting).
fn connect(path: &Path, wait: Duration) -> Result<UnixStream> {
    let deadline = Instant::now() + wait;
    let mut told_user = false;
    loop {
        match UnixStream::connect(path) {
            Ok(stream) => return Ok(stream),
            Err(_) if Instant::now() < deadline => {
                if !told_user {
                    eprintln!("waiting for netnode at {} ...", path.display());
                    told_user = true;
                }
                thread::sleep(Duration::from_millis(200));
            }
            Err(err) => {
                let hint = match err.kind() {
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
                        "is netnode running? Use the same --iface (or --control) as netnode"
                    }
                    io::ErrorKind::PermissionDenied => "run as the same user as netnode (often root)",
                    _ => "check the socket path",
                };
                return Err(
                    anyhow::Error::new(err).context(format!("cannot connect to {} ({hint})", path.display()))
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_round_trip() {
        let (server_end, client_end) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || {
            serve(server_end, |line| match line {
                "quit" => ("bye\n".into(), Flow::EndSession),
                other => (format!("echo {other}\n"), Flow::Continue),
            })
        });
        let mut session =
            Session { reader: BufReader::new(client_end.try_clone().unwrap()), writer: client_end };
        assert_eq!(session.send("host list").unwrap(), "echo host list\n");
        assert_eq!(session.send("stats").unwrap(), "echo stats\n");
        assert_eq!(session.send("quit").unwrap(), "bye\n");
        assert!(session.send("stats").is_err(), "server ended the session");
        server.join().unwrap().unwrap();
    }

    #[test]
    fn session_ending_words() {
        assert!(ends_session("quit"));
        assert!(ends_session("  shutdown "));
        assert!(!ends_session("host list"));
    }

    #[test]
    fn default_path_is_per_interface() {
        assert_eq!(default_socket_path("eth1"), PathBuf::from("/tmp/netnode-eth1.sock"));
    }
}
