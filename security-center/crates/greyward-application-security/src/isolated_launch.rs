//! Fixed development-account ELF isolation, using the shared restriction core.
//! No grant or publisher identity is inferred from a candidate descriptor. The
//! graphical/nested compositor and AppImage/script providers remain separate.
use crate::{
    CandidateContent, ContentError, ExecutionHandle, InstalledExecutable, ManagedCode,
    ManagedCodeStore, ManagedContentError, PayloadKind, ReviewedLaunchError,
};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::Read;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use thiserror::Error;

const WORKER: &str = "/usr/libexec/greyward-native-worker";
const CONTEXT: &str = "greyward_guard_u:greyward_guard_r:greyward_guard_t:s0";
const ENTRY: &str = "/usr/libexec/greyward-guard-entry";
const READY: &[u8] = b"GREYWARD_ISOLATED_WORKER_READY_V1\n";

#[derive(Debug, Error)]
pub enum IsolatedLaunchError {
    #[error("Isolation preparation, actor or worker prerequisites changed")]
    Unavailable,
    #[error(transparent)]
    Content(#[from] ContentError),
    #[error(transparent)]
    Cache(#[from] ManagedContentError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Kernel(#[from] rustix::io::Errno),
}
fn actor_check(
    binding: &crate::enrollment::ProviderBinding,
    actor: &ExecutionHandle,
) -> Result<(), IsolatedLaunchError> {
    actor
        .revalidate()
        .map_err(|_| IsolatedLaunchError::Unavailable)?;
    if !binding.permits_isolation_actor(actor) || rustix::process::geteuid().as_raw() != 0 {
        return Err(IsolatedLaunchError::Unavailable);
    }
    let enforcing = fs::read_to_string("/sys/fs/selinux/enforce")?;
    if enforcing.trim() != "1" {
        return Err(IsolatedLaunchError::Unavailable);
    }
    Ok(())
}
pub(crate) fn available(
    binding: &crate::enrollment::ProviderBinding,
    actor: &ExecutionHandle,
) -> bool {
    actor_check(binding, actor).is_ok()
        && worker_check().is_ok()
        && crate::selinux_readback::ordinary_context_available()
}
fn nonce() -> Result<String, IsolatedLaunchError> {
    let mut value = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut value)?;
    Ok(crate::framed_digest(&[&value]))
}
struct PrivateTree(PathBuf);
impl Drop for PrivateTree {
    fn drop(&mut self) {
        // Only this root-created nonce beneath a root-private parent. Rust's
        // removal does not follow symlink entries created inside the scratch.
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn tree(binding: &crate::enrollment::ProviderBinding) -> Result<PrivateTree, IsolatedLaunchError> {
    for path in binding.path().ancestors() {
        let value = fs::symlink_metadata(path)?;
        if !value.is_dir() || value.uid() != 0 || value.gid() != 0 || value.mode() & 0o022 != 0 {
            return Err(IsolatedLaunchError::Unavailable);
        }
    }
    let base = binding.path().join(format!("isolation-{}", nonce()?));
    fs::DirBuilder::new().mode(0o700).create(&base)?;
    let owned = PrivateTree(base);
    for suffix in [
        "root",
        "root/usr",
        "root/proc",
        "root/dev",
        "root/etc",
        "root/etc/fonts",
        "root/work",
        "root/run",
    ] {
        let path = owned.0.join(suffix);
        fs::DirBuilder::new().mode(0o755).create(&path)?;
        // The installed broker uses umask 0077. Explicit modes are necessary
        // inside this root-private parent before the workload drops privileges.
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    }
    std::os::unix::fs::symlink("work/tmp", owned.0.join("root/tmp"))?;
    for name in ["guard-interpreter", "guard-document", "guard-host-wayland"] {
        let path = owned.0.join("root/run").join(name);
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o555))?;
    }
    fs::write(
        owned.0.join("root/etc/passwd"),
        format!(
            "greyward:x:{}:{}:GREYWARD isolated workload:/work:/usr/bin/nologin\n",
            binding.uid, binding.gid
        ),
    )?;
    fs::write(
        owned.0.join("root/etc/group"),
        format!("greyward:x:{}:\n", binding.gid),
    )?;
    for name in ["passwd", "group"] {
        fs::set_permissions(
            owned.0.join("root/etc").join(name),
            fs::Permissions::from_mode(0o444),
        )?;
    }
    for name in ["bin", "lib", "lib64"] {
        std::os::unix::fs::symlink(format!("usr/{name}"), owned.0.join("root").join(name))?;
    }
    // PID 1 mounts the disposable home inside the workload's own namespace.
    // A mount in the broker's sandbox is invisible to PID 1 and must not be
    // mistaken for the environment used by the application.
    Ok(owned)
}
fn worker_check() -> Result<(), IsolatedLaunchError> {
    for path in ["/", "/usr", "/usr/libexec"] {
        let value = fs::symlink_metadata(path)?;
        if !value.is_dir() || value.uid() != 0 || value.gid() != 0 || value.mode() & 0o022 != 0 {
            return Err(IsolatedLaunchError::Unavailable);
        }
    }
    let value = fs::symlink_metadata(WORKER)?;
    if !value.is_file()
        || value.uid() != 0
        || value.gid() != 0
        || value.nlink() != 1
        || value.mode() & 0o7022 != 0
        || value.mode() & 0o111 == 0
    {
        return Err(IsolatedLaunchError::Unavailable);
    }
    let value = fs::symlink_metadata(ENTRY)?;
    if !value.is_file()
        || value.uid() != 0
        || value.gid() != 0
        || value.nlink() != 1
        || value.len() != 0
        || value.permissions().mode() & 0o777 != 0o555
    {
        return Err(IsolatedLaunchError::Unavailable);
    }
    Ok(())
}
fn candidate(
    uid: u32,
    descriptor: OwnedFd,
    deadline: Instant,
    document: bool,
) -> Result<CandidateContent, IsolatedLaunchError> {
    let held = File::from(descriptor);
    let flags = rustix::fs::fcntl_getfl(&held)?;
    if !flags.contains(rustix::fs::OFlags::PATH)
        && (!document || flags.intersects(rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::RDWR))
    {
        return Err(IsolatedLaunchError::Unavailable);
    }
    let metadata = held.metadata()?;
    if !metadata.is_file()
        || !((metadata.uid() == uid && metadata.mode() & 0o400 != 0)
            || (metadata.uid() == 0 && metadata.mode() & 0o004 != 0))
    {
        return Err(IsolatedLaunchError::Unavailable);
    }
    let proxy = format!("/proc/self/fd/{}", held.as_raw_fd());
    let mut context = [0u8; 1024];
    let size = rustix::fs::getxattr(&proxy, "security.selinux", &mut context[..])?;
    let context =
        std::str::from_utf8(&context[..size]).map_err(|_| IsolatedLaunchError::Unavailable)?;
    // The root copier is not a Protected Data read/export deputy. Only ordinary
    // code labels are eligible, never registered credential/resource labels.
    if !matches!(context.split(':').nth(2), Some("bin_t" | "user_home_t")) {
        return Err(IsolatedLaunchError::Unavailable);
    }
    let read = rustix::fs::open(
        &proxy,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )?;
    let opened = File::from(read);
    let current = opened.metadata()?;
    if (
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.mode(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    ) != (
        current.dev(),
        current.ino(),
        current.uid(),
        current.mode(),
        current.ctime(),
        current.ctime_nsec(),
    ) {
        return Err(IsolatedLaunchError::Unavailable);
    }
    Ok(CandidateContent::capture_payload(
        opened.into(),
        deadline,
        document,
    )?)
}
pub struct PreparedIsolatedLaunch {
    managed: ManagedCode,
    interpreter: Option<ManagedCode>,
    document: Option<ManagedCode>,
    kind: PayloadKind,
    display: Option<File>,
    args: Vec<String>,
    deadline: Instant,
    binding: crate::enrollment::ProviderBinding,
}
impl PreparedIsolatedLaunch {
    /// # Errors
    /// Only held regular ELF content is supported; absent required providers
    /// refuse preparation. Candidate input is copied into immutable root storage.
    pub fn prepare(
        actor: &ExecutionHandle,
        descriptor: OwnedFd,
        args: Vec<String>,
        deadline: Instant,
    ) -> Result<Self, IsolatedLaunchError> {
        Self::prepare_bound(
            crate::enrollment::ProviderBinding::development(),
            actor,
            descriptor,
            args,
            deadline,
        )
    }
    pub(crate) fn prepare_bound(
        binding: crate::enrollment::ProviderBinding,
        actor: &ExecutionHandle,
        descriptor: OwnedFd,
        args: Vec<String>,
        deadline: Instant,
    ) -> Result<Self, IsolatedLaunchError> {
        actor_check(&binding, actor)?;
        worker_check()?;
        if args.len() > 32
            || args.iter().any(|a| a.contains('\0') || a.len() > 4096)
            || args.iter().map(String::len).sum::<usize>() > 8192
            || Instant::now() >= deadline
        {
            return Err(IsolatedLaunchError::Unavailable);
        }
        let candidate = candidate(binding.uid, descriptor, deadline, false)?;
        let kind = candidate.kind();
        let cache = ManagedCodeStore::open_bound(&binding)?;
        let mut managed = cache.import(&candidate, deadline)?;
        managed.prepare_entrypoint(deadline)?;
        let interpreter = if let PayloadKind::Script(interpreter) = kind {
            let path = fs::canonicalize(interpreter.path())?;
            let installed = InstalledExecutable::capture(
                path.to_str().ok_or(IsolatedLaunchError::Unavailable)?,
                deadline,
            )
            .map_err(|_| IsolatedLaunchError::Unavailable)?;
            let mut code = cache.import(installed.content(), deadline)?;
            code.prepare_entrypoint(deadline)?;
            installed
                .revalidate()
                .map_err(|_| IsolatedLaunchError::Unavailable)?;
            Some(code)
        } else {
            None
        };
        candidate.revalidate_object()?;
        actor_check(&binding, actor)?;
        Ok(Self {
            binding,
            managed,
            interpreter,
            document: None,
            kind,
            display: None,
            args,
            deadline,
        })
    }

    pub fn kind(&self) -> PayloadKind {
        self.kind
    }
    pub fn generation(&self) -> &greyward_security_domain::ContentGeneration {
        self.managed.generation()
    }
    /// # Errors
    /// Scripts bind both immutable script content and the fixed interpreter.
    pub fn identity_generation(
        &self,
    ) -> Result<greyward_security_domain::ContentGeneration, IsolatedLaunchError> {
        if let Some(interpreter) = &self.interpreter {
            return greyward_security_domain::ContentGeneration::try_from(crate::framed_digest(&[
                b"script/interpreter/v1",
                self.managed.generation().as_str().as_bytes(),
                interpreter.generation().as_str().as_bytes(),
            ]))
            .map_err(|_| IsolatedLaunchError::Unavailable);
        }
        Ok(self.managed.generation().clone())
    }
    /// # Errors
    /// Only a descriptor-pinned, installed Labwc peer in the enrolled session.
    pub fn with_graphical(mut self) -> Result<Self, IsolatedLaunchError> {
        for path in [
            "/usr/libexec/greyward-wayland-context",
            "/usr/bin/bwrap",
            "/usr/bin/labwc",
        ] {
            let code = InstalledExecutable::capture(path, self.deadline)
                .map_err(|_| IsolatedLaunchError::Unavailable)?;
            code.revalidate()
                .map_err(|_| IsolatedLaunchError::Unavailable)?;
        }
        self.display = Some(crate::private_display::host_display(
            self.binding.uid,
            self.deadline,
        )?);
        Ok(self)
    }
    /// # Errors
    /// A held ordinary document is classified at the root boundary. Registered
    /// labels cannot be exported by a generic chooser, including through aliases.
    pub fn prepare_document(
        actor: &ExecutionHandle,
        selected: OwnedFd,
        handler: &str,
        args: Vec<String>,
        deadline: Instant,
    ) -> Result<Self, IsolatedLaunchError> {
        Self::prepare_document_bound(
            &crate::enrollment::ProviderBinding::development(),
            actor,
            selected,
            handler,
            args,
            deadline,
        )
    }
    pub(crate) fn prepare_document_bound(
        binding: &crate::enrollment::ProviderBinding,
        actor: &ExecutionHandle,
        selected: OwnedFd,
        handler: &str,
        args: Vec<String>,
        deadline: Instant,
    ) -> Result<Self, IsolatedLaunchError> {
        actor_check(binding, actor)?;
        worker_check()?;
        let document = candidate(binding.uid, selected, deadline, true)?;
        let code = InstalledExecutable::capture(handler, deadline)
            .map_err(|_| IsolatedLaunchError::Unavailable)?;
        let descriptor = rustix::fs::open(
            code.selected_path(),
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        let mut prepared = Self::prepare_bound(binding.clone(), actor, descriptor, args, deadline)?;
        if prepared.managed.generation() != code.generation() || prepared.kind != PayloadKind::Elf {
            return Err(IsolatedLaunchError::Unavailable);
        }
        let cache = ManagedCodeStore::open_bound(binding)?;
        let mut copy = cache.import(&document, deadline)?;
        copy.prepare_document(deadline)?;
        document.revalidate_object()?;
        prepared.document = Some(copy);
        Ok(prepared)
    }
    fn worker_command(&self, unit: &str) -> Result<Command, IsolatedLaunchError> {
        let mut command = Command::new("/usr/bin/systemd-run");
        command
            .env_clear()
            .env("PATH", "/usr/bin:/usr/sbin")
            .args([
                "--quiet",
                "--wait",
                "--pipe",
                "--collect",
                "--no-ask-password",
                "--expand-environment=no",
                "--service-type=exec",
            ])
            .arg(format!("--unit={unit}"));
        for property in [
            "PrivateUsers=yes",
            "PrivatePIDs=yes",
            "PrivateNetwork=yes",
            "PrivateMounts=yes",
            "PrivateDevices=yes",
            "NoNewPrivileges=yes",
            "CapabilityBoundingSet=",
            "ProtectSystem=strict",
            "TasksMax=64",
            "MemoryMax=512M",
            "CPUQuota=100%",
            "TimeoutStartSec=8",
            "TimeoutStopSec=2",
            "KillMode=control-group",
            "WorkingDirectory=/work",
            "Environment=PATH=/usr/bin:/bin HOME=/work TMPDIR=/work LANG=C.UTF-8",
        ] {
            command.args(["-p", property]);
        }
        command.args([
            "-p",
            &format!("Environment=GREYWARD_PAYLOAD={}", self.kind.worker_value()),
        ]);
        if self.document.is_some() {
            command.args(["-p", "Environment=GREYWARD_SELECTED_DOCUMENT=1"]);
        }
        for namespace in ["mnt", "pid", "net", "user"] {
            let host = fs::read_link(format!("/proc/self/ns/{namespace}"))?;
            let host = host.to_str().ok_or(IsolatedLaunchError::Unavailable)?;
            command.args([
                "-p",
                &format!(
                    "Environment=GREYWARD_HOST_NS_{}={host}",
                    namespace.to_uppercase()
                ),
            ]);
        }
        Ok(command)
    }

    /// # Errors
    /// A private PID/user/network/mount environment and successful worker
    /// readiness are mandatory; a failed setup never executes unrestricted code.
    pub fn spawn(
        self,
        actor: &ExecutionHandle,
    ) -> Result<RunningIsolatedLaunch, IsolatedLaunchError> {
        actor_check(&self.binding, actor)?;
        worker_check()?;
        self.managed.revalidate()?;
        if let Some(code) = &self.interpreter {
            code.revalidate()?;
        }
        if let Some(document) = &self.document {
            document.revalidate()?;
        }
        let _preparation_lease = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|d| *d >= Duration::from_secs(1))
            .ok_or(IsolatedLaunchError::Unavailable)?;
        let tree = tree(&self.binding)?;
        let descriptor = self.managed.entry_descriptor()?;
        let code = format!("/proc/{}/fd/{}", std::process::id(), descriptor.as_raw_fd());
        let unit = format!("greyward-appsec-isolated-{}", nonce()?);
        let mut command = self.worker_command(&unit)?;
        let mut binds = format!("/usr {code}:{ENTRY}");
        if self.display.is_some() {
            binds.push_str(" /etc/fonts:/etc/fonts");
        }
        let mut descriptors = vec![descriptor];
        if let Some(socket) = &self.display {
            write!(
                binds,
                " /proc/{}/fd/{}:/run/guard-host-wayland",
                std::process::id(),
                socket.as_raw_fd()
            )
            .map_err(|_| IsolatedLaunchError::Unavailable)?;
        }
        for (content, target) in [
            (&self.interpreter, "/run/guard-interpreter"),
            (&self.document, "/run/guard-document"),
        ] {
            if let Some(content) = content {
                let fd = content.entry_descriptor()?;
                write!(
                    binds,
                    " /proc/{}/fd/{}:{target}",
                    std::process::id(),
                    fd.as_raw_fd()
                )
                .map_err(|_| IsolatedLaunchError::Unavailable)?;
                descriptors.push(fd);
            }
        }
        command
            .args(["-p", &format!("User={}", self.binding.uid)])
            .args(["-p", &format!("Group={}", self.binding.gid)])
            .args(["-p", "RuntimeMaxSec=3600"])
            .args(["-p", &format!("SELinuxContext={CONTEXT}")])
            .args([
                "-p",
                &format!("RootDirectory={}", tree.0.join("root").display()),
            ])
            .args(["-p", &format!("BindReadOnlyPaths={binds}")])
            .args([
                "-p",
                &format!("TemporaryFileSystem=/work:rw,nosuid,nodev,size=256M,mode=0700,uid={},gid={},context=greyward_guard_u:object_r:user_home_t:s0", self.binding.uid, self.binding.gid),
            ])
            .args([
                "--",
                WORKER,
                if self.display.is_some() {
                    "--prepared-graphical"
                } else {
                    "--prepared-isolation"
                },
            ])
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = command.spawn()?;
        let mut running = RunningIsolatedLaunch {
            child,
            unit,
            _tree: tree,
            _prepared: self,
            _descriptors: descriptors,
        };
        running.readiness(Instant::now() + Duration::from_secs(5))?;
        Ok(running)
    }
}
pub struct RunningIsolatedLaunch {
    child: Child,
    unit: String,
    _tree: PrivateTree,
    _prepared: PreparedIsolatedLaunch,
    _descriptors: Vec<OwnedFd>,
}
impl RunningIsolatedLaunch {
    fn readiness(&mut self, deadline: Instant) -> Result<(), IsolatedLaunchError> {
        let stream = self
            .child
            .stderr
            .as_mut()
            .ok_or(IsolatedLaunchError::Unavailable)?;
        for expected in READY {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(IsolatedLaunchError::Unavailable)?;
            let mut descriptors = [PollFd::new(&*stream, PollFlags::IN)];
            let wait =
                Timespec::try_from(remaining).map_err(|_| IsolatedLaunchError::Unavailable)?;
            if poll(&mut descriptors, Some(&wait))? == 0 {
                return Err(IsolatedLaunchError::Unavailable);
            }
            let mut observed = [0];
            stream.read_exact(&mut observed)?;
            if observed[0] != *expected {
                return Err(IsolatedLaunchError::Unavailable);
            }
        }
        Ok(())
    }
    /// # Errors
    /// Transfer only the established worker's standard streams, without buffering
    /// or recording application output in policy/history.
    pub fn streams(&mut self) -> Result<(File, File, File), ReviewedLaunchError> {
        let input = self
            .child
            .stdin
            .take()
            .ok_or(ReviewedLaunchError::Invalid)?;
        let output = self
            .child
            .stdout
            .take()
            .ok_or(ReviewedLaunchError::Invalid)?;
        let error = self
            .child
            .stderr
            .take()
            .ok_or(ReviewedLaunchError::Invalid)?;
        Ok((
            rustix::io::dup(&input)?.into(),
            rustix::io::dup(&output)?.into(),
            rustix::io::dup(&error)?.into(),
        ))
    }
    /// # Errors
    /// An application exit code is separate from whole-session protection.
    pub fn wait(&mut self) -> Result<std::process::ExitStatus, ReviewedLaunchError> {
        Ok(self.child.wait()?)
    }
}
impl Drop for RunningIsolatedLaunch {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = Command::new("/usr/bin/timeout")
                .env_clear()
                .env("PATH", "/usr/bin:/usr/sbin")
                .args([
                    "--kill-after=1",
                    "3",
                    "/usr/bin/systemctl",
                    "stop",
                    &self.unit,
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
