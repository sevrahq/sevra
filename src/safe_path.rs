//! Capability-style filesystem access for paths supplied by a store or hub.
//!
//! On Unix, every traversal starts from a held directory descriptor and every
//! component is opened with `O_NOFOLLOW`. Reads use the final held descriptor;
//! writes create and rename a same-directory temporary file through the held
//! parent descriptor. A path swapped to a symlink after validation therefore
//! cannot redirect the operation.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
    #[cfg_attr(windows, allow(dead_code))]
    Other,
}

#[derive(Debug)]
pub struct SafeEntry {
    pub name: OsString,
    pub kind: EntryKind,
}

fn absolute(path: &Path) -> io::Result<std::path::PathBuf> {
    // Unlike canonicalize, `absolute` never follows a symlink in the path we
    // are about to treat as the capability root. The platform traversal below
    // must inspect every original component itself.
    let resolved = std::path::absolute(path)?;
    #[cfg(target_os = "macos")]
    {
        // macOS exposes three fixed root aliases as symlinks (`/var`, `/tmp`,
        // `/etc` → `/private/...`). Refusing them makes ordinary temp paths
        // unusable, including `sevra export /tmp/brain`. Rewrite only these
        // operating-system aliases to their canonical fixed roots; arbitrary
        // user-controlled symlinks remain subject to O_NOFOLLOW below.
        let mut components = resolved.components();
        if matches!(components.next(), Some(Component::RootDir)) {
            if let Some(Component::Normal(first)) = components.next() {
                if first == "var" || first == "tmp" || first == "etc" {
                    let mut expanded = std::path::PathBuf::from("/private");
                    expanded.push(first);
                    for component in components {
                        expanded.push(component.as_os_str());
                    }
                    return Ok(expanded);
                }
            }
        }
    }
    Ok(resolved)
}

fn parts(rel: &str) -> io::Result<Vec<OsString>> {
    if rel.is_empty() || rel.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "relative path is empty or contains NUL",
        ));
    }
    let mut out = Vec::new();
    for component in Path::new(rel).components() {
        match component {
            Component::Normal(name) => out.push(name.to_os_string()),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "path is not normalized and relative",
                ))
            }
        }
    }
    if out.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "relative path has no file name",
        ));
    }
    Ok(out)
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::ffi::{CString, OsStr};
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::ffi::OsStrExt;

    pub(super) struct SafeDir {
        file: fs::File,
    }

    struct DirStream(*mut libc::DIR);

    impl Drop for DirStream {
        fn drop(&mut self) {
            // SAFETY: `fdopendir` returned this live stream and ownership was
            // transferred to the guard exactly once.
            unsafe { libc::closedir(self.0) };
        }
    }

    fn c_name(name: &OsStr) -> io::Result<CString> {
        CString::new(name.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path component contains NUL"))
    }

    fn open_root(root: &Path) -> io::Result<fs::File> {
        let resolved = absolute(root)?;
        let slash = c_name(OsStr::new("/"))?;
        // SAFETY: `slash` is a live NUL-terminated string. The returned owned
        // descriptor is checked before conversion to `File`.
        let root_fd = unsafe {
            libc::open(
                slash.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if root_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `open` returned a fresh owned descriptor.
        let mut dir = unsafe { fs::File::from_raw_fd(root_fd) };
        // Do not reopen the absolute path in one syscall: that would still
        // follow a raced symlink in any ancestor. Descend from `/` one held,
        // no-follow directory descriptor at a time.
        for component in resolved.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => dir = open_dir_at(dir.as_raw_fd(), name)?,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "resolved root is not an absolute normalized Unix path",
                    ))
                }
            }
        }
        Ok(dir)
    }

    pub(super) fn ensure_dir(path: &Path, mode: u32) -> io::Result<()> {
        let resolved = absolute(path)?;
        let slash = c_name(OsStr::new("/"))?;
        // SAFETY: `slash` is a live NUL-terminated string. The returned owned
        // descriptor is checked before conversion to `File`.
        let root_fd = unsafe {
            libc::open(
                slash.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if root_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `open` returned a fresh owned descriptor.
        let mut dir = unsafe { fs::File::from_raw_fd(root_fd) };
        for component in resolved.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => match open_dir_at(dir.as_raw_fd(), name) {
                    Ok(next) => dir = next,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        let name_c = c_name(name)?;
                        // SAFETY: `dir` remains held and `name` is one live,
                        // NUL-terminated component.
                        let made = unsafe {
                            libc::mkdirat(dir.as_raw_fd(), name_c.as_ptr(), mode as libc::mode_t)
                        };
                        if made != 0 {
                            let mkdir_error = io::Error::last_os_error();
                            if mkdir_error.kind() != io::ErrorKind::AlreadyExists {
                                return Err(mkdir_error);
                            }
                        }
                        dir = open_dir_at(dir.as_raw_fd(), name)?;
                    }
                    Err(error) => return Err(error),
                },
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "directory path is not an absolute normalized Unix path",
                    ))
                }
            }
        }
        dir.sync_all()
    }

    pub(super) fn create_symlink(root: &Path, rel: &str, target: &str) -> io::Result<()> {
        let components = parts(rel)?;
        let parent = open_parent(root, &components, true)?;
        let name = c_name(
            components
                .last()
                .expect("parts rejects an empty relative path"),
        )?;
        let target = CString::new(target.as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "symlink target contains NUL")
        })?;
        // SAFETY: `parent` is a held no-follow directory capability and both
        // strings are live NUL-terminated byte sequences. `symlinkat` never
        // replaces an existing destination.
        if unsafe { libc::symlinkat(target.as_ptr(), parent.as_raw_fd(), name.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        parent.sync_all()
    }

    fn open_dir_at(parent: RawFd, name: &OsStr) -> io::Result<fs::File> {
        let name = c_name(name)?;
        // SAFETY: the parent descriptor is held by the caller and `name` is a
        // live NUL-terminated component. `O_NOFOLLOW|O_DIRECTORY` refuses
        // symlinks and non-directories in the kernel.
        let fd = unsafe {
            libc::openat(
                parent,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `openat` returned a fresh owned descriptor.
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }

    fn open_parent_from(
        mut dir: fs::File,
        components: &[OsString],
        create: bool,
    ) -> io::Result<fs::File> {
        for component in &components[..components.len().saturating_sub(1)] {
            match open_dir_at(dir.as_raw_fd(), component) {
                Ok(next) => dir = next,
                Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                    let name = c_name(component)?;
                    // SAFETY: `dir` remains held and `name` is a live
                    // NUL-terminated single component.
                    let made = unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o755) };
                    if made != 0 {
                        let mkdir_error = io::Error::last_os_error();
                        if mkdir_error.kind() != io::ErrorKind::AlreadyExists {
                            return Err(mkdir_error);
                        }
                    }
                    // Whether we created it or raced another creator, only a
                    // real directory (never a symlink) can pass this open.
                    dir = open_dir_at(dir.as_raw_fd(), component)?;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(dir)
    }

    fn open_parent(root: &Path, components: &[OsString], create: bool) -> io::Result<fs::File> {
        open_parent_from(open_root(root)?, components, create)
    }

    fn open_leaf(parent: RawFd, name: &OsStr) -> io::Result<fs::File> {
        let name = c_name(name)?;
        // SAFETY: the parent descriptor is held and `name` is a live
        // NUL-terminated component. `O_NOFOLLOW` binds the returned descriptor
        // to a regular leaf rather than a substituted symlink target.
        let fd = unsafe {
            libc::openat(
                parent,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `openat` returned a fresh owned descriptor.
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }

    impl SafeDir {
        pub(super) fn open(root: &Path) -> io::Result<Self> {
            Ok(Self {
                file: open_root(root)?,
            })
        }

        pub(super) fn entries(&self) -> io::Result<Vec<SafeEntry>> {
            // `fdopendir` owns and closes its descriptor, so duplicate the
            // held capability rather than transferring the original.
            // SAFETY: the source descriptor is live for this call.
            let dup = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
            if dup < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `dup` is a fresh directory descriptor.
            let stream = unsafe { libc::fdopendir(dup) };
            if stream.is_null() {
                let error = io::Error::last_os_error();
                // SAFETY: fdopendir failed and did not take ownership.
                unsafe { libc::close(dup) };
                return Err(error);
            }
            let stream = DirStream(stream);
            let mut entries = Vec::new();
            loop {
                // SAFETY: the guarded DIR stream is live. Calls are serialized
                // inside this method.
                let raw = unsafe { libc::readdir(stream.0) };
                if raw.is_null() {
                    break;
                }
                // SAFETY: a successful readdir points to a dirent whose d_name
                // is NUL-terminated for the lifetime of the next readdir call.
                let name = unsafe { std::ffi::CStr::from_ptr((*raw).d_name.as_ptr()) };
                let bytes = name.to_bytes();
                if bytes == b"." || bytes == b".." {
                    continue;
                }
                let name_os = OsStr::from_bytes(bytes);
                let mode = leaf_kind(self.file.as_raw_fd(), name_os)?.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "directory entry disappeared while inspecting it",
                    )
                })?;
                let kind = match mode & libc::S_IFMT {
                    libc::S_IFREG => EntryKind::File,
                    libc::S_IFDIR => EntryKind::Directory,
                    libc::S_IFLNK => EntryKind::Symlink,
                    _ => EntryKind::Other,
                };
                entries.push(SafeEntry {
                    name: name_os.to_os_string(),
                    kind,
                });
            }
            Ok(entries)
        }

        pub(super) fn open_dir(&self, name: &OsStr) -> io::Result<Self> {
            #[cfg(test)]
            test_pause_before_open(name);
            Ok(Self {
                file: open_dir_at(self.file.as_raw_fd(), name)?,
            })
        }

        pub(super) fn open_file(&self, name: &OsStr) -> io::Result<fs::File> {
            #[cfg(test)]
            test_pause_before_open(name);
            let file = open_leaf(self.file.as_raw_fd(), name)?;
            if !file.metadata()?.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "entry is not a regular file",
                ));
            }
            Ok(file)
        }

        pub(super) fn read_symlink(&self, name: &OsStr) -> io::Result<OsString> {
            let name = c_name(name)?;
            let mut capacity = 256_usize;
            loop {
                let mut bytes = vec![0_u8; capacity];
                // SAFETY: the directory descriptor and NUL-terminated name are
                // held for this call, and `bytes` exposes `capacity` writable
                // bytes. readlinkat reads the link itself and never follows it.
                let read = unsafe {
                    libc::readlinkat(
                        self.file.as_raw_fd(),
                        name.as_ptr(),
                        bytes.as_mut_ptr().cast(),
                        bytes.len(),
                    )
                };
                if read < 0 {
                    return Err(io::Error::last_os_error());
                }
                let read = read as usize;
                if read < bytes.len() {
                    bytes.truncate(read);
                    return Ok(OsStr::from_bytes(&bytes).to_os_string());
                }
                if capacity >= 64 * 1024 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "symlink target exceeds 64 KiB",
                    ));
                }
                capacity *= 2;
            }
        }

        pub(super) fn create_dir(&self, name: &str, mode: u32) -> io::Result<Self> {
            let components = parts(name)?;
            if components.len() != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "new directory name must be one component",
                ));
            }
            let name = &components[0];
            let name_c = c_name(name)?;
            if unsafe {
                libc::mkdirat(self.file.as_raw_fd(), name_c.as_ptr(), mode as libc::mode_t)
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            self.file.sync_all()?;
            Ok(Self {
                file: open_dir_at(self.file.as_raw_fd(), name)?,
            })
        }

        pub(super) fn publish_dir_no_replace(&self, source: &str, target: &str) -> io::Result<()> {
            let source = parts(source)?;
            let target = parts(target)?;
            if source.len() != 1 || target.len() != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "published directory names must be one component",
                ));
            }
            let source_name = &source[0];
            let target_name = &target[0];
            if leaf_kind(self.file.as_raw_fd(), source_name)?
                .is_none_or(|mode| mode & libc::S_IFMT != libc::S_IFDIR)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "staged export is not a directory",
                ));
            }
            if leaf_kind(self.file.as_raw_fd(), target_name)?.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "export destination appeared before publish",
                ));
            }
            let source_c = c_name(source_name)?;
            let target_c = c_name(target_name)?;
            #[cfg(target_os = "linux")]
            let published = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    self.file.as_raw_fd(),
                    source_c.as_ptr(),
                    self.file.as_raw_fd(),
                    target_c.as_ptr(),
                    libc::RENAME_NOREPLACE,
                ) as libc::c_int
            };
            #[cfg(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "tvos",
                target_os = "watchos",
                target_os = "visionos"
            ))]
            let published = unsafe {
                libc::renameatx_np(
                    self.file.as_raw_fd(),
                    source_c.as_ptr(),
                    self.file.as_raw_fd(),
                    target_c.as_ptr(),
                    libc::RENAME_EXCL,
                )
            };
            #[cfg(not(any(
                target_os = "linux",
                target_os = "macos",
                target_os = "ios",
                target_os = "tvos",
                target_os = "watchos",
                target_os = "visionos"
            )))]
            let published = {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "atomic no-replace directory publish is unsupported",
                ));
            };
            if published != 0 {
                return Err(io::Error::last_os_error());
            }
            self.file.sync_all()
        }

        pub(super) fn open_relative(&self, rel: &str) -> io::Result<Option<fs::File>> {
            let components = parts(rel)?;
            let parent = match open_parent_from(self.file.try_clone()?, &components, false) {
                Ok(parent) => parent,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error),
            };
            let file = match open_leaf(parent.as_raw_fd(), components.last().unwrap()) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error),
            };
            if !file.metadata()?.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "leaf is not a regular file",
                ));
            }
            Ok(Some(file))
        }

        pub(super) fn directory_exists_relative(&self, rel: &str) -> io::Result<bool> {
            let components = parts(rel)?;
            let parent = match open_parent_from(self.file.try_clone()?, &components, false) {
                Ok(parent) => parent,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
                Err(error) => return Err(error),
            };
            match open_dir_at(parent.as_raw_fd(), components.last().unwrap()) {
                Ok(_) => Ok(true),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(error),
            }
        }

        pub(super) fn lock_relative(&self, rel: &str) -> io::Result<fs::File> {
            let components = parts(rel)?;
            if components.len() != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "lock name must be one component",
                ));
            }
            let name = c_name(&components[0])?;
            // SAFETY: the held root descriptor and NUL-terminated name live
            // through the call. O_NOFOLLOW refuses a planted symlink.
            let fd = unsafe {
                libc::openat(
                    self.file.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: openat returned a fresh owned descriptor.
            let file = unsafe { fs::File::from_raw_fd(fd) };
            if !file.metadata()?.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "lock entry is not a regular file",
                ));
            }
            // The file is intentionally permanent. Removing a held lock file
            // would let another process create and lock a different inode.
            self.file.sync_all()?;
            // SAFETY: file owns a live descriptor. flock blocks until the
            // other pull/push exits and the kernel releases its lock on death.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(file)
        }

        pub(super) fn restore_permissions_relative(
            &self,
            rel: &str,
            mode: u32,
            _readonly: bool,
        ) -> io::Result<()> {
            use std::os::unix::fs::PermissionsExt;
            let file = self.open_relative(rel)?.ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "restored file disappeared")
            })?;
            file.set_permissions(fs::Permissions::from_mode(mode))?;
            file.sync_all()
        }

        pub(super) fn atomic_write_relative<F>(
            &self,
            rel: &str,
            create_parents: bool,
            mode: u32,
            write: F,
        ) -> io::Result<()>
        where
            F: FnOnce(&mut fs::File) -> io::Result<()>,
        {
            let components = parts(rel)?;
            let parent = open_parent_from(self.file.try_clone()?, &components, create_parents)?;
            atomic_write_in_parent(parent, components.last().unwrap(), rel, mode, true, write)
        }

        pub(super) fn atomic_create_relative<F>(
            &self,
            rel: &str,
            create_parents: bool,
            mode: u32,
            write: F,
        ) -> io::Result<()>
        where
            F: FnOnce(&mut fs::File) -> io::Result<()>,
        {
            let components = parts(rel)?;
            let parent = open_parent_from(self.file.try_clone()?, &components, create_parents)?;
            atomic_write_in_parent(parent, components.last().unwrap(), rel, mode, false, write)
        }

        pub(super) fn remove_regular_relative(&self, rel: &str) -> io::Result<bool> {
            let components = parts(rel)?;
            let parent = match open_parent_from(self.file.try_clone()?, &components, false) {
                Ok(parent) => parent,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
                Err(error) => return Err(error),
            };
            remove_regular_in_parent(parent, components.last().unwrap())
        }

        pub(super) fn remove_empty_dir(&self, rel: &str) -> io::Result<bool> {
            let components = parts(rel)?;
            let parent = match open_parent_from(self.file.try_clone()?, &components, false) {
                Ok(parent) => parent,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
                Err(error) => return Err(error),
            };
            let leaf = components.last().unwrap();
            let Some(mode) = leaf_kind(parent.as_raw_fd(), leaf)? else {
                return Ok(false);
            };
            if mode & libc::S_IFMT != libc::S_IFDIR {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "refusing to remove a non-directory rollback path",
                ));
            }
            let leaf_c = c_name(leaf)?;
            if unsafe { libc::unlinkat(parent.as_raw_fd(), leaf_c.as_ptr(), libc::AT_REMOVEDIR) }
                != 0
            {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::NotFound {
                    return Ok(false);
                }
                return Err(error);
            }
            parent.sync_all()?;
            Ok(true)
        }
    }

    #[cfg(test)]
    fn test_pause_before_open(name: &OsStr) {
        if let Some((test_name, barrier)) = TEST_BEFORE_OPEN.get() {
            if name == test_name {
                barrier.wait();
                barrier.wait();
            }
        }
    }

    fn leaf_kind(parent: RawFd, name: &OsStr) -> io::Result<Option<libc::mode_t>> {
        let name = c_name(name)?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `stat` points to writable storage, the parent descriptor is
        // held, and `name` is a live NUL-terminated component.
        let rc = unsafe {
            libc::fstatat(
                parent,
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc == 0 {
            // SAFETY: successful `fstatat` initialized the structure.
            return Ok(Some(unsafe { stat.assume_init() }.st_mode));
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(error)
        }
    }

    pub(super) fn open_regular(root: &Path, rel: &str) -> io::Result<Option<fs::File>> {
        let components = parts(rel)?;
        let parent = match open_parent(root, &components, false) {
            Ok(parent) => parent,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let file = match open_leaf(parent.as_raw_fd(), components.last().unwrap()) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "leaf is not a regular file",
            ));
        }
        Ok(Some(file))
    }

    pub(super) fn read_regular(root: &Path, rel: &str) -> io::Result<Option<Vec<u8>>> {
        let Some(mut file) = open_regular(root, rel)? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(Some(bytes))
    }

    fn atomic_write_in_parent<F>(
        parent: fs::File,
        leaf: &OsStr,
        rel: &str,
        mode: u32,
        replace_existing: bool,
        write: F,
    ) -> io::Result<()>
    where
        F: FnOnce(&mut fs::File) -> io::Result<()>,
    {
        #[cfg(not(test))]
        let _ = rel;
        if let Some(existing_mode) = leaf_kind(parent.as_raw_fd(), leaf)? {
            if !replace_existing {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "destination appeared after transaction preflight",
                ));
            }
            let kind = existing_mode & libc::S_IFMT;
            if kind == libc::S_IFLNK {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "destination leaf is a symlink",
                ));
            }
            if kind != libc::S_IFREG {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "destination leaf is not a regular file",
                ));
            }
        }

        let mut random = [0_u8; 16];
        getrandom::getrandom(&mut random)
            .map_err(|_| io::Error::other("operating-system randomness unavailable"))?;
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let temp_name = OsString::from(format!(".sevra-new-{suffix}"));
        let temp_c = c_name(&temp_name)?;
        // SAFETY: the parent descriptor is held and `temp_c` is a live
        // NUL-terminated single component. `O_EXCL|O_NOFOLLOW` makes a
        // pre-planted path a refusal, never a target.
        let temp_fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                temp_c.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                mode as libc::c_uint,
            )
        };
        if temp_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `openat` returned a fresh owned descriptor.
        let mut staged = unsafe { fs::File::from_raw_fd(temp_fd) };
        let write_result = write(&mut staged).and_then(|()| staged.sync_all());
        if let Err(error) = write_result {
            drop(staged);
            // SAFETY: the parent descriptor and temporary name remain valid.
            let _ = unsafe { libc::unlinkat(parent.as_raw_fd(), temp_c.as_ptr(), 0) };
            return Err(error);
        }

        #[cfg(test)]
        if let Some((test_rel, barrier)) = TEST_BEFORE_RENAME.get() {
            if rel == test_rel {
                barrier.wait();
                barrier.wait();
            }
        }

        let leaf_c = c_name(leaf)?;
        let installed = if replace_existing {
            // SAFETY: both names are live NUL-terminated components and both
            // directory descriptors refer to the same held parent. `renameat`
            // replaces a raced leaf entry itself; it never follows that entry.
            unsafe {
                libc::renameat(
                    parent.as_raw_fd(),
                    temp_c.as_ptr(),
                    parent.as_raw_fd(),
                    leaf_c.as_ptr(),
                )
            }
        } else {
            // A hard-link install is the portable Unix no-replace primitive:
            // linkat atomically fails with EEXIST if any exact destination
            // entry appeared after the held transaction snapshot.
            unsafe {
                libc::linkat(
                    parent.as_raw_fd(),
                    temp_c.as_ptr(),
                    parent.as_raw_fd(),
                    leaf_c.as_ptr(),
                    0,
                )
            }
        };
        if installed != 0 {
            let error = io::Error::last_os_error();
            drop(staged);
            // SAFETY: the parent descriptor and temporary name remain valid.
            let _ = unsafe { libc::unlinkat(parent.as_raw_fd(), temp_c.as_ptr(), 0) };
            return Err(error);
        }
        if !replace_existing {
            // SAFETY: the link succeeded, so the destination owns the inode;
            // unlink only the unguessable staging name.
            if unsafe { libc::unlinkat(parent.as_raw_fd(), temp_c.as_ptr(), 0) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        parent.sync_all()?;
        Ok(())
    }

    pub(super) fn atomic_write_with<F>(
        root: &Path,
        rel: &str,
        create_parents: bool,
        mode: u32,
        write: F,
    ) -> io::Result<()>
    where
        F: FnOnce(&mut fs::File) -> io::Result<()>,
    {
        let components = parts(rel)?;
        let parent = open_parent(root, &components, create_parents)?;
        atomic_write_in_parent(parent, components.last().unwrap(), rel, mode, true, write)
    }

    fn remove_regular_in_parent(parent: fs::File, leaf: &OsStr) -> io::Result<bool> {
        let Some(existing_mode) = leaf_kind(parent.as_raw_fd(), leaf)? else {
            return Ok(false);
        };
        if existing_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing to remove a non-regular file",
            ));
        }
        let leaf_c = c_name(leaf)?;
        // SAFETY: the parent descriptor is held and leaf_c is one live,
        // NUL-terminated component. If the leaf is raced to a symlink after
        // inspection, unlinkat removes the link entry itself, never its
        // target.
        if unsafe { libc::unlinkat(parent.as_raw_fd(), leaf_c.as_ptr(), 0) } != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                return Ok(false);
            }
            return Err(error);
        }
        parent.sync_all()?;
        Ok(true)
    }

    pub(super) fn remove_regular(root: &Path, rel: &str) -> io::Result<bool> {
        let components = parts(rel)?;
        let parent = match open_parent(root, &components, false) {
            Ok(parent) => parent,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        remove_regular_in_parent(parent, components.last().unwrap())
    }

    #[cfg(test)]
    pub(super) static TEST_BEFORE_RENAME: std::sync::OnceLock<(
        String,
        std::sync::Arc<std::sync::Barrier>,
    )> = std::sync::OnceLock::new();

    #[cfg(test)]
    pub(super) static TEST_BEFORE_OPEN: std::sync::OnceLock<(
        OsString,
        std::sync::Arc<std::sync::Barrier>,
    )> = std::sync::OnceLock::new();
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, GetFileInformationByHandle, LockFileEx, MoveFileExW,
        RemoveDirectoryW, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_WRITE_ATTRIBUTES, LOCKFILE_EXCLUSIVE_LOCK, MOVEFILE_REPLACE_EXISTING,
        MOVEFILE_WRITE_THROUGH, OPEN_ALWAYS, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;

    pub(super) struct SafeDir {
        // Keep the complete root-to-directory chain locked against rename.
        // Retaining only the final handle would let an ancestor path be
        // replaced before a later full-path child open.
        _guards: Vec<fs::File>,
        path: std::path::PathBuf,
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn open_raw(path: &Path, desired_access: u32, directory: bool) -> io::Result<HANDLE> {
        let path = wide(path);
        let mut flags = FILE_FLAG_OPEN_REPARSE_POINT;
        if directory {
            flags |= FILE_FLAG_BACKUP_SEMANTICS;
        }
        // SAFETY: `path` is NUL-terminated and lives through the call. The
        // returned owned handle is checked before use.
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                desired_access,
                // Deliberately omit FILE_SHARE_DELETE. While this handle is
                // held, the directory/file cannot be renamed away and swapped
                // underneath a later full-path operation.
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                flags,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else {
            Ok(handle)
        }
    }

    fn handle_attributes(handle: HANDLE) -> io::Result<u32> {
        // SAFETY: zero is a valid initial bit pattern and the live handle is
        // owned by the caller.
        let mut info = unsafe { std::mem::zeroed::<BY_HANDLE_FILE_INFORMATION>() };
        // SAFETY: `info` is writable and `handle` is live.
        if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(info.dwFileAttributes)
        }
    }

    fn file_from_handle(handle: HANDLE) -> fs::File {
        // SAFETY: `CreateFileW` returned a fresh owned Windows handle and this
        // transfers its sole ownership to `File`.
        unsafe { fs::File::from_raw_handle(handle as _) }
    }

    fn open_locked_dir(path: &Path) -> io::Result<fs::File> {
        let handle = open_raw(path, FILE_READ_ATTRIBUTES, true)?;
        let attributes = match handle_attributes(handle) {
            Ok(attributes) => attributes,
            Err(error) => {
                // SAFETY: the handle is live and has not been transferred.
                unsafe { CloseHandle(handle) };
                return Err(error);
            }
        };
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        {
            // SAFETY: the handle is live and has not been transferred.
            unsafe { CloseHandle(handle) };
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "directory component is a reparse point or not a directory",
            ));
        }
        Ok(file_from_handle(handle))
    }

    impl SafeDir {
        pub(super) fn open(root: &Path) -> io::Result<Self> {
            let resolved = absolute(root)?;
            let mut current = std::path::PathBuf::new();
            // Retain every ancestor until the final component has been opened.
            // Each handle omits FILE_SHARE_DELETE, so no checked component can
            // be replaced while the next one is resolved.
            let mut held = Vec::new();
            for component in resolved.components() {
                current.push(component.as_os_str());
                if matches!(component, Component::RootDir | Component::Normal(_)) {
                    let guard = open_locked_dir(&current)?;
                    held.push(guard);
                }
            }
            if held.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "directory path has no root",
                ));
            }
            Ok(Self {
                _guards: held,
                path: resolved,
            })
        }

        fn cloned_guards(&self) -> io::Result<Vec<fs::File>> {
            self._guards
                .iter()
                .map(fs::File::try_clone)
                .collect::<io::Result<Vec<_>>>()
        }

        pub(super) fn entries(&self) -> io::Result<Vec<SafeEntry>> {
            let mut entries = Vec::new();
            for entry in fs::read_dir(&self.path)? {
                let entry = entry?;
                let path = entry.path();
                let handle = open_raw(&path, FILE_READ_ATTRIBUTES, true)?;
                let attributes = match handle_attributes(handle) {
                    Ok(attributes) => attributes,
                    Err(error) => {
                        // SAFETY: the handle is live and has not transferred.
                        unsafe { CloseHandle(handle) };
                        return Err(error);
                    }
                };
                // SAFETY: inspection is complete and ownership was not
                // transferred to File.
                unsafe { CloseHandle(handle) };
                let kind = if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    EntryKind::Symlink
                } else if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                    EntryKind::Directory
                } else {
                    EntryKind::File
                };
                entries.push(SafeEntry {
                    name: entry.file_name(),
                    kind,
                });
            }
            Ok(entries)
        }

        pub(super) fn open_dir(&self, name: &std::ffi::OsStr) -> io::Result<Self> {
            let path = self.path.join(name);
            let mut guards = self.cloned_guards()?;
            guards.push(open_locked_dir(&path)?);
            Ok(Self {
                _guards: guards,
                path,
            })
        }

        pub(super) fn open_file(&self, name: &std::ffi::OsStr) -> io::Result<fs::File> {
            let path = self.path.join(name);
            let handle = open_raw(&path, GENERIC_READ, false)?;
            let attributes = match handle_attributes(handle) {
                Ok(attributes) => attributes,
                Err(error) => {
                    // SAFETY: the handle is live and has not transferred.
                    unsafe { CloseHandle(handle) };
                    return Err(error);
                }
            };
            if attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0 {
                // SAFETY: the handle is live and has not transferred.
                unsafe { CloseHandle(handle) };
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "entry is a reparse point or not a regular file",
                ));
            }
            Ok(file_from_handle(handle))
        }

        pub(super) fn read_symlink(&self, _name: &std::ffi::OsStr) -> io::Result<OsString> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "secure symlink capture is unsupported on Windows",
            ))
        }

        pub(super) fn create_dir(&self, name: &str, _mode: u32) -> io::Result<Self> {
            let components = parts(name)?;
            if components.len() != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "new directory name must be one component",
                ));
            }
            let path = self.path.join(&components[0]);
            let path_wide = wide(&path);
            if unsafe { CreateDirectoryW(path_wide.as_ptr(), std::ptr::null()) } == 0 {
                return Err(io::Error::last_os_error());
            }
            self.open_dir(&components[0])
        }

        pub(super) fn publish_dir_no_replace(&self, source: &str, target: &str) -> io::Result<()> {
            let source = parts(source)?;
            let target = parts(target)?;
            if source.len() != 1 || target.len() != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "published directory names must be one component",
                ));
            }
            let source_path = self.path.join(&source[0]);
            let target_path = self.path.join(&target[0]);
            let source_wide = wide(&source_path);
            let target_wide = wide(&target_path);
            if unsafe {
                MoveFileExW(
                    source_wide.as_ptr(),
                    target_wide.as_ptr(),
                    MOVEFILE_WRITE_THROUGH,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        pub(super) fn open_relative(&self, rel: &str) -> io::Result<Option<fs::File>> {
            open_regular(&self.path, rel)
        }

        pub(super) fn directory_exists_relative(&self, rel: &str) -> io::Result<bool> {
            let components = parts(rel)?;
            let (_held, parent) = match locked_parent(&self.path, &components, false) {
                Ok(parent) => parent,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
                Err(error) => return Err(error),
            };
            match open_locked_dir(&parent.join(components.last().unwrap())) {
                Ok(_) => Ok(true),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(error),
            }
        }

        pub(super) fn lock_relative(&self, rel: &str) -> io::Result<fs::File> {
            let components = parts(rel)?;
            if components.len() != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "lock name must be one component",
                ));
            }
            let path = wide(&self.path.join(&components[0]));
            // The held directory chain prevents root replacement. Opening the
            // reparse point itself lets us reject one instead of following it.
            let handle = unsafe {
                CreateFileW(
                    path.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    std::ptr::null(),
                    OPEN_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                    std::ptr::null_mut(),
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            let attributes = match handle_attributes(handle) {
                Ok(attributes) => attributes,
                Err(error) => {
                    unsafe { CloseHandle(handle) };
                    return Err(error);
                }
            };
            if attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0 {
                unsafe { CloseHandle(handle) };
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "lock entry is a reparse point or not a regular file",
                ));
            }
            let mut overlapped = unsafe { std::mem::zeroed::<OVERLAPPED>() };
            if unsafe {
                LockFileEx(
                    handle,
                    LOCKFILE_EXCLUSIVE_LOCK,
                    0,
                    u32::MAX,
                    u32::MAX,
                    &mut overlapped,
                )
            } == 0
            {
                let error = io::Error::last_os_error();
                unsafe { CloseHandle(handle) };
                return Err(error);
            }
            Ok(file_from_handle(handle))
        }

        pub(super) fn restore_permissions_relative(
            &self,
            rel: &str,
            _mode: u32,
            readonly: bool,
        ) -> io::Result<()> {
            let components = parts(rel)?;
            let (_held, parent) = locked_parent(&self.path, &components, false)?;
            let path = parent.join(components.last().unwrap());
            let handle = open_raw(&path, FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES, false)?;
            let attributes = match handle_attributes(handle) {
                Ok(attributes) => attributes,
                Err(error) => {
                    unsafe { CloseHandle(handle) };
                    return Err(error);
                }
            };
            if attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0 {
                unsafe { CloseHandle(handle) };
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "restored entry is a reparse point or not a regular file",
                ));
            }
            let file = file_from_handle(handle);
            let mut permissions = file.metadata()?.permissions();
            permissions.set_readonly(readonly);
            file.set_permissions(permissions)
        }

        pub(super) fn atomic_write_relative<F>(
            &self,
            rel: &str,
            create_parents: bool,
            mode: u32,
            write: F,
        ) -> io::Result<()>
        where
            F: FnOnce(&mut fs::File) -> io::Result<()>,
        {
            atomic_write_impl(&self.path, rel, create_parents, mode, true, write)
        }

        pub(super) fn atomic_create_relative<F>(
            &self,
            rel: &str,
            create_parents: bool,
            mode: u32,
            write: F,
        ) -> io::Result<()>
        where
            F: FnOnce(&mut fs::File) -> io::Result<()>,
        {
            atomic_write_impl(&self.path, rel, create_parents, mode, false, write)
        }

        pub(super) fn remove_regular_relative(&self, rel: &str) -> io::Result<bool> {
            remove_regular(&self.path, rel)
        }

        pub(super) fn remove_empty_dir(&self, rel: &str) -> io::Result<bool> {
            let components = parts(rel)?;
            let (_held, parent) = match locked_parent(&self.path, &components, false) {
                Ok(parent) => parent,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
                Err(error) => return Err(error),
            };
            let path = parent.join(components.last().unwrap());
            let handle = match open_raw(&path, FILE_READ_ATTRIBUTES, true) {
                Ok(handle) => handle,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
                Err(error) => return Err(error),
            };
            let attributes = match handle_attributes(handle) {
                Ok(attributes) => attributes,
                Err(error) => {
                    // SAFETY: the handle is live and has not been transferred.
                    unsafe { CloseHandle(handle) };
                    return Err(error);
                }
            };
            // SAFETY: the handle is live and has not been transferred.
            unsafe { CloseHandle(handle) };
            if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || attributes & FILE_ATTRIBUTE_DIRECTORY == 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "refusing to remove a reparse point or non-directory rollback path",
                ));
            }
            let mut random = [0_u8; 16];
            getrandom::getrandom(&mut random)
                .map_err(|_| io::Error::other("operating-system randomness unavailable"))?;
            let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
            let tombstone = parent.join(format!(".sevra-remove-dir-{suffix}"));
            let path_wide = wide(&path);
            let tombstone_wide = wide(&tombstone);
            if unsafe {
                MoveFileExW(
                    path_wide.as_ptr(),
                    tombstone_wide.as_ptr(),
                    MOVEFILE_WRITE_THROUGH,
                )
            } == 0
            {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::NotFound {
                    return Ok(false);
                }
                return Err(error);
            }
            // SAFETY: tombstone_wide is a live NUL-terminated path. If a leaf
            // was raced after inspection, this removes the moved entry itself.
            if unsafe { RemoveDirectoryW(tombstone_wide.as_ptr()) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(true)
        }
    }

    /// Open and retain every directory from the volume root through the
    /// requested parent. Holding without FILE_SHARE_DELETE is Windows'
    /// equivalent of the Unix dirfd chain: no component can be renamed or
    /// replaced until the operation finishes.
    fn locked_parent(
        root: &Path,
        components: &[OsString],
        create: bool,
    ) -> io::Result<(Vec<fs::File>, std::path::PathBuf)> {
        let resolved = absolute(root)?;
        let mut current = std::path::PathBuf::new();
        let mut held = Vec::new();
        for component in resolved.components() {
            current.push(component.as_os_str());
            if matches!(component, Component::RootDir | Component::Normal(_)) {
                held.push(open_locked_dir(&current)?);
            }
        }

        for component in &components[..components.len().saturating_sub(1)] {
            current.push(component);
            match open_locked_dir(&current) {
                Ok(dir) => held.push(dir),
                Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                    let path = wide(&current);
                    // SAFETY: `path` is NUL-terminated and the already-held
                    // parent cannot be renamed during this call.
                    if unsafe { CreateDirectoryW(path.as_ptr(), std::ptr::null()) } == 0 {
                        let create_error = io::Error::last_os_error();
                        if create_error.kind() != io::ErrorKind::AlreadyExists {
                            return Err(create_error);
                        }
                    }
                    held.push(open_locked_dir(&current)?);
                }
                Err(error) => return Err(error),
            }
        }
        Ok((held, current))
    }

    pub(super) fn ensure_dir(path: &Path, _mode: u32) -> io::Result<()> {
        let resolved = absolute(path)?;
        let mut current = std::path::PathBuf::new();
        let mut held = Vec::new();
        for component in resolved.components() {
            current.push(component.as_os_str());
            if !matches!(component, Component::RootDir | Component::Normal(_)) {
                continue;
            }
            match open_locked_dir(&current) {
                Ok(dir) => held.push(dir),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    let path = wide(&current);
                    // SAFETY: the path is NUL-terminated and every existing
                    // parent is held without delete sharing.
                    if unsafe { CreateDirectoryW(path.as_ptr(), std::ptr::null()) } == 0 {
                        let create_error = io::Error::last_os_error();
                        if create_error.kind() != io::ErrorKind::AlreadyExists {
                            return Err(create_error);
                        }
                    }
                    held.push(open_locked_dir(&current)?);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    pub(super) fn open_regular(root: &Path, rel: &str) -> io::Result<Option<fs::File>> {
        let components = parts(rel)?;
        let (_held, parent) = match locked_parent(root, &components, false) {
            Ok(parent) => parent,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let path = parent.join(components.last().unwrap());
        let handle = match open_raw(&path, GENERIC_READ, false) {
            Ok(handle) => handle,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let attributes = match handle_attributes(handle) {
            Ok(attributes) => attributes,
            Err(error) => {
                // SAFETY: the handle is live and has not been transferred.
                unsafe { CloseHandle(handle) };
                return Err(error);
            }
        };
        if attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0 {
            // SAFETY: the handle is live and has not been transferred.
            unsafe { CloseHandle(handle) };
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "leaf is a reparse point or not a regular file",
            ));
        }
        Ok(Some(file_from_handle(handle)))
    }

    pub(super) fn read_regular(root: &Path, rel: &str) -> io::Result<Option<Vec<u8>>> {
        let Some(mut file) = open_regular(root, rel)? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(Some(bytes))
    }

    fn atomic_write_impl<F>(
        root: &Path,
        rel: &str,
        create_parents: bool,
        _mode: u32,
        replace_existing: bool,
        write: F,
    ) -> io::Result<()>
    where
        F: FnOnce(&mut fs::File) -> io::Result<()>,
    {
        let components = parts(rel)?;
        let (_held, parent) = locked_parent(root, &components, create_parents)?;
        let path = parent.join(components.last().unwrap());
        // Refuse static reparse points and non-files. The parent chain remains
        // locked through the final move; a raced leaf entry is replaced as an
        // entry by MoveFileExW, never traversed.
        match open_raw(&path, FILE_READ_ATTRIBUTES, true) {
            Ok(handle) => {
                let attributes = match handle_attributes(handle) {
                    Ok(attributes) => attributes,
                    Err(error) => {
                        // SAFETY: the handle is live and has not transferred.
                        unsafe { CloseHandle(handle) };
                        return Err(error);
                    }
                };
                // SAFETY: inspection is complete and ownership was not
                // transferred to File.
                unsafe { CloseHandle(handle) };
                if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "destination leaf is a reparse point",
                    ));
                }
                if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "destination leaf is not a regular file",
                    ));
                }
                if !replace_existing {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "destination appeared after transaction preflight",
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        let mut random = [0_u8; 16];
        getrandom::getrandom(&mut random)
            .map_err(|_| io::Error::other("operating-system randomness unavailable"))?;
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let staged_path = parent.join(format!(".sevra-new-{suffix}"));
        let mut staged = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged_path)?;
        if let Err(error) = write(&mut staged).and_then(|()| staged.sync_all()) {
            drop(staged);
            let _ = fs::remove_file(&staged_path);
            return Err(error);
        }
        drop(staged);

        let staged_wide = wide(&staged_path);
        let target_wide = wide(&path);
        // SAFETY: both paths are live NUL-terminated strings. Their parent
        // chain is locked against rename, the source name is unguessable and
        // CREATE_NEW-created, and MoveFileExW replaces the destination entry
        // itself rather than following a reparse point planted at that leaf.
        let move_flags = if replace_existing {
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
        } else {
            MOVEFILE_WRITE_THROUGH
        };
        if unsafe { MoveFileExW(staged_wide.as_ptr(), target_wide.as_ptr(), move_flags) } == 0 {
            let error = io::Error::last_os_error();
            let _ = fs::remove_file(&staged_path);
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn atomic_write_with<F>(
        root: &Path,
        rel: &str,
        create_parents: bool,
        mode: u32,
        write: F,
    ) -> io::Result<()>
    where
        F: FnOnce(&mut fs::File) -> io::Result<()>,
    {
        atomic_write_impl(root, rel, create_parents, mode, true, write)
    }

    pub(super) fn remove_regular(root: &Path, rel: &str) -> io::Result<bool> {
        let components = parts(rel)?;
        let (_held, parent) = match locked_parent(root, &components, false) {
            Ok(parent) => parent,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        let path = parent.join(components.last().unwrap());
        let handle = match open_raw(&path, FILE_READ_ATTRIBUTES, false) {
            Ok(handle) => handle,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        let attributes = match handle_attributes(handle) {
            Ok(attributes) => attributes,
            Err(error) => {
                // SAFETY: the handle is live and has not been transferred.
                unsafe { CloseHandle(handle) };
                return Err(error);
            }
        };
        // Close before rename: open_raw intentionally denied delete sharing.
        // The parent chain remains locked, and MoveFileExW moves a raced leaf
        // entry itself rather than following a reparse target.
        // SAFETY: the handle is live and has not been transferred.
        unsafe { CloseHandle(handle) };
        if attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing to remove a reparse point or non-regular file",
            ));
        }

        let mut random = [0_u8; 16];
        getrandom::getrandom(&mut random)
            .map_err(|_| io::Error::other("operating-system randomness unavailable"))?;
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let tombstone = parent.join(format!(".sevra-remove-{suffix}"));
        let path_wide = wide(&path);
        let tombstone_wide = wide(&tombstone);
        // SAFETY: both paths are live NUL-terminated strings and the complete
        // parent chain is held against rename. No replacement flag means an
        // astronomically unlikely collision refuses.
        if unsafe {
            MoveFileExW(
                path_wide.as_ptr(),
                tombstone_wide.as_ptr(),
                MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                return Ok(false);
            }
            return Err(error);
        }
        fs::remove_file(tombstone)?;
        Ok(true)
    }

    pub(super) fn create_symlink(_root: &Path, _rel: &str, _target: &str) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "secure symlink restoration is unsupported on Windows",
        ))
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use super::*;

    pub(super) struct SafeDir;

    impl SafeDir {
        pub(super) fn open(_root: &Path) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "secure directory traversal is unsupported on this platform",
            ))
        }

        pub(super) fn atomic_create_relative<F>(
            &self,
            _rel: &str,
            _create_parents: bool,
            _mode: u32,
            _write: F,
        ) -> io::Result<()>
        where
            F: FnOnce(&mut fs::File) -> io::Result<()>,
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "secure relative filesystem access is unsupported on this platform",
            ))
        }

        pub(super) fn entries(&self) -> io::Result<Vec<SafeEntry>> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "secure directory traversal is unsupported on this platform",
            ))
        }

        pub(super) fn open_dir(&self, _name: &std::ffi::OsStr) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "secure directory traversal is unsupported on this platform",
            ))
        }

        pub(super) fn open_file(&self, _name: &std::ffi::OsStr) -> io::Result<fs::File> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "secure directory traversal is unsupported on this platform",
            ))
        }

        pub(super) fn read_symlink(&self, _name: &std::ffi::OsStr) -> io::Result<OsString> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "secure symlink capture is unsupported on this platform",
            ))
        }

        pub(super) fn create_dir(&self, _name: &str, _mode: u32) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "secure directory creation is unsupported on this platform",
            ))
        }

        pub(super) fn publish_dir_no_replace(
            &self,
            _source: &str,
            _target: &str,
        ) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "atomic directory publish is unsupported on this platform",
            ))
        }

        pub(super) fn open_relative(&self, _rel: &str) -> io::Result<Option<fs::File>> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "secure relative filesystem access is unsupported on this platform",
            ))
        }

        pub(super) fn directory_exists_relative(&self, _rel: &str) -> io::Result<bool> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "secure relative filesystem access is unsupported on this platform",
            ))
        }

        pub(super) fn lock_relative(&self, _rel: &str) -> io::Result<fs::File> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "secure filesystem locking is unsupported on this platform",
            ))
        }

        pub(super) fn restore_permissions_relative(
            &self,
            _rel: &str,
            _mode: u32,
            _readonly: bool,
        ) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "secure permission restoration is unsupported on this platform",
            ))
        }

        pub(super) fn atomic_write_relative<F>(
            &self,
            _rel: &str,
            _create_parents: bool,
            _mode: u32,
            _write: F,
        ) -> io::Result<()>
        where
            F: FnOnce(&mut fs::File) -> io::Result<()>,
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "secure relative filesystem access is unsupported on this platform",
            ))
        }

        pub(super) fn remove_regular_relative(&self, _rel: &str) -> io::Result<bool> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "secure relative filesystem access is unsupported on this platform",
            ))
        }

        pub(super) fn remove_empty_dir(&self, _rel: &str) -> io::Result<bool> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "secure relative filesystem access is unsupported on this platform",
            ))
        }
    }

    pub(super) fn open_regular(_root: &Path, _rel: &str) -> io::Result<Option<fs::File>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "secure relative filesystem access is unsupported on this platform",
        ))
    }

    pub(super) fn read_regular(_root: &Path, _rel: &str) -> io::Result<Option<Vec<u8>>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "secure relative filesystem access is unsupported on this platform",
        ))
    }

    pub(super) fn ensure_dir(_path: &Path, _mode: u32) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "secure directory creation is unsupported on this platform",
        ))
    }

    pub(super) fn atomic_write_with<F>(
        _root: &Path,
        _rel: &str,
        _create_parents: bool,
        _mode: u32,
        _write: F,
    ) -> io::Result<()>
    where
        F: FnOnce(&mut fs::File) -> io::Result<()>,
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "secure relative filesystem access is unsupported on this platform",
        ))
    }

    pub(super) fn remove_regular(_root: &Path, _rel: &str) -> io::Result<bool> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "secure relative filesystem access is unsupported on this platform",
        ))
    }

    pub(super) fn create_symlink(_root: &Path, _rel: &str, _target: &str) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "secure symlink restoration is unsupported on this platform",
        ))
    }
}

pub fn read_regular(root: &Path, rel: &str) -> io::Result<Option<Vec<u8>>> {
    platform::read_regular(root, rel)
}

pub fn open_regular(root: &Path, rel: &str) -> io::Result<Option<fs::File>> {
    platform::open_regular(root, rel)
}

pub struct SafeDir(platform::SafeDir);

impl SafeDir {
    pub fn open(root: &Path) -> io::Result<Self> {
        platform::SafeDir::open(root).map(Self)
    }

    pub fn entries(&self) -> io::Result<Vec<SafeEntry>> {
        self.0.entries()
    }

    pub fn open_dir(&self, name: &std::ffi::OsStr) -> io::Result<Self> {
        self.0.open_dir(name).map(Self)
    }

    pub fn open_file(&self, name: &std::ffi::OsStr) -> io::Result<fs::File> {
        self.0.open_file(name)
    }

    pub fn read_symlink(&self, name: &std::ffi::OsStr) -> io::Result<OsString> {
        self.0.read_symlink(name)
    }

    pub fn create_dir(&self, name: &str, mode: u32) -> io::Result<Self> {
        self.0.create_dir(name, mode).map(Self)
    }

    pub fn publish_dir_no_replace(&self, source: &str, target: &str) -> io::Result<()> {
        self.0.publish_dir_no_replace(source, target)
    }

    pub fn open_relative(&self, rel: &str) -> io::Result<Option<fs::File>> {
        self.0.open_relative(rel)
    }

    pub fn directory_exists_relative(&self, rel: &str) -> io::Result<bool> {
        self.0.directory_exists_relative(rel)
    }

    pub fn lock_relative(&self, rel: &str) -> io::Result<fs::File> {
        self.0.lock_relative(rel)
    }

    pub fn restore_permissions(&self, rel: &str, mode: u32, readonly: bool) -> io::Result<()> {
        self.0.restore_permissions_relative(rel, mode, readonly)
    }

    pub fn atomic_write(
        &self,
        rel: &str,
        data: &[u8],
        create_parents: bool,
        mode: u32,
    ) -> io::Result<()> {
        self.atomic_write_with(rel, create_parents, mode, |file| file.write_all(data))
    }

    pub fn atomic_write_with<F>(
        &self,
        rel: &str,
        create_parents: bool,
        mode: u32,
        write: F,
    ) -> io::Result<()>
    where
        F: FnOnce(&mut fs::File) -> io::Result<()>,
    {
        self.0
            .atomic_write_relative(rel, create_parents, mode, write)
    }

    pub fn atomic_create(
        &self,
        rel: &str,
        data: &[u8],
        create_parents: bool,
        mode: u32,
    ) -> io::Result<()> {
        self.atomic_create_with(rel, create_parents, mode, |file| file.write_all(data))
    }

    pub fn atomic_create_with<F>(
        &self,
        rel: &str,
        create_parents: bool,
        mode: u32,
        write: F,
    ) -> io::Result<()>
    where
        F: FnOnce(&mut fs::File) -> io::Result<()>,
    {
        self.0
            .atomic_create_relative(rel, create_parents, mode, write)
    }

    pub fn remove_regular(&self, rel: &str) -> io::Result<bool> {
        self.0.remove_regular_relative(rel)
    }

    pub fn remove_empty_dir(&self, rel: &str) -> io::Result<bool> {
        self.0.remove_empty_dir(rel)
    }
}

pub fn ensure_dir(path: &Path, mode: u32) -> io::Result<()> {
    platform::ensure_dir(path, mode)
}

/// Create one relative symlink beneath `root` without following or replacing
/// any destination component. The caller validates that `target` resolves
/// inside the restored workspace.
pub fn create_symlink(root: &Path, rel: &str, target: &str) -> io::Result<()> {
    platform::create_symlink(root, rel, target)
}

pub fn atomic_write(
    root: &Path,
    rel: &str,
    data: &[u8],
    create_parents: bool,
    mode: u32,
) -> io::Result<()> {
    atomic_write_with(root, rel, create_parents, mode, |file| file.write_all(data))
}

pub fn atomic_write_with<F>(
    root: &Path,
    rel: &str,
    create_parents: bool,
    mode: u32,
    write: F,
) -> io::Result<()>
where
    F: FnOnce(&mut fs::File) -> io::Result<()>,
{
    platform::atomic_write_with(root, rel, create_parents, mode, write)
}

pub fn remove_regular(root: &Path, rel: &str) -> io::Result<bool> {
    platform::remove_regular(root, rel)
}

#[cfg(all(test, any(unix, windows)))]
mod common_tests {
    use super::*;

    #[test]
    fn streamed_atomic_write_commits_only_after_the_writer_succeeds() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();

        atomic_write_with(&root, "asset.bin", false, 0o600, |staged| {
            staged.write_all(b"streamed ")?;
            staged.write_all(b"asset")
        })
        .unwrap();
        assert_eq!(fs::read(root.join("asset.bin")).unwrap(), b"streamed asset");

        let result = atomic_write_with(&root, "asset.bin", false, 0o600, |staged| {
            staged.write_all(b"unverified partial bytes")?;
            Err(io::Error::other("verification failed"))
        });
        assert!(result.is_err());
        assert_eq!(fs::read(root.join("asset.bin")).unwrap(), b"streamed asset");
        assert!(fs::read_dir(&root).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".sevra-new-")));
    }
}

#[cfg(all(test, unix))]
pub(crate) fn set_test_before_open(name: OsString, barrier: std::sync::Arc<std::sync::Barrier>) {
    platform::TEST_BEFORE_OPEN
        .set((name, barrier))
        .expect("one exact open-race test owns the hook");
}

#[cfg(all(test, unix))]
mod unix_tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    #[test]
    fn atomic_write_remains_bound_when_ancestor_is_swapped_before_rename() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap().join("root");
        let parent = root.join("inside");
        let parked = root.join("parked");
        let outside = temp.path().join("outside");
        fs::create_dir_all(&parent).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("victim"), b"SAFE").unwrap();

        let barrier = Arc::new(Barrier::new(2));
        platform::TEST_BEFORE_RENAME
            .set(("inside/victim".into(), Arc::clone(&barrier)))
            .expect("one exact race test owns the hook");
        let root_for_writer = root.clone();
        let writer = std::thread::spawn(move || {
            atomic_write(&root_for_writer, "inside/victim", b"VERIFIED", false, 0o600)
        });

        // The writer holds the original parent descriptor and has fully
        // written/synced its temporary file. Replace the path spelling with a
        // symlink before the final rename, exactly the old TOCTOU window.
        barrier.wait();
        fs::rename(&parent, &parked).unwrap();
        std::os::unix::fs::symlink(&outside, &parent).unwrap();
        barrier.wait();

        writer.join().unwrap().unwrap();
        assert_eq!(fs::read(outside.join("victim")).unwrap(), b"SAFE");
        assert_eq!(fs::read(parked.join("victim")).unwrap(), b"VERIFIED");
    }

    #[test]
    fn secure_directory_creation_refuses_a_root_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(temp.path()).unwrap();
        let outside = base.join("outside");
        fs::create_dir(&outside).unwrap();
        let root = base.join("export");
        std::os::unix::fs::symlink(&outside, &root).unwrap();

        assert!(ensure_dir(&root, 0o755).is_err());
        assert!(atomic_write(&root, "victim", b"ATTACK", true, 0o600).is_err());
        assert!(!outside.join("victim").exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn secure_directory_creation_accepts_the_fixed_macos_temp_alias() {
        let temp = tempfile::tempdir().unwrap();
        let requested = temp.path().join("export-parent");
        assert!(requested.starts_with("/var") || requested.starts_with("/tmp"));

        ensure_dir(&requested, 0o700).unwrap();
        assert!(requested.is_dir());
    }

    #[test]
    fn remove_regular_refuses_a_symlinked_root_without_deleting_its_target() {
        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("config.json"), b"KEEP").unwrap();
        let root = temp.path().join("root");
        std::os::unix::fs::symlink(&outside, &root).unwrap();

        assert!(remove_regular(&root, "config.json").is_err());
        assert_eq!(fs::read(outside.join("config.json")).unwrap(), b"KEEP");
    }

    #[test]
    fn remove_regular_unlinks_only_a_regular_leaf() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("config.json"), b"credential").unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        assert!(remove_regular(&root, "config.json").unwrap());
        assert!(!temp.path().join("config.json").exists());
        assert!(!remove_regular(&root, "config.json").unwrap());
    }

    #[test]
    fn store_lock_never_follows_a_symlink_leaf() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        fs::write(root.join("outside"), b"KEEP").unwrap();
        std::os::unix::fs::symlink(root.join("outside"), root.join(".sevra-pull.lock")).unwrap();
        let held = SafeDir::open(&root).unwrap();

        assert!(held.lock_relative(".sevra-pull.lock").is_err());
        assert_eq!(fs::read(root.join("outside")).unwrap(), b"KEEP");
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use std::os::windows::fs::{symlink_dir, symlink_file};

    #[test]
    fn refuses_reparse_point_parent_for_read_and_write() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("victim"), b"SAFE").unwrap();
        symlink_dir(&outside, root.join("alias")).unwrap();

        assert!(read_regular(&root, "alias/victim").is_err());
        assert!(atomic_write(&root, "alias/victim", b"ATTACK", true, 0o600).is_err());
        assert_eq!(fs::read(outside.join("victim")).unwrap(), b"SAFE");
    }

    #[test]
    fn refuses_reparse_point_leaf_for_read() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("victim"), b"SECRET").unwrap();
        symlink_file(outside.join("victim"), root.join("alias")).unwrap();

        assert!(read_regular(&root, "alias").is_err());
    }

    #[test]
    fn atomic_write_refuses_a_reparse_leaf_without_touching_its_target() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("victim"), b"SAFE").unwrap();
        symlink_file(outside.join("victim"), root.join("alias")).unwrap();

        assert!(atomic_write(&root, "alias", b"VERIFIED", false, 0o600).is_err());
        assert_eq!(fs::read(outside.join("victim")).unwrap(), b"SAFE");
        assert!(fs::symlink_metadata(root.join("alias"))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn secure_directory_creation_refuses_a_reparse_root() {
        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let root = temp.path().join("root");
        symlink_dir(&outside, &root).unwrap();

        assert!(ensure_dir(&root, 0o700).is_err());
        assert!(remove_regular(&root, "config.json").is_err());
        assert!(!outside.join("config.json").exists());
    }

    #[test]
    fn remove_regular_refuses_reparse_leaf_and_removes_regular_file() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("victim"), b"KEEP").unwrap();
        symlink_file(outside.join("victim"), root.join("config.json")).unwrap();

        assert!(remove_regular(&root, "config.json").is_err());
        assert_eq!(fs::read(outside.join("victim")).unwrap(), b"KEEP");

        fs::remove_file(root.join("config.json")).unwrap();
        fs::write(root.join("config.json"), b"credential").unwrap();
        assert!(remove_regular(&root, "config.json").unwrap());
        assert!(!root.join("config.json").exists());
    }
}
