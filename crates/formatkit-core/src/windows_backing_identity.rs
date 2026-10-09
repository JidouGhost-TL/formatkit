//! Narrow Win32 backing-identity query; no parser or allocation policy.
use std::fs::File;
use std::os::windows::io::AsRawHandle;
use windows_sys::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
};

pub(super) fn query(file: &File) -> std::io::Result<(u32, u64)> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the borrowed File keeps its handle live through this synchronous
    // call. The initialized output has the exact Win32 type and remains writable
    // for the duration of the call. Nothing from it is consumed on failure.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut information) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((
        information.dwVolumeSerialNumber,
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
    ))
}
