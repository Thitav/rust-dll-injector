use std::{
  ffi::c_void,
  io::{self, Error, ErrorKind, Write},
  mem::{size_of, transmute, zeroed},
};
use windows::{
  s,
  Win32::{
    Foundation::{GetLastError, CHAR, HINSTANCE, INVALID_HANDLE_VALUE},
    System::{
      Com::{CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED},
      Diagnostics::{
        Debug::WriteProcessMemory,
        ToolHelp::{
          CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
          TH32CS_SNAPPROCESS,
        },
      },
      LibraryLoader::{GetModuleHandleExA, GetProcAddress},
      Memory::{VirtualAllocEx, MEM_COMMIT, PAGE_READWRITE},
      Threading::{CreateRemoteThreadEx, OpenProcess, PROCESS_ALL_ACCESS},
    },
    UI::Shell::{FileOpenDialog, IFileDialog, SIGDN_FILESYSPATH},
  },
};

unsafe fn winapi_error(message: &str) -> Error {
  let error = GetLastError().to_hresult();
  Error::new(
    ErrorKind::Other,
    format!(
      "{:?}: windows api error {:?}: {:?}",
      message,
      error,
      error.message()
    ),
  )
}

fn main() -> Result<(), Error> {
  let mut pid = 0;

  print!("Target process name: ");
  io::stdout().flush()?;
  let mut target_process = String::new();
  io::stdin().read_line(&mut target_process)?;
  target_process = target_process.trim().to_string();

  println!("Please select the dll file to inject into the target process");
  unsafe {
    CoInitializeEx(None, COINIT_MULTITHREADED)?;
    let file_dialog: IFileDialog = CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER)?;
    file_dialog.Show(None)?;
    let dll_path = file_dialog
      .GetResult()?
      .GetDisplayName(SIGDN_FILESYSPATH)?
      .to_string()
      .expect("Unable to convert dll path to string");

    let process_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
    if process_snapshot == INVALID_HANDLE_VALUE {
      return Err(winapi_error("Unable to create tool help snapshot"));
    }

    let mut process_entry: PROCESSENTRY32 = zeroed();
    process_entry.dwSize = size_of::<PROCESSENTRY32>() as u32;
    if Process32First(process_snapshot, &mut process_entry).as_bool() {
      while Process32Next(process_snapshot, &mut process_entry).as_bool() {
        let process_name = String::from_utf8(
          process_entry
            .szExeFile
            .to_vec()
            .iter()
            .enumerate()
            .filter(|&(_, &c)| c != CHAR(0))
            .map(|(_, &c)| transmute::<CHAR, u8>(c))
            .collect(),
        )
        .expect("Unable to convert process name to string");

        if process_name == target_process {
          pid = process_entry.th32ProcessID;
          break;
        }

        process_entry.szExeFile = zeroed();
      }
    } else {
      return Err(winapi_error("Unable to get process list"));
    }

    if pid == 0 {
      return Err(Error::new(
        ErrorKind::Other,
        "Unable to find target process",
      ));
    }

    let mut kernel_module: HINSTANCE = Default::default();
    if !GetModuleHandleExA(0, s!("kernel32.dll"), &mut kernel_module).as_bool() {
      return Err(winapi_error("Unable to get kernel module handle"));
    };

    let function_addr = GetProcAddress(kernel_module, s!("LoadLibraryA"));
    let process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid)?;
    let alloc_addr = VirtualAllocEx(
      process_handle,
      None,
      dll_path.len() + 1,
      MEM_COMMIT,
      PAGE_READWRITE,
    );
    WriteProcessMemory(
      process_handle,
      alloc_addr,
      dll_path.as_ptr() as *const c_void,
      dll_path.len() + 1,
      None,
    );
    CreateRemoteThreadEx(
      process_handle,
      None,
      0,
      transmute(function_addr),
      Some(alloc_addr),
      0,
      None,
      None,
    )?;
  }

  println!("Injection completed!");

  Ok(())
}
