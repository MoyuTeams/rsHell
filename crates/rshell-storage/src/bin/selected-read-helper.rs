#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
pub mod selected_read_helper;

fn main() {
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    {
        selected_read_helper::main();
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        std::process::exit(2);
    }
}
