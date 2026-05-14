fn main() {
    if let Err(e) = ocean::cli::run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
