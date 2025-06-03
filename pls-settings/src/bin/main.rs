fn main() {
    let settings = pls_settings::Settings::default();
    let generate = foundations::settings::to_yaml_string(&settings).unwrap();
    println!("{}", generate);
}
