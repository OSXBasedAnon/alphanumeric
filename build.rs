use winres::WindowsResource;

fn main() {
    let mut res = WindowsResource::new();
    res.set_icon("app_icon.ico");
    res.compile().unwrap();
}
