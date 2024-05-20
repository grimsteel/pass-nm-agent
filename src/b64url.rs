pub fn to_base64url(value: &str) -> String {
    value.chars()
        .map(|c| {
            match c {
                '+' => '-',
                '/' => '_',
                c => c
            }
        })
        .collect()
}
