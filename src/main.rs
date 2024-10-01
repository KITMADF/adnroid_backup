use ftp::{FtpStream, FtpError};  // Импортируйте FtpError
use std::io::{Cursor, Result};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

// Функция для подключения к FTP-серверу
fn connect_to_ftp(server: &str, username: &str, password: &str) -> Result<FtpStream> {
    let mut ftp_stream = FtpStream::connect(server).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    ftp_stream.login(username, password).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    println!("Подключение к серверу установлено!");
    Ok(ftp_stream)
}

// Функция для загрузки файла на сервер
fn upload_file(ftp_stream: &mut FtpStream, remote_path: &str, data: &[u8]) -> Result<()> {
    let mut reader = Cursor::new(data);
    ftp_stream.put(remote_path, &mut reader).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    println!("Файл загружен на сервер!");
    Ok(())
}

fn main() {
    // Пример подключения к FTP-серверу
    let server = "192.168.1.100:21"; // Укажите IP адрес вашего сервера
    let username = "user";
    let password = "pass";

    // Попробуем подключиться к серверу
    match connect_to_ftp(server, username, password) {
        Ok(mut ftp_stream) => {
            // Пример загрузки файла на сервер
            let file_data = b"Hello, FTP!";
            if let Err(e) = upload_file(&mut ftp_stream, "/backup/file.txt", file_data) {
                println!("Ошибка при загрузке файла: {:?}", e);
            }
        }
        Err(e) => println!("Ошибка подключения: {:?}", e),
    }
}

#[no_mangle]
pub extern "C" fn connect_to_ftp_jni(server: *const c_char, username: *const c_char, password: *const c_char) -> bool {
    let server = unsafe { CStr::from_ptr(server).to_str().unwrap() };
    let username = unsafe { CStr::from_ptr(username).to_str().unwrap() };
    let password = unsafe { CStr::from_ptr(password).to_str().unwrap() };

    match connect_to_ftp(server, username, password) {
        Ok(_) => true,
        Err(_) => false,
    }
}
