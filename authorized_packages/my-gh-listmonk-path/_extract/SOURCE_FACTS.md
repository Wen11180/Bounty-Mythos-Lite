# Source facts — my-gh-listmonk-path

- Upstream: knadh/listmonk **v6.2.0**
- Primary control: `filepath.Base(url)` inside filesystem `GetBlob` before `os.ReadFile(join(uploadPath, base))`
- Upload control: `makeFilename` -> whitespace normalize + `filepath.Base`
- Primary sink: media store blob read (`GetBlob` / modeled `get_blob`)
- Serve route: `ServeS3Media` passes path param into `GetBlob` (Base still applied for FS provider)
- Package models basename-before-read for expected **refute**