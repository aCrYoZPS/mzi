# МЗИ -- лабораторные работы

## Setup (once per machine)

```sh
./install-template.sh
```

Installs the BSUIR STP 01-2024 typst template as the local typst package
`@local/stp2024:0.1.0`, into the platform's typst data directory:

| OS      | Path                                                  |
|---------|-------------------------------------------------------|
| Windows | `%APPDATA%\typst\packages\local\stp2024\0.1.0\`        |
| Linux   | `~/.local/share/typst/packages/local/stp2024/0.1.0/`   |
| macOS   | `~/Library/Application Support/typst/packages/local/…` |

The sources are taken from `~/typst` (cloned automatically if missing); set
`TYPST_TEMPLATE_SRC` to override. Because typst resolves `@local/…` itself,
the repo contains **no symlinks and no vendored `lib/`** -- reports build
identically on Windows and Linux.

The template needs the fonts Times New Roman, Courier New and GOST type B
(`~/typst/fonts`) installed system-wide.

## Building reports

```sh
./build.sh          # all labs
./build.sh lab1     # one lab
```

Produces `labN/report/labN.pdf`.

## Layout

```
labN/
  src/                 Rust sources
  report/
    main.typ           #import "@local/stp2024:0.1.0"
    title.typ
    img/               screenshots
    labN.pdf
```

Listings pull the real sources via `read("../src/…")`, so they never drift
from the code -- this is why `build.sh` passes `--root labN`.
