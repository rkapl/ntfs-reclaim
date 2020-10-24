R=--release
RUST_BACKTRACE=full cargo run \
    $R \
    -- --reuse-sigs --partition-offset=8064 --parse-indices \
    -m ~/Downloads/vrys/bk1.map ~/Downloads/vrys/bk1-work.img ~/Downloads/vrys/work -v "$@"
