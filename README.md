# grin-faucet

Grin faucet backend written in Rust.

It is meant to run on your Grin node, you will need to edit the wallet \<PASSWORD\>, \<DIRs\> and \<URLs\> in main.rs.

There is no front end or webserver included so you will need to serve an HTML/CSS/JS page with something like Nginx.

To run after cloning and changing parameters, cd in to it, and execute 'cargo run'. Your faucet will listen on port 3031. Check out the releases page for an executable. To create your own executable run 'cargo build --release'.


