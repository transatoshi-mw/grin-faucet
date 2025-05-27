# grin_faucet

Grin faucet written in Rust with a vanilla HTML/CSS/JS frontend.

It is meant to run on your Grin node, you will need to edit the wallet \<PASSWORD\> and URLs in main.rs.

There is no front end or webserver included so you will need to serve an HTML/CSS/JS page with something like Nginx.

To run after changing parameters, simply clone the repository, cd in to it, and execute 'cargo run'. Your faucet will listen on port 3031. Check out the releases page for an executable.


