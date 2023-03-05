use clap::Parser;
use rtshark;

#[derive(Parser)]
struct Args {
    #[arg(short = 'f', long)]
    pcapfile: String,
    #[arg(short = 'p', long, value_name = "PORT NUMBER(s)")]
    http2ports: Option<String>,
}

fn main() {
    let args = Args::parse();

    // Creates a builder with needed tshark parameters
    let mut builder = rtshark::RTSharkBuilder::builder()
        //let builder = rtshark::RTSharkBuilder::builder()
        .input_path(&args.pcapfile);

    // 29502,29503,29504,29507,29509,29518
    let mut decode_as_expr: Vec<String> = vec![];
    if args.http2ports != None {
        for port in args.http2ports.unwrap().split(',') {
            let expr = String::from(format!("tcp.port=={},http2", port));
            decode_as_expr.push(expr);
            /*
             * Rust forbids second borrowing on the same scope...
             * How can we avoid the second loop?
             */
            //builder = builder.decode_as(&decode_as_expr[i]);
        }
        for (i, _) in decode_as_expr.iter().enumerate() {
            builder = builder.decode_as(&decode_as_expr[i]);
        }
    }

    // Start a new TShark process
    let mut rtshark = match builder.spawn() {
        Err(err) => {
            eprintln!("Error running tshark: {err}");
            return;
        }
        Ok(rtshark) => rtshark,
    };

    // read packets until the end of the PCAP file
    while let Some(packet) = rtshark.read().unwrap_or_else(|e| {
        eprintln!("Error parsing TShark output: {e}");
        None
    }) {
        println!("Frame");
        for layer in packet {
            println!("    Layer: {}", layer.name());
            for metadata in layer {
                println!("        {}", metadata.display());
            }
        }
    }
}
