use clap::Parser;
use rtshark;

#[derive(Parser)]
struct Args {
    #[arg(short = 'f', long)]
    pcapfile: String,
    #[arg(short = 'p', long, value_name = "PORT NUMBER(s)")]
    http2ports: Option<String>,
    #[arg(short = 'i', long, value_name = "IMSI")]
    imsi: Option<String>,
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

    if args.imsi == None {
        pickup_imsi(&mut rtshark);
        return;
    }

    let _imsi = &args.imsi.unwrap();

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

fn pickup_imsi(rtshark: &mut rtshark::RTShark) {
    const IMSI_PREFIX: usize = 5; // imsi-
    const IMSI_LENGTH: usize = 13; // 2089300007487

    let mut imsi_list: Vec<String> = vec![];

    // read packets until the end of the PCAP file
    while let Some(packet) = rtshark.read().unwrap_or_else(|e| {
        eprintln!("Error parsing TShark output: {e}");
        None
    }) {
        'packet: for layer in packet {
            for metadata in layer {
                let head = metadata.value().find("imsi-");
                if head == None {
                    continue;
                }
                let n = head.unwrap();
                let tmp = substr(
                    metadata.value(),
                    n + IMSI_PREFIX,
                    n + IMSI_PREFIX + IMSI_LENGTH,
                );
                let mut found_new_imsi = true;
                for imsi in &imsi_list {
                    if imsi != &tmp {
                        found_new_imsi = true;
                        break;
                    }
                    found_new_imsi = false;
                }
                if found_new_imsi {
                    imsi_list.push(tmp.to_string());
                    break 'packet;
                }
            }
        }
    }
    let imsi_len = imsi_list.len();
    if imsi_len == 0 {
        println!("imsi not found in the capture file.");
        return;
    }
    println!("following imsi(s) found.");
    for imsi in imsi_list {
        println!("{}", imsi);
    }
    return;
}

fn substr(line: &str, begin: usize, end: usize) -> String {
    let mut tmp = "".to_string();
    for (i, c) in line.chars().enumerate() {
        if i >= begin && i < end {
            tmp.push(c);
        }
    }
    tmp
}
