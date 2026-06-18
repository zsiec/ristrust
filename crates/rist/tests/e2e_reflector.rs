//! The Main-profile reflector: a transparent one-to-many fan-out relay. A sender feeds
//! one input flow; the reflector recovers it and re-emits every packet to N outputs
//! preserving `(seq, source_time)`. Each output must receive the stream byte-exact.

use std::time::Duration;

use rist::{Config, Error, Profile, Receiver, dial, listen, reflect};

/// Probes an OS-chosen free UDP port (for an address a constructor will bind itself).
fn free_port() -> u16 {
    for _ in 0..64 {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe bind");
        let port = probe.local_addr().expect("probe addr").port();
        drop(probe);
        if port != 0 {
            return port;
        }
    }
    panic!("no free port");
}

/// Binds a Main receiver on a free port, retrying past the probe/bind race.
async fn listen_free(cfg: &Config) -> (Receiver, u16) {
    for _ in 0..64 {
        let port = free_port();
        if let Ok(r) = listen(&format!("127.0.0.1:{port}"), cfg.clone()).await {
            return (r, port);
        }
    }
    panic!("could not bind a Main receiver");
}

#[tokio::test]
async fn reflector_fans_one_input_to_two_outputs_byte_exact() {
    let cfg = Config::default().with_profile(Profile::Main);

    // Two downstream output receivers.
    let (mut out1, p1) = listen_free(&cfg).await;
    let (mut out2, p2) = listen_free(&cfg).await;

    // The reflector: listen for the input, fan out to both outputs. Retry the input
    // bind past the probe/bind race.
    let (reflector, in_port) = 'bind: loop {
        let port = free_port();
        // The probe/bind race may lose the port; retry on any bind error.
        if let Ok(r) = reflect(
            &format!("127.0.0.1:{port}"),
            &[&format!("127.0.0.1:{p1}"), &format!("127.0.0.1:{p2}")],
            cfg.clone(),
        )
        .await
        {
            break 'bind (r, port);
        }
    };
    assert_eq!(reflector.output_count(), 2);

    // The origin sender feeds the reflector's input.
    let sender = dial(&format!("127.0.0.1:{in_port}"), cfg.clone())
        .await
        .expect("dial reflector input");

    let frames: Vec<Vec<u8>> = (0..40u8).map(|i| vec![i.wrapping_add(1); 188]).collect();
    let send_frames = frames.clone();
    let send_task = tokio::spawn(async move {
        for frame in &send_frames {
            sender.send(frame).await.expect("send to reflector");
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        sender
    });

    // Both outputs receive the identical stream byte-exact.
    for (i, want) in frames.iter().enumerate() {
        let g1 = tokio::time::timeout(Duration::from_secs(10), out1.recv())
            .await
            .unwrap_or_else(|_| panic!("out1 timed out on frame {i}"))
            .expect("out1 open");
        let g2 = tokio::time::timeout(Duration::from_secs(10), out2.recv())
            .await
            .unwrap_or_else(|_| panic!("out2 timed out on frame {i}"))
            .expect("out2 open");
        assert_eq!(
            g1.as_ref(),
            want.as_slice(),
            "out1 frame {i} not byte-exact"
        );
        assert_eq!(
            g2.as_ref(),
            want.as_slice(),
            "out2 frame {i} not byte-exact"
        );
    }

    let sender = send_task.await.expect("send task");
    sender.close().await.expect("close sender");
    reflector.close().await.expect("close reflector");
    out1.close().await.expect("close out1");
    out2.close().await.expect("close out2");
}

#[tokio::test]
async fn reflect_rejects_non_main_and_empty_outputs() {
    // Simple profile is rejected.
    let err = reflect("127.0.0.1:9000", &["127.0.0.1:9002"], Config::default())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Unimplemented(_)), "got {err:?}");

    // No outputs is rejected.
    let err = reflect(
        "127.0.0.1:9000",
        &[],
        Config::default().with_profile(Profile::Main),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::Unimplemented(_)), "got {err:?}");
}
