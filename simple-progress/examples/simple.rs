use simple_progress::ProgressBar;
use std::thread;
use std::time::Duration;

fn main() {
    println!("Testing simple-progress library...\n");

    // Create a progress bar with custom message format
    let pb = ProgressBar::new("Progress: {total} items | {elapsed} | Rate: {rate}/s");

    // Test 1: Single increments with some logging
    pb.log("Starting test 1: Single increments");
    for i in 0..40 {
        pb.inc();
        thread::sleep(Duration::from_millis(25));

        if i == 20 {
            pb.log("Halfway through test 1!");
        }
    }

    // Test 2: Batch increments to test inc_many
    pb.log("Starting test 2: Batch increments");
    for _ in 0..10 {
        pb.inc_many(25);
        thread::sleep(Duration::from_millis(50));
    }

    // Test 3: High-frequency updates to test performance
    pb.log("Starting test 3: High-frequency updates");
    let pb_clone = pb.clone();
    let handle = thread::spawn(move || {
        for _ in 0..1000 {
            pb_clone.inc();
            thread::sleep(Duration::from_micros(500));
        }
    });

    // Main thread also doing updates
    for _ in 0..500 {
        pb.inc();
        thread::sleep(Duration::from_millis(1));
    }

    handle.join().unwrap();

    // Test 4: Mixed operations
    pb.log("Starting test 4: Mixed operations");
    for i in 0..20 {
        if i % 3 == 0 {
            pb.inc_many(10);
        } else {
            pb.inc();
        }

        if i % 7 == 0 {
            pb.log(&format!("Checkpoint at iteration {}", i));
        }

        thread::sleep(Duration::from_millis(100));
    }

    pb.log("All tests completed!");

    // Let it run a bit more to see final stats
    thread::sleep(Duration::from_secs(1));

    println!("\nTest finished. The progress bar will continue running in the background.");
    println!("Press Ctrl+C to exit.");

    // Keep the main thread alive to see the progress bar
    thread::sleep(Duration::from_secs(2));
}
