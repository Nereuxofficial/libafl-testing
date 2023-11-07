extern crate libafl;
extern crate libafl_bolts;

use libafl::prelude::tui::ui::TuiUI;
use libafl::prelude::tui::TuiMonitor;
use libafl::prelude::{
    havoc_mutations, CrashFeedback, InMemoryCorpus, InProcessExecutor, MaxMapFeedback,
    OnDiskCorpus, RandPrintablesGenerator, SimpleEventManager, SimpleMonitor, StdMapObserver,
    StdMutationalStage, StdScheduledMutator, StdState,
};
use libafl::schedulers::QueueScheduler;
use libafl::{
    executors::ExitKind,
    inputs::{BytesInput, HasTargetBytes},
    Fuzzer, StdFuzzer,
};
use libafl_bolts::prelude::*;
use libafl_bolts::{current_nanos, AsSlice};
use std::path::PathBuf;

// Coverage map with explicit assignments due to the lack of instrumentation
static mut SIGNALS: [u8; 16] = [0; 16];
static mut SIGNALS_PTR: *mut u8 = unsafe { SIGNALS.as_mut_ptr() };

fn signals_set(idx: usize) {
    unsafe { SIGNALS[idx] = 1 };
}

fn main() {
    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        signals_set(0); // set SIGNALS[0]
        if !buf.is_empty() && buf[0] == b'a' {
            signals_set(1); // set SIGNALS[1]
            if buf.len() > 1 && buf[1] == b'b' {
                signals_set(2); // set SIGNALS[2]
                if buf.len() > 2 && buf[2] == b'c' {
                    signals_set(3); // set SIGNALS[3]
                    if buf.ends_with(b"cba") {
                        panic!("=)");
                    }
                }
            }
        }
        ExitKind::Ok
    };

    // To test the panic:
    let input = BytesInput::new(Vec::from("abc"));
    #[cfg(feature = "panic")]
    harness(&input);
    let observer = unsafe { StdMapObserver::from_mut_ptr("signals", SIGNALS_PTR, SIGNALS.len()) };

    let mut feedback = MaxMapFeedback::new(&observer);
    let mut objective = CrashFeedback::new();

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::new(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        &mut feedback,
        &mut objective,
    )
    .unwrap();

    // The Monitor trait defines how the fuzzer stats are displayed to the user
    let mon = TuiMonitor::new(TuiUI::new("libafl example".to_string(), true));

    // The event manager handles the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(mon);

    // A queue policy to get testcases from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Create the executor for an in-process function
    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor");

    // Generator of printable bytearrays of max size 32
    let mut generator = RandPrintablesGenerator::new(32);

    // Generate 8 initial inputs
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("Failed to generate the initial corpus");

    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .unwrap();
}
