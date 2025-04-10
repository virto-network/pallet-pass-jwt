// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: MIT-0

// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is furnished to do
// so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! Benchmarking for `pallet-example-basic`.

// Only enable this module for benchmarking.
#![cfg(feature = "runtime-benchmarks")]

use crate::*;
use frame_benchmarking::v2::*;
use frame_system::RawOrigin;

// To actually run this benchmark on pallet-example-basic, we need to put this pallet into the
//   runtime and compile it with `runtime-benchmarks` feature. The detail procedures are
//   documented at:
//   https://docs.substrate.io/reference/how-to-guides/weights/add-benchmarks/
//
// The auto-generated weight estimate of this pallet is copied over to the `weights.rs` file.
// The exact command of how the estimate generated is printed at the top of the file.

// Details on using the benchmarks macro can be seen at:
//   https://paritytech.github.io/substrate/master/frame_benchmarking/trait.Benchmarking.html#tymethod.benchmarks
#[benchmarks]
mod benchmarks {
    use super::*;

    // This will measure the execution time of `set_dummy`.
    #[benchmark]
    fn set_dummy_benchmark() {
        // This is the benchmark setup phase.
        // `set_dummy` is a constant time function, hence we hard-code some random value here.
        let value = 1000u32.into();
        #[extrinsic_call]
        set_dummy(RawOrigin::Root, value); // The execution phase is just running `set_dummy` extrinsic call

        // This is the optional benchmark verification phase, asserting certain states.
        assert_eq!(Dummy::<T>::get(), Some(value))
    }

    // An example method that returns a Result that can be called within a benchmark
    fn example_result_method() -> Result<(), BenchmarkError> {
        Ok(())
    }

    // This will measure the execution time of `accumulate_dummy`.
    // The benchmark execution phase is shorthanded. When the name of the benchmark case is the same
    // as the extrinsic call. `_(...)` is used to represent the extrinsic name.
    // The benchmark verification phase is omitted.
    #[benchmark]
    fn accumulate_dummy() -> Result<(), BenchmarkError> {
        let value = 1000u32.into();
        // The caller account is whitelisted for DB reads/write by the benchmarking macro.
        let caller: T::AccountId = whitelisted_caller();

        // an example of calling something result-based within a benchmark using the ? operator
        // this necessitates specifying the `Result<(), BenchmarkError>` return type
        example_result_method()?;

        // You can use `_` if the name of the Call matches the benchmark name.
        #[extrinsic_call]
        _(RawOrigin::Signed(caller), value);

        // need this to be compatible with the return type
        Ok(())
    }

    /// You can write helper functions in here since its a normal Rust module.
    fn setup_vector(len: u32) -> Vec<u32> {
        let mut vector = Vec::<u32>::new();
        for i in (0..len).rev() {
            vector.push(i);
        }
        vector
    }

    // This will measure the execution time of sorting a vector.
    //
    // Define `x` as a linear component with range `[0, =10_000]`. This means that the benchmarking
    // will assume that the weight grows at a linear rate depending on `x`.
    #[benchmark]
    fn sort_vector(x: Linear<0, 10_000>) {
        let mut vector = setup_vector(x);

        // The benchmark execution phase could also be a closure with custom code:
        #[block]
        {
            vector.sort();
        }

        // Check that it was sorted correctly. This will not be benchmarked and is just for
        // verification.
        vector.windows(2).for_each(|w| assert!(w[0] <= w[1]));
    }

    // This line generates test cases for benchmarking, and could be run by:
    //   `cargo test -p pallet-example-basic --all-features`, you will see one line per case:
    //   `test benchmarking::bench_sort_vector ... ok`
    //   `test benchmarking::bench_accumulate_dummy ... ok`
    //   `test benchmarking::bench_set_dummy_benchmark ... ok` in the result.
    //
    // The line generates three steps per benchmark, with repeat=1 and the three steps are
    //   [low, mid, high] of the range.
    impl_benchmark_test_suite!(Pallet, crate::tests::new_test_ext(), crate::tests::Test);
}
