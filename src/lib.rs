// SPDX-License-Identifier: MIT OR Apache-2.0

#![doc = include_str!("../README.md")]
#![cfg(not(test))]
#![deny(clippy::all)]

#[macro_use]
extern crate log;

extern crate core;
extern crate crc;
extern crate hex;
extern crate zerocopy;

mod consts;
mod frame;
mod port;
mod proto;

pub mod recv;
pub mod send;
