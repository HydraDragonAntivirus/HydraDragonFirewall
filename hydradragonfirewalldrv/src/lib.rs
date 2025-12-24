#![no_std]
#![no_main]

extern crate alloc;
extern crate wdk_panic;

use core::ffi::c_void;
use core::ptr::null_mut;
use core::slice;
use core::str;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::string::ToString;
use wdk::*;
use wdk_alloc::WdkAllocator;
use wdk_sys::ntddk::*;
use wdk_sys::*;
