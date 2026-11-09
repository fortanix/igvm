// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! Intel TDX launch measurement (MRTD) calculation.
//!
//! Computes the MRTD by iterating IGVM directive headers and hashing
//! `MEM.PAGE.ADD` and `MR.EXTEND` operations, matching the TDX module's
//! measurement algorithm.

use super::MeasurementError;
use super::SHA_384_OUTPUT_SIZE;
use crate::page_table::X64_LARGE_PAGE_SIZE;
use crate::IgvmDirectiveHeader;
use igvm_defs::PAGE_SIZE_4K;
use sha2::Digest;
use sha2::Sha384;
use std::collections::HashMap;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

const PAGE_SIZE_4K_USIZE: usize = PAGE_SIZE_4K as usize;
const PAGE_SIZE_2M_USIZE: usize = X64_LARGE_PAGE_SIZE as usize;
const TDX_EXTEND_CHUNK_SIZE: usize = 256;

/// Structure for measuring a page addition to the TD.
#[repr(C)]
#[derive(IntoBytes, Immutable, KnownLayout, FromBytes)]
struct TdxPageAdd {
    /// `MEM.PAGE.ADD` operation identifier.
    operation: [u8; 16],
    /// Guest physical address (page-aligned).
    gpa: u64,
    /// Reserved, must be zero.
    mbz: [u8; 104],
}

/// Structure for measuring a 256-byte data chunk.
#[repr(C)]
#[derive(IntoBytes, Immutable, KnownLayout, FromBytes)]
struct TdxMrExtend {
    /// `MR.EXTEND` operation identifier.
    operation: [u8; 16],
    /// Guest physical address (256-byte aligned).
    gpa: u64,
    /// Reserved, must be zero.
    mbz: [u8; 104],
    /// 256 bytes of data to measure.
    data: [u8; TDX_EXTEND_CHUNK_SIZE],
}

/// Compute the TDX MRTD from IGVM directive headers.
///
/// Iterates all directive headers for the given compatibility mask,
/// computing the running SHA-384 hash of `MEM.PAGE.ADD` and `MR.EXTEND`
/// operations that the TDX module would perform during `TDH.MR.FINALIZE`.
pub fn generate_tdx_measurement(
    directive_headers: &[IgvmDirectiveHeader],
    compatibility_mask: u32,
) -> Result<[u8; SHA_384_OUTPUT_SIZE], MeasurementError> {
    let mut parameter_area_table = HashMap::new();
    let mut padding_vec_4k = vec![0u8; PAGE_SIZE_4K_USIZE];
    let mut padding_vec_2m = vec![0u8; PAGE_SIZE_2M_USIZE];
    let mut hasher = Sha384::new();

    let mut measure_page =
        |gpa: u64, page_data: Option<&[u8]>, large_page: bool| -> Result<(), MeasurementError> {
            // Measure the page being added.
            let page_add = TdxPageAdd {
                operation: *b"MEM.PAGE.ADD\0\0\0\0",
                gpa,
                mbz: [0; 104],
            };
            hasher.update(page_add.as_bytes());

            // The page size, offset limit, and padding vec used will depend on the large page flag
            let page_size = if large_page {
                PAGE_SIZE_2M_USIZE
            } else {
                PAGE_SIZE_4K_USIZE
            };
            // Avoid casting usize as u64 for use
            let offset_limit = if large_page {
                X64_LARGE_PAGE_SIZE
            } else {
                PAGE_SIZE_4K
            };
            let padding_vec = if large_page {
                &mut padding_vec_2m
            } else {
                &mut padding_vec_4k
            };

            // Possibly measure the page contents in 256-byte chunks.
            if let Some(data) = page_data {
                let data = match data.len() {
                    0 => None,
                    len if len == page_size => Some(data),
                    len if len < page_size => {
                        padding_vec.fill(0);
                        padding_vec[..len].copy_from_slice(data);
                        Some(padding_vec.as_slice())
                    }
                    len => return Err(MeasurementError::UnsupportedPageSize(len)),
                };

                for offset in (0..offset_limit as u64).step_by(TDX_EXTEND_CHUNK_SIZE) {
                    let mut mr_extend = TdxMrExtend {
                        operation: *b"MR.EXTEND\0\0\0\0\0\0\0",
                        gpa: gpa + offset,
                        mbz: [0; 104],
                        data: [0; TDX_EXTEND_CHUNK_SIZE],
                    };

                    if let Some(data) = data {
                        mr_extend.data.copy_from_slice(
                            &data[offset as usize..offset as usize + TDX_EXTEND_CHUNK_SIZE],
                        );
                    }
                    hasher.update(mr_extend.as_bytes());
                }
            }
            Ok(())
        };

    for header in directive_headers {
        if header
            .compatibility_mask()
            .map(|mask| mask & compatibility_mask != compatibility_mask)
            .unwrap_or(false)
        {
            continue;
        }

        match header {
            IgvmDirectiveHeader::ParameterArea {
                number_of_bytes,
                parameter_area_index,
                initial_data: _,
            } => {
                parameter_area_table.insert(*parameter_area_index, *number_of_bytes);
            }
            IgvmDirectiveHeader::PageData {
                gpa, flags, data, ..
            } => {
                if flags.shared() {
                    continue;
                }

                let data = if flags.unmeasured() {
                    None
                } else {
                    Some(data.as_slice())
                };

                measure_page(*gpa, data, flags.is_2mb_page())?;
            }
            IgvmDirectiveHeader::ParameterInsert(param) => {
                let parameter_area_size = parameter_area_table
                    .get(&param.parameter_area_index)
                    .ok_or(MeasurementError::InvalidParameterAreaIndex(
                        param.parameter_area_index,
                    ))?;

                for gpa in (param.gpa..param.gpa + *parameter_area_size).step_by(PAGE_SIZE_4K_USIZE)
                {
                    measure_page(gpa, None, false)?;
                }
            }
            _ => {}
        }
    }

    Ok(hasher.finalize().into())
}
