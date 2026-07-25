/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

use openssl::hash::MessageDigest;
use openssl::x509::X509;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn get_subject_key_id(cert: &X509) -> Vec<u8> {
    let pubkey_der = cert
        .public_key()
        .expect("Failed to get public key")
        .public_key_to_der()
        .expect("Failed to DER encode public key");
    openssl::hash::hash(MessageDigest::sha1(), &pubkey_der)
        .expect("Failed to hash public key")
        .to_vec()
}

pub fn rand_serial() -> u32 {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    (duration.as_secs() as u32) ^ (duration.subsec_nanos())
}
