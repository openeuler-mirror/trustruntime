//! 业务错误码映射模块
//!
//! 职责：
//! - 定义统一的业务错误类型（BusinessError）
//! - 将签名/验签错误映射为标准结果码
//! - 解析OpenSSL错误字符串并分类映射
//!
//! 架构决策：
//! - 统一结果码编码（ADR-0001: Unified Result Code Encoding）
//! - 错误码范围：0-11，便于vsock消息传递和日志分析
//!
//! 编码规则：
//! - result=0：成功
//! - result=1/2：验签身份判定（SameNode、OtherNode、IdentityConflict）
//!   注意：result=1/2为验签通过的合法结果，不表示失败
//! - result=3-6：验签失败
//!   - result=3：证书链无效（CertificateChainInvalid）
//!   - result=4：CRL吊销（CertificateRevoked）
//!   - result=5：签名不匹配（SignatureMismatch）
//!   - result=6：格式错误（FormatError）
//! - result=7-9：签名失败
//!   - result=7：证书加载失败（CertificateLoadFailed）
//!   - result=8：私钥不可用（PrivateKeyUnavailable）
//!   - result=9：签名算法错误（SigningAlgorithmError）
//! - result=10-11：其他错误
//!   - result=10：JSON解析错误（JsonParseError）
//!   - result=11：Base64解码错误（Base64DecodeError）
//!
//! 依赖：
//! - sign模块：SignError（签名错误类型）
//! - verify模块：VerifyError（验签错误类型）
//! - openssl库：ErrorStack（OpenSSL错误栈）

use crate::sign::SignError;
use crate::verify::VerifyError;
use openssl::error::ErrorStack;

/// 业务错误枚举
///
/// 定义统一的业务错误类型，用于映射为标准结果码。
/// 每个错误类型对应一个固定的结果码（详见ADR-0001）。
///
/// 设计原则：
/// - 错误码语义明确，便于排查问题
/// - 错误码分类清晰（验签失败3-6、签名失败7-9、其他10-11）
/// - 支持OpenSSL错误的字符串匹配映射
///
/// 映射规则：
/// | 错误类型                  | 结果码 | 说明                     |
/// |---------------------------|--------|--------------------------|
/// | CertificateChainInvalid   | 3      | 证书链验证失败           |
/// | CertificateRevoked        | 4      | 证书被CRL吊销            |
/// | SignatureMismatch         | 5      | 签名不匹配               |
/// | FormatError               | 6      | CMS数据格式错误          |
/// | CertificateLoadFailed     | 7      | 证书加载失败             |
/// | PrivateKeyUnavailable     | 8      | 私钥不可用               |
/// | SigningAlgorithmError     | 9      | 签名算法错误             |
/// | JsonParseError            | 10     | JSON解析错误             |
/// | Base64DecodeError         | 11     | Base64解码错误           |
/// | Other(code)               | code   | 其他错误（透传错误码）   |
#[derive(Debug, PartialEq)]
pub(crate) enum BusinessError {
    /// 证书链无效（result=3）
    ///
    /// 场景：
    /// - 签名方证书非CA签发
    /// - CA证书缺失或不可信
    /// - 证书链不完整
    CertificateChainInvalid,

    /// 证书被CRL吊销（result=4）
    ///
    /// 场景：
    /// - 签名方证书在CRL吊销列表中
    /// - 证书已被管理员主动吊销
    CertificateRevoked,

    /// 签名不匹配（result=5）
    ///
    /// 场景：
    /// - 数据被篡改
    /// - 签名无效
    /// - 公钥不匹配
    SignatureMismatch,

    /// 格式错误（result=6）
    ///
    /// 场景：
    /// - CMS数据格式无效
    /// - DER编码解析失败
    /// - 数据结构不符合预期
    FormatError,

    /// 证书加载失败（result=7）
    ///
    /// 场景：
    /// - 证书文件不存在
    /// - 证书文件权限不足
    /// - 证书格式不支持
    CertificateLoadFailed,

    /// 私钥不可用（result=8）
    ///
    /// 场景：
    /// - 私钥文件不存在
    /// - 私钥权限不足
    /// - 私钥格式错误
    /// - 私钥密码错误
    PrivateKeyUnavailable,

    /// 签名算法错误（result=9）
    ///
    /// 场景：
    /// - 签名算法不支持
    /// - 算法参数错误
    SigningAlgorithmError,

    /// JSON解析错误（result=10）
    ///
    /// 场景：
    /// - 请求消息JSON格式错误
    /// - 响应消息JSON序列化失败
    JsonParseError,

    /// Base64解码错误（result=11）
    ///
    /// 场景：
    /// - 签名数据Base64解码失败
    /// - 证书ID Base64解码失败
    Base64DecodeError,

    /// 其他错误（透传错误码）
    ///
    /// 用于未分类的OpenSSL错误或其他内部错误。
    /// 错误码由调用方指定。
    Other(u32),
}

impl BusinessError {
    /// 转换为标准结果码
    ///
    /// 将业务错误映射为统一的结果码（详见ADR-0001）。
    /// 结果码用于vsock消息响应，便于客户端判断错误类型。
    ///
    /// 编码规则：
    /// - 成功：result=0（验签通过，返回身份判定结果1/2）
    /// - 验签失败：result=3-6
    /// - 签名失败：result=7-9
    /// - 其他错误：result=10-11
    ///
    /// # Returns
    /// 标准结果码（u32）
    ///
    /// # 结果码映射表
    /// | 错误类型 | 结果码 |
    /// |----------|--------|
    /// | CertificateChainInvalid | 3 |
    /// | CertificateRevoked | 4 |
    /// | SignatureMismatch | 5 |
    /// | FormatError | 6 |
    /// | CertificateLoadFailed | 7 |
    /// | PrivateKeyUnavailable | 8 |
    /// | SigningAlgorithmError | 9 |
    /// | JsonParseError | 10 |
    /// | Base64DecodeError | 11 |
    pub(crate) fn to_result_code(&self) -> u32 {
        match self {
            BusinessError::CertificateChainInvalid => 3,
            BusinessError::CertificateRevoked => 4,
            BusinessError::SignatureMismatch => 5,
            BusinessError::FormatError => 6,
            BusinessError::CertificateLoadFailed => 7,
            BusinessError::PrivateKeyUnavailable => 8,
            BusinessError::SigningAlgorithmError => 9,
            BusinessError::JsonParseError => 10,
            BusinessError::Base64DecodeError => 11,
            BusinessError::Other(code) => *code,
        }
    }
}

/// 映射签名错误为业务错误
///
/// 将SignError转换为BusinessError，用于生成标准结果码。
///
/// 映射逻辑：
/// - SignError::OpenSslError → 通过map_openssl_error_string解析错误字符串
///   - "certificate verify failed" / "unable to get issuer certificate" → CertificateChainInvalid
///   - "certificate revoked" → CertificateRevoked
///   - "signature" + "verification" → SignatureMismatch
///   - "decode" / "parse" → FormatError
///   - "no such file" / "permission denied" → CertificateLoadFailed
///   - "private key" → PrivateKeyUnavailable
///   - "algorithm" / "unsupported" → SigningAlgorithmError
///   - 其他 → Other(10)
///
/// # Arguments
/// * `err` - 签名错误引用
///
/// # Returns
/// 对应的BusinessError实例
pub(crate) fn map_sign_error(err: &SignError) -> BusinessError {
    match err {
        SignError::OpenSslError(e) => map_openssl_error_string(&e.to_string()),
    }
}

/// 映射验签错误为业务错误
///
/// 将VerifyError转换为BusinessError，用于生成标准结果码。
///
/// 映射逻辑：
/// - VerifyError::OpenSslError → 通过map_openssl_error_string解析错误字符串
/// - VerifyError::CertificateChainInvalid → CertificateChainInvalid（result=3）
/// - VerifyError::CertificateRevoked → CertificateRevoked（result=4）
/// - VerifyError::SignatureMismatch → SignatureMismatch（result=5）
/// - VerifyError::FormatError → FormatError（result=6）
///
/// 注意：VerifyError已在verify模块完成错误分类，此处仅做类型转换。
/// OpenSSL错误的详细解析在map_openssl_error_string中完成。
///
/// # Arguments
/// * `err` - 验签错误引用
///
/// # Returns
/// 对应的BusinessError实例
pub(crate) fn map_verify_error(err: &VerifyError) -> BusinessError {
    match err {
        VerifyError::OpenSslError(s) => map_openssl_error_string(s),
        VerifyError::CertificateChainInvalid => BusinessError::CertificateChainInvalid,
        VerifyError::CertificateRevoked => BusinessError::CertificateRevoked,
        VerifyError::SignatureMismatch => BusinessError::SignatureMismatch,
        VerifyError::FormatError => BusinessError::FormatError,
    }
}

/// 映射OpenSSL错误栈为业务错误
///
/// 将OpenSSL ErrorStack转换为BusinessError。
/// 主要用于签名错误映射（SignError::OpenSslError）。
///
/// 映射逻辑：
/// 1. 将ErrorStack转换为字符串
/// 2. 调用map_openssl_error_string解析错误类型
///
/// # Arguments
/// * `error` - OpenSSL错误栈引用
///
/// # Returns
/// 对应的BusinessError实例
#[allow(dead_code)]
pub(crate) fn map_openssl_error(error: &ErrorStack) -> BusinessError {
    map_openssl_error_string(&error.to_string())
}

/// 映射OpenSSL错误字符串为业务错误
///
/// 通过字符串匹配将OpenSSL错误分类为BusinessError。
/// 错误字符串为小写匹配，不区分大小写。
///
/// 匹配规则（按优先级顺序）：
/// 1. "certificate verify failed" / "unable to get issuer certificate" → CertificateChainInvalid
///    - 证书链验证失败
///    - CA证书缺失或不可信
///
/// 2. "certificate revoked" → CertificateRevoked
///    - 证书被CRL吊销
///
/// 3. "signature" && "verification" → SignatureMismatch
///    - 签名验证失败
///    - 数据被篡改或签名无效
///
/// 4. "decode" / "parse" → FormatError
///    - 数据格式错误
///    - DER/PEM编码解析失败
///
/// 5. "no such file" / "permission denied" → CertificateLoadFailed
///    - 文件不存在
///    - 权限不足
///
/// 6. "private key" → PrivateKeyUnavailable
///    - 私钥相关错误
///
/// 7. "algorithm" / "unsupported" → SigningAlgorithmError
///    - 算法不支持
///    - 算法参数错误
///
/// 8. 其他 → Other(10)
///    - 未分类错误，透传错误码10
///
/// # Arguments
/// * `error_string` - OpenSSL错误字符串
///
/// # Returns
/// 对应的BusinessError实例
fn map_openssl_error_string(error_string: &str) -> BusinessError {
    let lower = error_string.to_lowercase();

    if lower.contains("certificate verify failed")
        || lower.contains("unable to get issuer certificate")
    {
        BusinessError::CertificateChainInvalid
    } else if lower.contains("certificate revoked") {
        BusinessError::CertificateRevoked
    } else if lower.contains("signature") && lower.contains("verification") {
        BusinessError::SignatureMismatch
    } else if lower.contains("decode") || lower.contains("parse") {
        BusinessError::FormatError
    } else if lower.contains("no such file") || lower.contains("permission denied") {
        BusinessError::CertificateLoadFailed
    } else if lower.contains("private key") {
        BusinessError::PrivateKeyUnavailable
    } else if lower.contains("algorithm") || lower.contains("unsupported") {
        BusinessError::SigningAlgorithmError
    } else {
        BusinessError::Other(10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试：BusinessError转换为正确的结果码
    ///
    /// 场景：验证所有BusinessError类型映射到正确的结果码
    /// 预期：
    /// - CertificateChainInvalid → 3
    /// - CertificateRevoked → 4
    /// - SignatureMismatch → 5
    /// - FormatError → 6
    /// - CertificateLoadFailed → 7
    /// - PrivateKeyUnavailable → 8
    /// - SigningAlgorithmError → 9
    /// - Other(10) → 10
    /// - Other(15) → 15（透传）
    #[test]
    fn business_error_maps_to_correct_result_code() {
        assert_eq!(BusinessError::CertificateChainInvalid.to_result_code(), 3);
        assert_eq!(BusinessError::CertificateRevoked.to_result_code(), 4);
        assert_eq!(BusinessError::SignatureMismatch.to_result_code(), 5);
        assert_eq!(BusinessError::FormatError.to_result_code(), 6);
        assert_eq!(BusinessError::CertificateLoadFailed.to_result_code(), 7);
        assert_eq!(BusinessError::PrivateKeyUnavailable.to_result_code(), 8);
        assert_eq!(BusinessError::SigningAlgorithmError.to_result_code(), 9);
        assert_eq!(BusinessError::Other(10).to_result_code(), 10);
        assert_eq!(BusinessError::Other(15).to_result_code(), 15);
    }

    /// 测试：map_sign_error映射OpenSSL错误
    ///
    /// 场景：签名过程中发生OpenSSL错误
    /// 预期：返回BusinessError::Other(10)（无法匹配具体错误）
    #[test]
    fn map_sign_error_maps_openssl_error() {
        let error = openssl::error::ErrorStack::get();
        let result = map_sign_error(&SignError::OpenSslError(error));
        assert_eq!(result, BusinessError::Other(10));
    }

    /// 测试：map_verify_error映射VerifyError类型
    ///
    /// 场景：验签过程中的各种错误类型
    /// 预期：
    /// - CertificateChainInvalid → BusinessError::CertificateChainInvalid
    /// - CertificateRevoked → BusinessError::CertificateRevoked
    /// - SignatureMismatch → BusinessError::SignatureMismatch
    /// - FormatError → BusinessError::FormatError
    #[test]
    fn map_verify_error_maps_verify_error_types() {
        assert_eq!(
            map_verify_error(&VerifyError::CertificateChainInvalid),
            BusinessError::CertificateChainInvalid
        );
        assert_eq!(
            map_verify_error(&VerifyError::CertificateRevoked),
            BusinessError::CertificateRevoked
        );
        assert_eq!(
            map_verify_error(&VerifyError::SignatureMismatch),
            BusinessError::SignatureMismatch
        );
        assert_eq!(
            map_verify_error(&VerifyError::FormatError),
            BusinessError::FormatError
        );
    }

    /// 测试：map_verify_error映射OpenSSL错误
    ///
    /// 场景：验签过程中发生OpenSSL错误（未知错误）
    /// 预期：返回BusinessError::Other(10)
    #[test]
    fn map_verify_error_maps_openssl_error() {
        let error_string = "some openssl error".to_string();
        let result = map_verify_error(&VerifyError::OpenSslError(error_string));
        assert_eq!(result, BusinessError::Other(10));
    }

    /// 测试：map_openssl_error处理空错误栈
    ///
    /// 场景：OpenSSL错误栈为空（无具体错误）
    /// 预期：返回BusinessError::Other(10)
    #[test]
    fn openssl_error_with_certificate_verify_failed_maps_to_chain_invalid() {
        let error = openssl::error::ErrorStack::get();
        let mapped = map_openssl_error(&error);
        assert_eq!(mapped, BusinessError::Other(10));
    }
}