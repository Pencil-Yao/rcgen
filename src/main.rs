extern crate rcgen;

use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, SanType, date_time_ymd, PKCS_ECDSA_SM2P256_SM3, KeyIdMethod, ExtendedKeyUsagePurpose, CustomExtension, IsCa, BasicConstraints};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let params = modify_ca_param("0x37d1c7449bfe76fe9c445e626da06265e9377601");
	let server_params1 = modify_server_param("0x31a47f66dca6cb6094892f0d5933bcbdcede4d27");
	let server_params2 = modify_server_param("0x31a47f66dca6cb6094892f0d5933bcbdcede4d27");

	let cert = Certificate::from_params(params)?;
	let server_cert1 = Certificate::from_params(server_params1)?;
	let server_cert2 = Certificate::from_params(server_params2)?;
	std::fs::create_dir_all("certs/")?;
	fs::write("certs/ca.crt", &cert.serialize_pem().unwrap().as_bytes())?;
	fs::write("certs/server0.crt", &server_cert1.serialize_pem_with_signer(&cert).unwrap().as_bytes())?;
	fs::write("certs/server1.crt", &server_cert2.serialize_pem_with_signer(&cert).unwrap().as_bytes())?;
	fs::write("certs/ca.pk8", &cert.serialize_private_key_pem().as_bytes())?;
	fs::write("certs/server0.pk8", &server_cert1.serialize_private_key_pem().as_bytes())?;
	fs::write("certs/server1.pk8", &server_cert2.serialize_private_key_pem().as_bytes())?;
	Ok(())
}

fn modify_ca_param(ca: &str) -> CertificateParams {
	let mut params :CertificateParams = Default::default();

	params.not_before = date_time_ymd(1975, 01, 01);
	params.not_after = date_time_ymd(4096, 01, 01);
	params.distinguished_name = DistinguishedName::new();
	params.distinguished_name.push(DnType::CountryName, "CN");
	params.distinguished_name.push(DnType::StateOrProvinceName, "ZJ");
	params.distinguished_name.push(DnType::LocalityName, "HZ");
	params.distinguished_name.push(DnType::OrganizationName, "CITA");
	params.distinguished_name.push(DnType::OrganizationalUnitName, "BlockchainDevelop");
	params.distinguished_name.push(DnType::CommonName, ca);
	params.subject_alt_names = vec![SanType::DnsName(ca.to_string()),
									SanType::DnsName(ca.to_string())];
	params.alg = &PKCS_ECDSA_SM2P256_SM3;
	params.key_identifier_method = KeyIdMethod::SM3;
	let mut ex_vec = Vec::new();
	ex_vec.push(ExtendedKeyUsagePurpose::ClientAuth);
	ex_vec.push(ExtendedKeyUsagePurpose::ServerAuth);
	params.extended_key_usages.append(&mut ex_vec);
	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	params.use_authority_key_identifier_extension = true;
	// let mut cuex = CustomExtension::from_oid_content(&[2, 5, 29, 15], vec![0b0000_0001]);
	// cuex.set_criticality(true);
	// params.custom_extensions.push(cuex);
	params
}

fn modify_server_param(server: &str) -> CertificateParams {
	let mut params :CertificateParams = Default::default();

	params.not_before = date_time_ymd(1975, 01, 01);
	params.not_after = date_time_ymd(4096, 01, 01);
	params.distinguished_name = DistinguishedName::new();
	params.distinguished_name.push(DnType::CountryName, "CN");
	params.distinguished_name.push(DnType::StateOrProvinceName, "ZJ");
	params.distinguished_name.push(DnType::LocalityName, "HZ");
	params.distinguished_name.push(DnType::OrganizationName, "CITA");
	params.distinguished_name.push(DnType::OrganizationalUnitName, "BlockchainDevelop");
	params.distinguished_name.push(DnType::CommonName, server);
	params.subject_alt_names = vec![SanType::DnsName(server.to_string()),
									SanType::DnsName(server.to_string())];
	params.alg = &PKCS_ECDSA_SM2P256_SM3;
	params.key_identifier_method = KeyIdMethod::SM3;
	let mut ex_vec = Vec::new();
	ex_vec.push(ExtendedKeyUsagePurpose::ClientAuth);
	ex_vec.push(ExtendedKeyUsagePurpose::ServerAuth);
	params.extended_key_usages.append(&mut ex_vec);
	params.is_ca = IsCa::NormalCert;
	params.use_authority_key_identifier_extension = true;
	// let mut cuex = CustomExtension::from_oid_content(&[2, 5, 29, 15], vec![0b1000_0000]);
	// cuex.set_criticality(true);
	// params.custom_extensions.push(cuex);
	params
}
