﻿namespace RS.Schannel.Manager.API;

internal class AlgorithmObjectIdentifiers
{
    // Following are the definitions of various algorithm object identifiers
    // RSA
    public const string szOID_RSA = "1.2.840.113549";
    public const string szOID_PKCS = "1.2.840.113549.1";
    public const string szOID_RSA_HASH = "1.2.840.113549.2";
    public const string szOID_RSA_ENCRYPT = "1.2.840.113549.3";

    public const string szOID_PKCS_1 = "1.2.840.113549.1.1";
    public const string szOID_PKCS_2 = "1.2.840.113549.1.2";
    public const string szOID_PKCS_3 = "1.2.840.113549.1.3";
    public const string szOID_PKCS_4 = "1.2.840.113549.1.4";
    public const string szOID_PKCS_5 = "1.2.840.113549.1.5";
    public const string szOID_PKCS_6 = "1.2.840.113549.1.6";
    public const string szOID_PKCS_7 = "1.2.840.113549.1.7";
    public const string szOID_PKCS_8 = "1.2.840.113549.1.8";
    public const string szOID_PKCS_9 = "1.2.840.113549.1.9";
    public const string szOID_PKCS_10 = "1.2.840.113549.1.10";
    public const string szOID_PKCS_12 = "1.2.840.113549.1.12";

    public const string szOID_RSA_RSA = "1.2.840.113549.1.1.1";
    public const string szOID_RSA_MD2RSA = "1.2.840.113549.1.1.2";
    public const string szOID_RSA_MD4RSA = "1.2.840.113549.1.1.3";
    public const string szOID_RSA_MD5RSA = "1.2.840.113549.1.1.4";
    public const string szOID_RSA_SHA1RSA = "1.2.840.113549.1.1.5";
    public const string szOID_RSA_SETOAEP_RSA = "1.2.840.113549.1.1.6";

    public const string szOID_RSAES_OAEP = "1.2.840.113549.1.1.7";
    public const string szOID_RSA_MGF1 = "1.2.840.113549.1.1.8";
    public const string szOID_RSA_PSPECIFIED = "1.2.840.113549.1.1.9";
    public const string szOID_RSA_SSA_PSS = "1.2.840.113549.1.1.10";
    public const string szOID_RSA_SHA256RSA = "1.2.840.113549.1.1.11";
    public const string szOID_RSA_SHA384RSA = "1.2.840.113549.1.1.12";
    public const string szOID_RSA_SHA512RSA = "1.2.840.113549.1.1.13";

    public const string szOID_RSA_DH = "1.2.840.113549.1.3.1";

    public const string szOID_RSA_data = "1.2.840.113549.1.7.1";
    public const string szOID_RSA_signedData = "1.2.840.113549.1.7.2";
    public const string szOID_RSA_envelopedData = "1.2.840.113549.1.7.3";
    public const string szOID_RSA_signEnvData = "1.2.840.113549.1.7.4";
    public const string szOID_RSA_digestedData = "1.2.840.113549.1.7.5";
    public const string szOID_RSA_hashedData = "1.2.840.113549.1.7.5";
    public const string szOID_RSA_encryptedData = "1.2.840.113549.1.7.6";

    public const string szOID_RSA_emailAddr = "1.2.840.113549.1.9.1";
    public const string szOID_RSA_unstructName = "1.2.840.113549.1.9.2";
    public const string szOID_RSA_contentType = "1.2.840.113549.1.9.3";
    public const string szOID_RSA_messageDigest = "1.2.840.113549.1.9.4";
    public const string szOID_RSA_signingTime = "1.2.840.113549.1.9.5";
    public const string szOID_RSA_counterSign = "1.2.840.113549.1.9.6";
    public const string szOID_RSA_challengePwd = "1.2.840.113549.1.9.7";
    public const string szOID_RSA_unstructAddr = "1.2.840.113549.1.9.8";
    public const string szOID_RSA_extCertAttrs = "1.2.840.113549.1.9.9";
    public const string szOID_RSA_certExtensions = "1.2.840.113549.1.9.14";
    public const string szOID_RSA_SMIMECapabilities = "1.2.840.113549.1.9.15";
    public const string szOID_RSA_preferSignedData = "1.2.840.113549.1.9.15.1";

    public const string szOID_TIMESTAMP_TOKEN = "1.2.840.113549.1.9.16.1.4";
    public const string szOID_RFC3161_counterSign = "1.3.6.1.4.1.311.3.3.1";

    public const string szOID_RSA_SMIMEalg = "1.2.840.113549.1.9.16.3";
    public const string szOID_RSA_SMIMEalgESDH = "1.2.840.113549.1.9.16.3.5";
    public const string szOID_RSA_SMIMEalgCMS3DESwrap = "1.2.840.113549.1.9.16.3.6";
    public const string szOID_RSA_SMIMEalgCMSRC2wrap = "1.2.840.113549.1.9.16.3.7";

    public const string szOID_RSA_MD2 = "1.2.840.113549.2.2";
    public const string szOID_RSA_MD4 = "1.2.840.113549.2.4";
    public const string szOID_RSA_MD5 = "1.2.840.113549.2.5";

    public const string szOID_RSA_RC2CBC = "1.2.840.113549.3.2";
    public const string szOID_RSA_RC4 = "1.2.840.113549.3.4";
    public const string szOID_RSA_DES_EDE3_CBC = "1.2.840.113549.3.7";
    public const string szOID_RSA_RC5_CBCPad = "1.2.840.113549.3.9";

    public const string szOID_ANSI_X942 = "1.2.840.10046";
    public const string szOID_ANSI_X942_DH = "1.2.840.10046.2.1";

    public const string szOID_X957 = "1.2.840.10040";
    public const string szOID_X957_DSA = "1.2.840.10040.4.1";
    public const string szOID_X957_SHA1DSA = "1.2.840.10040.4.3";

    // iso(1) member-body(2) us(840) 10045 keyType(2) unrestricted(1)
    public const string szOID_ECC_PUBLIC_KEY = "1.2.840.10045.2.1";

    // iso(1) member-body(2) us(840) 10045 curves(3) prime(1) 7
    public const string szOID_ECC_CURVE_P256 = "1.2.840.10045.3.1.7";

    // iso(1) identified-organization(3) certicom(132) curve(0) 34
    public const string szOID_ECC_CURVE_P384 = "1.3.132.0.34";

    // iso(1) identified-organization(3) certicom(132) curve(0) 35
    public const string szOID_ECC_CURVE_P521 = "1.3.132.0.35";

    //
    // Generic ECC Curve OIDS
    //
    public const string szOID_ECC_CURVE_BRAINPOOLP160R1 = "1.3.36.3.3.2.8.1.1.1";
    public const string szOID_ECC_CURVE_BRAINPOOLP160T1 = "1.3.36.3.3.2.8.1.1.2";
    public const string szOID_ECC_CURVE_BRAINPOOLP192R1 = "1.3.36.3.3.2.8.1.1.3";
    public const string szOID_ECC_CURVE_BRAINPOOLP192T1 = "1.3.36.3.3.2.8.1.1.4";
    public const string szOID_ECC_CURVE_BRAINPOOLP224R1 = "1.3.36.3.3.2.8.1.1.5";
    public const string szOID_ECC_CURVE_BRAINPOOLP224T1 = "1.3.36.3.3.2.8.1.1.6";
    public const string szOID_ECC_CURVE_BRAINPOOLP256R1 = "1.3.36.3.3.2.8.1.1.7";
    public const string szOID_ECC_CURVE_BRAINPOOLP256T1 = "1.3.36.3.3.2.8.1.1.8";
    public const string szOID_ECC_CURVE_BRAINPOOLP320R1 = "1.3.36.3.3.2.8.1.1.9";
    public const string szOID_ECC_CURVE_BRAINPOOLP320T1 = "1.3.36.3.3.2.8.1.1.10";
    public const string szOID_ECC_CURVE_BRAINPOOLP384R1 = "1.3.36.3.3.2.8.1.1.11";
    public const string szOID_ECC_CURVE_BRAINPOOLP384T1 = "1.3.36.3.3.2.8.1.1.12";
    public const string szOID_ECC_CURVE_BRAINPOOLP512R1 = "1.3.36.3.3.2.8.1.1.13";
    public const string szOID_ECC_CURVE_BRAINPOOLP512T1 = "1.3.36.3.3.2.8.1.1.14";

    public const string szOID_ECC_CURVE_EC192WAPI = "1.2.156.11235.1.1.2.1";
    public const string szOID_CN_ECDSA_SHA256 = "1.2.156.11235.1.1.1";

    public const string szOID_ECC_CURVE_NISTP192 = "1.2.840.10045.3.1.1";
    public const string szOID_ECC_CURVE_NISTP224 = "1.3.132.0.33";
    public const string szOID_ECC_CURVE_NISTP256 = szOID_ECC_CURVE_P256;
    public const string szOID_ECC_CURVE_NISTP384 = szOID_ECC_CURVE_P384;
    public const string szOID_ECC_CURVE_NISTP521 = szOID_ECC_CURVE_P521;

    public const string szOID_ECC_CURVE_SECP160K1 = "1.3.132.0.9";
    public const string szOID_ECC_CURVE_SECP160R1 = "1.3.132.0.8";
    public const string szOID_ECC_CURVE_SECP160R2 = "1.3.132.0.30";
    public const string szOID_ECC_CURVE_SECP192K1 = "1.3.132.0.31";
    public const string szOID_ECC_CURVE_SECP192R1 = szOID_ECC_CURVE_NISTP192;
    public const string szOID_ECC_CURVE_SECP224K1 = "1.3.132.0.32";
    public const string szOID_ECC_CURVE_SECP224R1 = szOID_ECC_CURVE_NISTP224;
    public const string szOID_ECC_CURVE_SECP256K1 = "1.3.132.0.10";
    public const string szOID_ECC_CURVE_SECP256R1 = szOID_ECC_CURVE_P256;
    public const string szOID_ECC_CURVE_SECP384R1 = szOID_ECC_CURVE_P384;
    public const string szOID_ECC_CURVE_SECP521R1 = szOID_ECC_CURVE_P521;

    public const string szOID_ECC_CURVE_WTLS7 = szOID_ECC_CURVE_SECP160R2;
    public const string szOID_ECC_CURVE_WTLS9 = "2.23.43.1.4.9";
    public const string szOID_ECC_CURVE_WTLS12 = szOID_ECC_CURVE_NISTP224;

    public const string szOID_ECC_CURVE_X962P192V1 = "1.2.840.10045.3.1.1";
    public const string szOID_ECC_CURVE_X962P192V2 = "1.2.840.10045.3.1.2";
    public const string szOID_ECC_CURVE_X962P192V3 = "1.2.840.10045.3.1.3";
    public const string szOID_ECC_CURVE_X962P239V1 = "1.2.840.10045.3.1.4";
    public const string szOID_ECC_CURVE_X962P239V2 = "1.2.840.10045.3.1.5";
    public const string szOID_ECC_CURVE_X962P239V3 = "1.2.840.10045.3.1.6";
    public const string szOID_ECC_CURVE_X962P256V1 = szOID_ECC_CURVE_P256;

    // iso(1) member-body(2) us(840) 10045 signatures(4) sha1(1)
    public const string szOID_ECDSA_SHA1 = "1.2.840.10045.4.1";

    // iso(1) member-body(2) us(840) 10045 signatures(4) specified(3)
    public const string szOID_ECDSA_SPECIFIED = "1.2.840.10045.4.3";

    // iso(1) member-body(2) us(840) 10045 signatures(4) specified(3) 2
    public const string szOID_ECDSA_SHA256 = "1.2.840.10045.4.3.2";

    // iso(1) member-body(2) us(840) 10045 signatures(4) specified(3) 3
    public const string szOID_ECDSA_SHA384 = "1.2.840.10045.4.3.3";

    // iso(1) member-body(2) us(840) 10045 signatures(4) specified(3) 4
    public const string szOID_ECDSA_SHA512 = "1.2.840.10045.4.3.4";

    // NIST AES CBC Algorithms
    // joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithms(4)  aesAlgs(1) }
    public const string szOID_NIST_AES128_CBC = "2.16.840.1.101.3.4.1.2";
    public const string szOID_NIST_AES192_CBC = "2.16.840.1.101.3.4.1.22";
    public const string szOID_NIST_AES256_CBC = "2.16.840.1.101.3.4.1.42";

    // For the above Algorithms, the AlgorithmIdentifier parameters must be
    // present and the parameters field MUST contain an AES-IV:
    //
    //  AES-IV ::= OCTET STRING (SIZE(16))

    // NIST AES WRAP Algorithms
    public const string szOID_NIST_AES128_WRAP = "2.16.840.1.101.3.4.1.5";
    public const string szOID_NIST_AES192_WRAP = "2.16.840.1.101.3.4.1.25";
    public const string szOID_NIST_AES256_WRAP = "2.16.840.1.101.3.4.1.45";

    //      x9-63-scheme OBJECT IDENTIFIER ::= { iso(1)
    //         identified-organization(3) tc68(133) country(16) x9(840)
    //         x9-63(63) schemes(0) }

    // ECDH single pass ephemeral-static KeyAgreement KeyEncryptionAlgorithm
    public const string szOID_DH_SINGLE_PASS_STDDH_SHA1_KDF = "1.3.133.16.840.63.0.2";
    public const string szOID_DH_SINGLE_PASS_STDDH_SHA256_KDF = "1.3.132.1.11.1";
    public const string szOID_DH_SINGLE_PASS_STDDH_SHA384_KDF = "1.3.132.1.11.2";

    // For the above KeyEncryptionAlgorithm the following wrap algorithms are
    // supported:
    //  szOID_RSA_SMIMEalgCMS3DESwrap
    //  szOID_RSA_SMIMEalgCMSRC2wrap
    //  szOID_NIST_AES128_WRAP
    //  szOID_NIST_AES192_WRAP
    //  szOID_NIST_AES256_WRAP

    // ITU-T UsefulDefinitions
    public const string szOID_DS = "2.5";
    public const string szOID_DSALG = "2.5.8";
    public const string szOID_DSALG_CRPT = "2.5.8.1";
    public const string szOID_DSALG_HASH = "2.5.8.2";
    public const string szOID_DSALG_SIGN = "2.5.8.3";
    public const string szOID_DSALG_RSA = "2.5.8.1.1";
    // NIST OSE Implementors' Workshop (OIW)
    // http://nemo.ncsl.nist.gov/oiw/agreements/stable/OSI/12s_9506.w51
    // http://nemo.ncsl.nist.gov/oiw/agreements/working/OSI/12w_9503.w51
    public const string szOID_OIW = "1.3.14";
    // NIST OSE Implementors' Workshop (OIW) Security SIG algorithm identifiers
    public const string szOID_OIWSEC = "1.3.14.3.2";
    public const string szOID_OIWSEC_md4RSA = "1.3.14.3.2.2";
    public const string szOID_OIWSEC_md5RSA = "1.3.14.3.2.3";
    public const string szOID_OIWSEC_md4RSA2 = "1.3.14.3.2.4";
    public const string szOID_OIWSEC_desECB = "1.3.14.3.2.6";
    public const string szOID_OIWSEC_desCBC = "1.3.14.3.2.7";
    public const string szOID_OIWSEC_desOFB = "1.3.14.3.2.8";
    public const string szOID_OIWSEC_desCFB = "1.3.14.3.2.9";
    public const string szOID_OIWSEC_desMAC = "1.3.14.3.2.10";
    public const string szOID_OIWSEC_rsaSign = "1.3.14.3.2.11";
    public const string szOID_OIWSEC_dsa = "1.3.14.3.2.12";
    public const string szOID_OIWSEC_shaDSA = "1.3.14.3.2.13";
    public const string szOID_OIWSEC_mdc2RSA = "1.3.14.3.2.14";
    public const string szOID_OIWSEC_shaRSA = "1.3.14.3.2.15";
    public const string szOID_OIWSEC_dhCommMod = "1.3.14.3.2.16";
    public const string szOID_OIWSEC_desEDE = "1.3.14.3.2.17";
    public const string szOID_OIWSEC_sha = "1.3.14.3.2.18";
    public const string szOID_OIWSEC_mdc2 = "1.3.14.3.2.19";
    public const string szOID_OIWSEC_dsaComm = "1.3.14.3.2.20";
    public const string szOID_OIWSEC_dsaCommSHA = "1.3.14.3.2.21";
    public const string szOID_OIWSEC_rsaXchg = "1.3.14.3.2.22";
    public const string szOID_OIWSEC_keyHashSeal = "1.3.14.3.2.23";
    public const string szOID_OIWSEC_md2RSASign = "1.3.14.3.2.24";
    public const string szOID_OIWSEC_md5RSASign = "1.3.14.3.2.25";
    public const string szOID_OIWSEC_sha1 = "1.3.14.3.2.26";
    public const string szOID_OIWSEC_dsaSHA1 = "1.3.14.3.2.27";
    public const string szOID_OIWSEC_dsaCommSHA1 = "1.3.14.3.2.28";
    public const string szOID_OIWSEC_sha1RSASign = "1.3.14.3.2.29";
    // NIST OSE Implementors' Workshop (OIW) Directory SIG algorithm identifiers
    public const string szOID_OIWDIR = "1.3.14.7.2";
    public const string szOID_OIWDIR_CRPT = "1.3.14.7.2.1";
    public const string szOID_OIWDIR_HASH = "1.3.14.7.2.2";
    public const string szOID_OIWDIR_SIGN = "1.3.14.7.2.3";
    public const string szOID_OIWDIR_md2 = "1.3.14.7.2.2.1";
    public const string szOID_OIWDIR_md2RSA = "1.3.14.7.2.3.1";

    // INFOSEC Algorithms
    // joint-iso-ccitt(2) country(16) us(840) organization(1) us-government(101) dod(2) id-infosec(1)
    public const string szOID_INFOSEC = "2.16.840.1.101.2.1";
    public const string szOID_INFOSEC_sdnsSignature = "2.16.840.1.101.2.1.1.1";
    public const string szOID_INFOSEC_mosaicSignature = "2.16.840.1.101.2.1.1.2";
    public const string szOID_INFOSEC_sdnsConfidentiality = "2.16.840.1.101.2.1.1.3";
    public const string szOID_INFOSEC_mosaicConfidentiality = "2.16.840.1.101.2.1.1.4";
    public const string szOID_INFOSEC_sdnsIntegrity = "2.16.840.1.101.2.1.1.5";
    public const string szOID_INFOSEC_mosaicIntegrity = "2.16.840.1.101.2.1.1.6";
    public const string szOID_INFOSEC_sdnsTokenProtection = "2.16.840.1.101.2.1.1.7";
    public const string szOID_INFOSEC_mosaicTokenProtection = "2.16.840.1.101.2.1.1.8";
    public const string szOID_INFOSEC_sdnsKeyManagement = "2.16.840.1.101.2.1.1.9";
    public const string szOID_INFOSEC_mosaicKeyManagement = "2.16.840.1.101.2.1.1.10";
    public const string szOID_INFOSEC_sdnsKMandSig = "2.16.840.1.101.2.1.1.11";
    public const string szOID_INFOSEC_mosaicKMandSig = "2.16.840.1.101.2.1.1.12";
    public const string szOID_INFOSEC_SuiteASignature = "2.16.840.1.101.2.1.1.13";
    public const string szOID_INFOSEC_SuiteAConfidentiality = "2.16.840.1.101.2.1.1.14";
    public const string szOID_INFOSEC_SuiteAIntegrity = "2.16.840.1.101.2.1.1.15";
    public const string szOID_INFOSEC_SuiteATokenProtection = "2.16.840.1.101.2.1.1.16";
    public const string szOID_INFOSEC_SuiteAKeyManagement = "2.16.840.1.101.2.1.1.17";
    public const string szOID_INFOSEC_SuiteAKMandSig = "2.16.840.1.101.2.1.1.18";
    public const string szOID_INFOSEC_mosaicUpdatedSig = "2.16.840.1.101.2.1.1.19";
    public const string szOID_INFOSEC_mosaicKMandUpdSig = "2.16.840.1.101.2.1.1.20";
    public const string szOID_INFOSEC_mosaicUpdatedInteg = "2.16.840.1.101.2.1.1.21";

    // NIST Hash Algorithms
    // joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2)
    public const string szOID_NIST_sha256 = "2.16.840.1.101.3.4.2.1";
    public const string szOID_NIST_sha384 = "2.16.840.1.101.3.4.2.2";
    public const string szOID_NIST_sha512 = "2.16.840.1.101.3.4.2.3";

    public string GetName(string identifier)
    {
        var dictionary = new Dictionary<string, string>
        {
            { szOID_RSA, nameof(szOID_RSA) },
            { szOID_PKCS, nameof(szOID_PKCS) },
            { szOID_RSA_HASH, nameof(szOID_RSA_HASH) },
            { szOID_RSA_ENCRYPT, nameof(szOID_RSA_ENCRYPT) },
            { szOID_PKCS_1, nameof(szOID_PKCS_1) },
            { szOID_PKCS_2, nameof(szOID_PKCS_2) },
            { szOID_PKCS_3, nameof(szOID_PKCS_3) },
            { szOID_PKCS_4, nameof(szOID_PKCS_4) },
            { szOID_PKCS_5, nameof(szOID_PKCS_5) },
            { szOID_PKCS_6, nameof(szOID_PKCS_6) },
            { szOID_PKCS_7, nameof(szOID_PKCS_7) },
            { szOID_PKCS_8, nameof(szOID_PKCS_8) },
            { szOID_PKCS_9, nameof(szOID_PKCS_9) },
            { szOID_PKCS_10, nameof(szOID_PKCS_10) },
            { szOID_PKCS_12, nameof(szOID_PKCS_12) },
            { szOID_RSA_RSA, nameof(szOID_RSA_RSA) },
            { szOID_RSA_MD2RSA, nameof(szOID_RSA_MD2RSA) },
            { szOID_RSA_MD4RSA, nameof(szOID_RSA_MD4RSA) },
            { szOID_RSA_MD5RSA, nameof(szOID_RSA_MD5RSA) },
            { szOID_RSA_SHA1RSA, nameof(szOID_RSA_SHA1RSA) },
            { szOID_RSA_SETOAEP_RSA, nameof(szOID_RSA_SETOAEP_RSA) },
            { szOID_RSAES_OAEP, nameof(szOID_RSAES_OAEP) },
            { szOID_RSA_MGF1, nameof(szOID_RSA_MGF1) },
            { szOID_RSA_PSPECIFIED, nameof(szOID_RSA_PSPECIFIED) },
            { szOID_RSA_SSA_PSS, nameof(szOID_RSA_SSA_PSS) },
            { szOID_RSA_SHA256RSA, nameof(szOID_RSA_SHA256RSA) },
            { szOID_RSA_SHA384RSA, nameof(szOID_RSA_SHA384RSA) },
            { szOID_RSA_SHA512RSA, nameof(szOID_RSA_SHA512RSA) },
            { szOID_RSA_DH, nameof(szOID_RSA_DH) },
            { szOID_RSA_data, nameof(szOID_RSA_data) },
            { szOID_RSA_signedData, nameof(szOID_RSA_signedData) },
            { szOID_RSA_envelopedData, nameof(szOID_RSA_envelopedData) },
            { szOID_RSA_signEnvData, nameof(szOID_RSA_signEnvData) },
            { szOID_RSA_digestedData, nameof(szOID_RSA_digestedData) },
            { szOID_RSA_hashedData, nameof(szOID_RSA_hashedData) },
            { szOID_RSA_encryptedData, nameof(szOID_RSA_encryptedData) },
            { szOID_RSA_emailAddr, nameof(szOID_RSA_emailAddr) },
            { szOID_RSA_unstructName, nameof(szOID_RSA_unstructName) },
            { szOID_RSA_contentType, nameof(szOID_RSA_contentType) },
            { szOID_RSA_messageDigest, nameof(szOID_RSA_messageDigest) },
            { szOID_RSA_signingTime, nameof(szOID_RSA_signingTime) },
            { szOID_RSA_counterSign, nameof(szOID_RSA_counterSign) },
            { szOID_RSA_challengePwd, nameof(szOID_RSA_challengePwd) },
            { szOID_RSA_unstructAddr, nameof(szOID_RSA_unstructAddr) },
            { szOID_RSA_extCertAttrs, nameof(szOID_RSA_extCertAttrs) },
            { szOID_RSA_certExtensions, nameof(szOID_RSA_certExtensions) },
            { szOID_RSA_SMIMECapabilities, nameof(szOID_RSA_SMIMECapabilities) },
            { szOID_RSA_preferSignedData, nameof(szOID_RSA_preferSignedData) },
            { szOID_TIMESTAMP_TOKEN, nameof(szOID_TIMESTAMP_TOKEN) },
            { szOID_RFC3161_counterSign, nameof(szOID_RFC3161_counterSign) },
            { szOID_RSA_SMIMEalg, nameof(szOID_RSA_SMIMEalg) },
            { szOID_RSA_SMIMEalgESDH, nameof(szOID_RSA_SMIMEalgESDH) },
            { szOID_RSA_SMIMEalgCMS3DESwrap, nameof(szOID_RSA_SMIMEalgCMS3DESwrap) },
            { szOID_RSA_SMIMEalgCMSRC2wrap, nameof(szOID_RSA_SMIMEalgCMSRC2wrap) },
            { szOID_RSA_MD2, nameof(szOID_RSA_MD2) },
            { szOID_RSA_MD4, nameof(szOID_RSA_MD4) },
            { szOID_RSA_MD5, nameof(szOID_RSA_MD5) },
            { szOID_RSA_RC2CBC, nameof(szOID_RSA_RC2CBC) },
            { szOID_RSA_RC4, nameof(szOID_RSA_RC4) },
            { szOID_RSA_DES_EDE3_CBC, nameof(szOID_RSA_DES_EDE3_CBC) },
            { szOID_RSA_RC5_CBCPad, nameof(szOID_RSA_RC5_CBCPad) },
            { szOID_ANSI_X942, nameof(szOID_ANSI_X942) },
            { szOID_ANSI_X942_DH, nameof(szOID_ANSI_X942_DH) },
            { szOID_X957, nameof(szOID_X957) },
            { szOID_X957_DSA, nameof(szOID_X957_DSA) },
            { szOID_X957_SHA1DSA, nameof(szOID_X957_SHA1DSA) },
            { szOID_ECC_PUBLIC_KEY, nameof(szOID_ECC_PUBLIC_KEY) },
            { szOID_ECC_CURVE_P256, nameof(szOID_ECC_CURVE_P256) },
            { szOID_ECC_CURVE_P384, nameof(szOID_ECC_CURVE_P384) },
            { szOID_ECC_CURVE_P521, nameof(szOID_ECC_CURVE_P521) },
            { szOID_ECC_CURVE_BRAINPOOLP160R1, nameof(szOID_ECC_CURVE_BRAINPOOLP160R1) },
            { szOID_ECC_CURVE_BRAINPOOLP160T1, nameof(szOID_ECC_CURVE_BRAINPOOLP160T1) },
            { szOID_ECC_CURVE_BRAINPOOLP192R1, nameof(szOID_ECC_CURVE_BRAINPOOLP192R1) },
            { szOID_ECC_CURVE_BRAINPOOLP192T1, nameof(szOID_ECC_CURVE_BRAINPOOLP192T1) },
            { szOID_ECC_CURVE_BRAINPOOLP224R1, nameof(szOID_ECC_CURVE_BRAINPOOLP224R1) },
            { szOID_ECC_CURVE_BRAINPOOLP224T1, nameof(szOID_ECC_CURVE_BRAINPOOLP224T1) },
            { szOID_ECC_CURVE_BRAINPOOLP256R1, nameof(szOID_ECC_CURVE_BRAINPOOLP256R1) },
            { szOID_ECC_CURVE_BRAINPOOLP256T1, nameof(szOID_ECC_CURVE_BRAINPOOLP256T1) },
            { szOID_ECC_CURVE_BRAINPOOLP320R1, nameof(szOID_ECC_CURVE_BRAINPOOLP320R1) },
            { szOID_ECC_CURVE_BRAINPOOLP320T1, nameof(szOID_ECC_CURVE_BRAINPOOLP320T1) },
            { szOID_ECC_CURVE_BRAINPOOLP384R1, nameof(szOID_ECC_CURVE_BRAINPOOLP384R1) },
            { szOID_ECC_CURVE_BRAINPOOLP384T1, nameof(szOID_ECC_CURVE_BRAINPOOLP384T1) },
            { szOID_ECC_CURVE_BRAINPOOLP512R1, nameof(szOID_ECC_CURVE_BRAINPOOLP512R1) },
            { szOID_ECC_CURVE_BRAINPOOLP512T1, nameof(szOID_ECC_CURVE_BRAINPOOLP512T1) },
            { szOID_ECC_CURVE_EC192WAPI, nameof(szOID_ECC_CURVE_EC192WAPI) },
            { szOID_CN_ECDSA_SHA256, nameof(szOID_CN_ECDSA_SHA256) },
            { szOID_ECC_CURVE_NISTP192, nameof(szOID_ECC_CURVE_NISTP192) },
            { szOID_ECC_CURVE_NISTP224, nameof(szOID_ECC_CURVE_NISTP224) },
            { szOID_ECC_CURVE_NISTP256, nameof(szOID_ECC_CURVE_NISTP256) },
            { szOID_ECC_CURVE_NISTP384, nameof(szOID_ECC_CURVE_NISTP384) },
            { szOID_ECC_CURVE_NISTP521, nameof(szOID_ECC_CURVE_NISTP521) },
            { szOID_ECC_CURVE_SECP160K1, nameof(szOID_ECC_CURVE_SECP160K1) },
            { szOID_ECC_CURVE_SECP160R1, nameof(szOID_ECC_CURVE_SECP160R1) },
            { szOID_ECC_CURVE_SECP160R2, nameof(szOID_ECC_CURVE_SECP160R2) },
            { szOID_ECC_CURVE_SECP192K1, nameof(szOID_ECC_CURVE_SECP192K1) },
            { szOID_ECC_CURVE_SECP192R1, nameof(szOID_ECC_CURVE_SECP192R1) },
            { szOID_ECC_CURVE_SECP224K1, nameof(szOID_ECC_CURVE_SECP224K1) },
            { szOID_ECC_CURVE_SECP224R1, nameof(szOID_ECC_CURVE_SECP224R1) },
            { szOID_ECC_CURVE_SECP256K1, nameof(szOID_ECC_CURVE_SECP256K1) },
            { szOID_ECC_CURVE_SECP256R1, nameof(szOID_ECC_CURVE_SECP256R1) },
            { szOID_ECC_CURVE_SECP384R1, nameof(szOID_ECC_CURVE_SECP384R1) },
            { szOID_ECC_CURVE_SECP521R1, nameof(szOID_ECC_CURVE_SECP521R1) },
            { szOID_ECC_CURVE_WTLS7, nameof(szOID_ECC_CURVE_WTLS7) },
            { szOID_ECC_CURVE_WTLS9, nameof(szOID_ECC_CURVE_WTLS9) },
            { szOID_ECC_CURVE_WTLS12, nameof(szOID_ECC_CURVE_WTLS12) },
            { szOID_ECC_CURVE_X962P192V1, nameof(szOID_ECC_CURVE_X962P192V1) },
            { szOID_ECC_CURVE_X962P192V2, nameof(szOID_ECC_CURVE_X962P192V2) },
            { szOID_ECC_CURVE_X962P192V3, nameof(szOID_ECC_CURVE_X962P192V3) },
            { szOID_ECC_CURVE_X962P239V1, nameof(szOID_ECC_CURVE_X962P239V1) },
            { szOID_ECC_CURVE_X962P239V2, nameof(szOID_ECC_CURVE_X962P239V2) },
            { szOID_ECC_CURVE_X962P239V3, nameof(szOID_ECC_CURVE_X962P239V3) },
            { szOID_ECC_CURVE_X962P256V1, nameof(szOID_ECC_CURVE_X962P256V1) },
            { szOID_ECDSA_SHA1, nameof(szOID_ECDSA_SHA1) },
            { szOID_ECDSA_SPECIFIED, nameof(szOID_ECDSA_SPECIFIED) },
            { szOID_ECDSA_SHA256, nameof(szOID_ECDSA_SHA256) },
            { szOID_ECDSA_SHA384, nameof(szOID_ECDSA_SHA384) },
            { szOID_ECDSA_SHA512, nameof(szOID_ECDSA_SHA512) },
            { szOID_NIST_AES128_CBC, nameof(szOID_NIST_AES128_CBC) },
            { szOID_NIST_AES192_CBC, nameof(szOID_NIST_AES192_CBC) },
            { szOID_NIST_AES256_CBC, nameof(szOID_NIST_AES256_CBC) },
            { szOID_NIST_AES128_WRAP, nameof(szOID_NIST_AES128_WRAP) },
            { szOID_NIST_AES192_WRAP, nameof(szOID_NIST_AES192_WRAP) },
            { szOID_NIST_AES256_WRAP, nameof(szOID_NIST_AES256_WRAP) },
            { szOID_DH_SINGLE_PASS_STDDH_SHA1_KDF, nameof(szOID_DH_SINGLE_PASS_STDDH_SHA1_KDF) },
            { szOID_DH_SINGLE_PASS_STDDH_SHA256_KDF, nameof(szOID_DH_SINGLE_PASS_STDDH_SHA256_KDF) },
            { szOID_DH_SINGLE_PASS_STDDH_SHA384_KDF, nameof(szOID_DH_SINGLE_PASS_STDDH_SHA384_KDF) },
            { szOID_DS, nameof(szOID_DS) },
            { szOID_DSALG, nameof(szOID_DSALG) },
            { szOID_DSALG_CRPT, nameof(szOID_DSALG_CRPT) },
            { szOID_DSALG_HASH, nameof(szOID_DSALG_HASH) },
            { szOID_DSALG_SIGN, nameof(szOID_DSALG_SIGN) },
            { szOID_DSALG_RSA, nameof(szOID_DSALG_RSA) },
            { szOID_OIW, nameof(szOID_OIW) },
            { szOID_OIWSEC, nameof(szOID_OIWSEC) },
            { szOID_OIWSEC_md4RSA, nameof(szOID_OIWSEC_md4RSA) },
            { szOID_OIWSEC_md5RSA, nameof(szOID_OIWSEC_md5RSA) },
            { szOID_OIWSEC_md4RSA2, nameof(szOID_OIWSEC_md4RSA2) },
            { szOID_OIWSEC_desECB, nameof(szOID_OIWSEC_desECB) },
            { szOID_OIWSEC_desCBC, nameof(szOID_OIWSEC_desCBC) },
            { szOID_OIWSEC_desOFB, nameof(szOID_OIWSEC_desOFB) },
            { szOID_OIWSEC_desCFB, nameof(szOID_OIWSEC_desCFB) },
            { szOID_OIWSEC_desMAC, nameof(szOID_OIWSEC_desMAC) },
            { szOID_OIWSEC_rsaSign, nameof(szOID_OIWSEC_rsaSign) },
            { szOID_OIWSEC_dsa, nameof(szOID_OIWSEC_dsa) },
            { szOID_OIWSEC_shaDSA, nameof(szOID_OIWSEC_shaDSA) },
            { szOID_OIWSEC_mdc2RSA, nameof(szOID_OIWSEC_mdc2RSA) },
            { szOID_OIWSEC_shaRSA, nameof(szOID_OIWSEC_shaRSA) },
            { szOID_OIWSEC_dhCommMod, nameof(szOID_OIWSEC_dhCommMod) },
            { szOID_OIWSEC_desEDE, nameof(szOID_OIWSEC_desEDE) },
            { szOID_OIWSEC_sha, nameof(szOID_OIWSEC_sha) },
            { szOID_OIWSEC_mdc2, nameof(szOID_OIWSEC_mdc2) },
            { szOID_OIWSEC_dsaComm, nameof(szOID_OIWSEC_dsaComm) },
            { szOID_OIWSEC_dsaCommSHA, nameof(szOID_OIWSEC_dsaCommSHA) },
            { szOID_OIWSEC_rsaXchg, nameof(szOID_OIWSEC_rsaXchg) },
            { szOID_OIWSEC_keyHashSeal, nameof(szOID_OIWSEC_keyHashSeal) },
            { szOID_OIWSEC_md2RSASign, nameof(szOID_OIWSEC_md2RSASign) },
            { szOID_OIWSEC_md5RSASign, nameof(szOID_OIWSEC_md5RSASign) },
            { szOID_OIWSEC_sha1, nameof(szOID_OIWSEC_sha1) },
            { szOID_OIWSEC_dsaSHA1, nameof(szOID_OIWSEC_dsaSHA1) },
            { szOID_OIWSEC_dsaCommSHA1, nameof(szOID_OIWSEC_dsaCommSHA1) },
            { szOID_OIWSEC_sha1RSASign, nameof(szOID_OIWSEC_sha1RSASign) },
            { szOID_OIWDIR, nameof(szOID_OIWDIR) },
            { szOID_OIWDIR_CRPT, nameof(szOID_OIWDIR_CRPT) },
            { szOID_OIWDIR_HASH, nameof(szOID_OIWDIR_HASH) },
            { szOID_OIWDIR_SIGN, nameof(szOID_OIWDIR_SIGN) },
            { szOID_OIWDIR_md2, nameof(szOID_OIWDIR_md2) },
            { szOID_OIWDIR_md2RSA, nameof(szOID_OIWDIR_md2RSA) },
            { szOID_INFOSEC, nameof(szOID_INFOSEC) },
            { szOID_INFOSEC_sdnsSignature, nameof(szOID_INFOSEC_sdnsSignature) },
            { szOID_INFOSEC_mosaicSignature, nameof(szOID_INFOSEC_mosaicSignature) },
            { szOID_INFOSEC_sdnsConfidentiality, nameof(szOID_INFOSEC_sdnsConfidentiality) },
            { szOID_INFOSEC_mosaicConfidentiality, nameof(szOID_INFOSEC_mosaicConfidentiality) },
            { szOID_INFOSEC_sdnsIntegrity, nameof(szOID_INFOSEC_sdnsIntegrity) },
            { szOID_INFOSEC_mosaicIntegrity, nameof(szOID_INFOSEC_mosaicIntegrity) },
            { szOID_INFOSEC_sdnsTokenProtection, nameof(szOID_INFOSEC_sdnsTokenProtection) },
            { szOID_INFOSEC_mosaicTokenProtection, nameof(szOID_INFOSEC_mosaicTokenProtection) },
            { szOID_INFOSEC_sdnsKeyManagement, nameof(szOID_INFOSEC_sdnsKeyManagement) },
            { szOID_INFOSEC_mosaicKeyManagement, nameof(szOID_INFOSEC_mosaicKeyManagement) },
            { szOID_INFOSEC_sdnsKMandSig, nameof(szOID_INFOSEC_sdnsKMandSig) },
            { szOID_INFOSEC_mosaicKMandSig, nameof(szOID_INFOSEC_mosaicKMandSig) },
            { szOID_INFOSEC_SuiteASignature, nameof(szOID_INFOSEC_SuiteASignature) },
            { szOID_INFOSEC_SuiteAConfidentiality, nameof(szOID_INFOSEC_SuiteAConfidentiality) },
            { szOID_INFOSEC_SuiteAIntegrity, nameof(szOID_INFOSEC_SuiteAIntegrity) },
            { szOID_INFOSEC_SuiteATokenProtection, nameof(szOID_INFOSEC_SuiteATokenProtection) },
            { szOID_INFOSEC_SuiteAKeyManagement, nameof(szOID_INFOSEC_SuiteAKeyManagement) },
            { szOID_INFOSEC_SuiteAKMandSig, nameof(szOID_INFOSEC_SuiteAKMandSig) },
            { szOID_INFOSEC_mosaicUpdatedSig, nameof(szOID_INFOSEC_mosaicUpdatedSig) },
            { szOID_INFOSEC_mosaicKMandUpdSig, nameof(szOID_INFOSEC_mosaicKMandUpdSig) },
            { szOID_INFOSEC_mosaicUpdatedInteg, nameof(szOID_INFOSEC_mosaicUpdatedInteg) },
            { szOID_NIST_sha256, nameof(szOID_NIST_sha256) },
            { szOID_NIST_sha384, nameof(szOID_NIST_sha384) },
            { szOID_NIST_sha512, nameof(szOID_NIST_sha512) }
        };

        return dictionary[identifier];
    }
}