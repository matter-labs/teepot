# Intel® SGX and Intel® TDX services - V3 API Documentation

## Intel® SGX and Intel® TDX Registration Service for Scalable Platforms

The API exposed by the Intel SGX registration service allows registering an Intel® SGX platform with multiple processor
packages as a single platform instance, which can be remotely attested as a single entity later on[cite: 1]. The minimum
version of the TLS protocol supported by the service is 1.2; any connection attempts with previous versions of TLS/SSL
will be dropped by the server[cite: 2].

### Register Platform

This API allows registering a multi-package SGX platform, covering initial registration and TCB Recovery[cite: 2].
During registration, the platform manifest is authenticated by the Registration Service to verify it originates from a
genuine, non-revoked SGX platform[cite: 2]. If the platform configuration is successfully verified, platform
provisioning root keys are stored in the backend[cite: 2].

Stored platform provisioning root keys are later used to derive the public parts of Provisioning Certification Keys (
PCKs)[cite: 2]. These PCKs are distributed as x.509 certificates by the Provisioning Certification Service for Intel SGX
and are used during the remote attestation of the platform[cite: 3].

#### POST `https://api.trustedservices.intel.com/sgx/registration/v1/platform`

**Request**

**Headers**

Besides the headers explicitly mentioned below, the HTTP request may contain standard HTTP headers (e.g.,
Content-Length)[cite: 3].

| Name         | Required | Value                      | Description                             |
|:-------------|:---------|:---------------------------|:----------------------------------------|
| Content-Type | True     | `application/octet-stream` | MIME type of the request body[cite: 4]. |

**Body**

The body is a binary representation of the Platform Manifest structure – an opaque blob representing a registration
manifest for a multi-package platform[cite: 5]. It contains platform provisioning root keys established by the platform
instance and data required to authenticate the platform as genuine and non-revoked[cite: 5].

**Example Request**

```bash
curl -H "Content-Type: application/octet-stream" --data-binary @platform_manifest POST "[https://api.trustedservices.intel.com/sgx/registration/v1/platform](https://api.trustedservices.intel.com/sgx/registration/v1/platform)"
````

**Response**

**Model**

The response is a Hex-encoded representation of the PPID for the registered platform instance (only if the HTTP Status
Code is 201; otherwise, the body is empty).

**Example Response**

```
001122334455667788AABBCCDDEEFF
```

**Status Codes**

| Code | Headers                                                                                                                               | Body                                | Description                                                                                                                                                                                                                                                                                                                                                                              |
|:-----|:--------------------------------------------------------------------------------------------------------------------------------------|:------------------------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 201  | Request-ID: Randomly generated identifier for each request (for troubleshooting purposes).                                            | Hex-encoded representation of PPID. | Operation successful (new platform instance registered). A new platform instance has been registered[cite: 5].                                                                                                                                                                                                                                                                           |
| 400  | Request-ID: Randomly generated identifier[cite: 6]. \<br\> Error-Code and Error-Message: Additional details about the error[cite: 9]. |                                     | Invalid Platform Manifest[cite: 8]. The request might be malformed[cite: 6], intended for a different server[cite: 7], contain an invalid/revoked package[cite: 7], an unrecognized package[cite: 7], an incompatible package[cite: 7], an invalid manifest[cite: 7], or violate a key caching policy[cite: 8]. The client should not repeat the request without modifications[cite: 9]. |
| 415  | Request-ID: Randomly generated identifier[cite: 10].                                                                                  |                                     | MIME type specified in the request is not supported[cite: 10].                                                                                                                                                                                                                                                                                                                           |
| 500  | Request-ID: Randomly generated identifier[cite: 10].                                                                                  |                                     | Internal server error occurred[cite: 10].                                                                                                                                                                                                                                                                                                                                                |
| 503  | Request-ID: Randomly generated identifier[cite: 10].                                                                                  |                                     | Server is currently unable to process the request. The client should try again later[cite: 11].                                                                                                                                                                                                                                                                                          |

-----

### Add Package

This API adds new package(s) to an already registered platform instance[cite: 11]. A subscription is required[cite: 11].
If successful, a Platform Membership Certificate is generated for each processor package in the Add Request[cite: 12].

#### POST `https://api.trustedservices.intel.com/sgx/registration/v1/package`

**Request**

**Headers**

| Name                      | Required | Value                      | Description                                                                     |
|:--------------------------|:---------|:---------------------------|:--------------------------------------------------------------------------------|
| Ocp-Apim-Subscription-Key | True     |                            | Subscription key providing access to this API, found in your Profile[cite: 14]. |
| Content-Type              | True     | `application/octet-stream` | MIME type of the request body[cite: 14].                                        |

**Body**

Binary representation of the Add Request structure – an opaque blob for adding new processor packages to an existing
platform instance.

**Example Request**

```bash
curl -H "Content-Type: application/octet-stream" --data-binary @add_package POST "[https://api.trustedservices.intel.com/sgx/registration/v1/package](https://api.trustedservices.intel.com/sgx/registration/v1/package)" -H "Ocp-Apim-Subscription-Key: {subscription_key}"
```

**Response**

**Model**

For a 200 HTTP Status Code, the response is a fixed-size array (8 elements) containing binary representations of
Platform Membership Certificate structures[cite: 15]. Certificates are populated sequentially, starting at index 0, with
the rest of the elements zeroed[cite: 15].

**Example Response (hex-encoded)**

```
E4B0E8B80F8B49184488F77273550840984816854488B7CFRP...
```

**Status Codes**

| Code | Headers                                                                                                                                                                 | Body                                                            | Description                                                                                                                                                       |
|:-----|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:----------------------------------------------------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 200  | Content-Type: `application/octet-stream`[cite: 17]. \<br\> Request-ID: Random identifier[cite: 17]. \<br\> CertificateCount: Number of certificates returned[cite: 17]. | Fixed-size array of Platform Membership Certificates[cite: 17]. | Operation successful. Packages added[cite: 17].                                                                                                                   |
| 400  | Request-ID: Random identifier[cite: 17]. \<br\> Error-Code and Error-Message: Details on the error[cite: 17].                                                           |                                                                 | Invalid Add Request Payload[cite: 17]. Can be due to malformed syntax, platform not found, invalid/revoked/unrecognized package, or invalid AddRequest[cite: 17]. |
| 401  | Request-ID: Random identifier[cite: 17].                                                                                                                                |                                                                 | Failed to authenticate or authorize the request[cite: 17].                                                                                                        |
| 415  | Request-ID: Random identifier[cite: 17].                                                                                                                                |                                                                 | MIME type specified is not supported[cite: 17].                                                                                                                   |
| 500  | Request-ID: Random identifier[cite: 17].                                                                                                                                |                                                                 | Internal server error occurred[cite: 17].                                                                                                                         |
| 503  | Request-ID: Random identifier[cite: 17].                                                                                                                                |                                                                 | Server is currently unable to process the request[cite: 17].                                                                                                      |

-----

## Intel® SGX Provisioning Certification Service for ECDSA Attestation

Download the Provisioning Certification Root CA Certificate (API v3) here:

* [DER](https://www.google.com/search?q=https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.cer) [cite: 18]
* [PEM](https://www.google.com/search?q=https://certificates.trustedservices.intel.com/intel_SGX_Provisioning_Certification_RootCA.perm) [cite: 18]

### Get PCK Certificate V3

This API allows requesting a single PCK certificate by specifying PPID and SVNs or Platform Manifest and SVNs[cite: 18].
A subscription is required[cite: 18].

* **Using PPID and SVNs**:
    * Single-socket platforms: No prerequisites[cite: 18].
    * Multi-socket platforms: Requires previous registration via `Register Platform` API[cite: 18]. Platform root keys
      must be persistently stored[cite: 19], and the `Keys Caching Policy` must be set to `true`[cite: 21]. The service
      uses a PCK public key derived from stored keys[cite: 20].
* **Using Platform Manifest and SVNs**:
    * Multi-socket platforms: Does not require previous registration[cite: 21]. It doesn't require keys to be
      persistently stored[cite: 22]. The service uses a PCK public key derived from the provided manifest[cite: 23].
      Depending on the `Keys Caching Policy`, keys might be stored[cite: 24].
        * **Direct Registration** (`Register Platform` first): Sets policy to always store keys[cite: 25]. Keys are
          stored when the manifest is sent[cite: 26]. `CachedKeys` flag in PCK Certificates is set to `true`[cite: 27].
        * **Indirect Registration** (`Get PCK Certificate(s)` first): Sets policy to never store keys[cite: 27]. Keys
          are discarded after use[cite: 28]. Standard metadata is stored, but `Register Platform` cannot be used
          anymore[cite: 29]. `CachedKeys` flag is set to `false`[cite: 30].

The PCS returns the PCK Certificate representing the TCB level with the highest security posture based on CPUSVN and PCE
ISVSVN[cite: 30].

#### GET `https://api.trustedservices.intel.com/sgx/certification/v3/pckcert`

**Request**

| Name                      | Type   | Type   | Required | Pattern             | Description                                                      |
|:--------------------------|:-------|:-------|:---------|:--------------------|:-----------------------------------------------------------------|
| Ocp-Apim-Subscription-Key | String | Header | True     |                     | Subscription key[cite: 32].                                      |
| PPID-Encryption-Key       | String | Header | False    |                     | Type of key for PPID encryption (Default: `RSA-3072`)[cite: 32]. |
| encrypted\_ppid           | String | Query  | True     | `[0-9a-fA-F]{768}$` | Base16-encoded PPID (encrypted with PPIDEK)[cite: 32].           |
| cpusvn                    | String | Query  | True     | `[0-9a-fA-F]{32}$`  | Base16-encoded CPUSVN (16 bytes)[cite: 32].                      |
| pcesvn                    | String | Query  | True     | `[0-9a-fA-F]{4}$`   | Base16-encoded PCESVN (2 bytes, little endian)[cite: 32].        |
| pceid                     | String | Query  | True     | `[0-9a-fA-F]{4}$`   | Base16-encoded PCE-ID (2 bytes, little endian)[cite: 32].        |

**Example Request**

```bash
curl -X GET "[https://api.trustedservices.intel.com/sgx/certification/v3/pckcert?encrypted_ppid=...&cpusvn=...&pcesvn=...&pceid=](https://api.trustedservices.intel.com/sgx/certification/v3/pckcert?encrypted_ppid=...&cpusvn=...&pcesvn=...&pceid=)..." -H "Ocp-Apim-Subscription-Key: {subscription_key}"
```

**Response**: Response description can be
found [here](https://www.google.com/search?q=%23response-get-and-post-1)[cite: 34].

#### POST `https://api.trustedservices.intel.com/sgx/certification/v3/pckcert`

**Request**

| Name                      | Type   | Request Type | Required | Pattern                      | Description                                  |
|:--------------------------|:-------|:-------------|:---------|:-----------------------------|:---------------------------------------------|
| Ocp-Apim-Subscription-Key | String | Header       | True     |                              | Subscription key[cite: 35].                  |
| Content-Type              | String | Header       | True     |                              | Content Type (`application/json`)[cite: 35]. |
| platformManifest          | String | Body Field   | True     | `[0-9a-fA-F]{16882,112884}$` | Base16-encoded Platform Manifest[cite: 35].  |
| cpusvn                    | String | Body Field   | True     | `[0-9a-fA-F]{32}$`           | Base16-encoded CPUSVN[cite: 35].             |
| pcesvn                    | String | Body Field   | True     | `[0-9a-fA-F]{4}$`            | Base16-encoded PCESVN[cite: 35].             |
| pceid                     | String | Body Field   | True     | `[0-9a-fA-F]{4}$`            | Base16-encoded PCE-ID[cite: 35].             |

**Body**

```json
{
  "platformManifest": "...",
  "cpusvn": "...",
  "pcesvn": "...",
  "pceid": "..."
}
```

**Example Request**

```bash
curl -X POST -d '{"platformManifest": "...", "cpusvn": "...", "pcesvn": "...", "pceid": "..."}' -H "Content-Type: application/json" -H "Ocp-Apim-Subscription-Key: {subscription_key}" "[https://api.trustedservices.intel.com/sgx/certification/v3/pckcert](https://api.trustedservices.intel.com/sgx/certification/v3/pckcert)"
```

**Response (GET and POST)**

**Model**: PckCert (X-PEM-FILE) - PEM-encoded SGX PCK Certificate[cite: 36].

**Example Response**

```pem
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
```

**Status Codes**

| Code | Model   | Headers                                                                                                                                                                                                                                                                                                                                                                                   | Description                                                                                                                                      |
|:-----|:--------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| 200  | PckCert | Content-Type: `application/x-pem-file`[cite: 36]. \<br\> Request-ID[cite: 36]. \<br\> SGX-PCK-Certificate-Issuer-Chain: URL-encoded issuer chain[cite: 36]. \<br\> SGX-TCBm: Hex-encoded CPUSVN and PCESVN[cite: 37]. \<br\> SGX-FMSPC: Hex-encoded FMSPC[cite: 37]. \<br\> SGX-PCK-Certificate-CA-Type: 'processor' or 'platform'[cite: 39]. \<br\> Warning: Optional message[cite: 39]. | Operation successful[cite: 36].                                                                                                                  |
| 400  |         | Request-ID[cite: 39]. \<br\> Warning[cite: 39].                                                                                                                                                                                                                                                                                                                                           | Invalid request parameters[cite: 39].                                                                                                            |
| 401  |         | Request-ID[cite: 40]. \<br\> Warning[cite: 40].                                                                                                                                                                                                                                                                                                                                           | Failed to authenticate or authorize the request[cite: 40].                                                                                       |
| 404  |         | Request-ID[cite: 40]. \<br\> Warning[cite: 40].                                                                                                                                                                                                                                                                                                                                           | PCK Certificate not found[cite: 40]. Reasons: unsupported PPID/PCE-ID, TCB level too low, or Platform Manifest not registered/updated[cite: 41]. |
| 500  |         | Request-ID[cite: 41]. \<br\> Warning[cite: 41].                                                                                                                                                                                                                                                                                                                                           | Internal server error occurred[cite: 41].                                                                                                        |
| 503  |         | Request-ID[cite: 42]. \<br\> Warning[cite: 42].                                                                                                                                                                                                                                                                                                                                           | Server is currently unable to process the request[cite: 42].                                                                                     |

-----

### Get PCK Certificates V3

This API retrieves PCK certificates for all configured TCB levels using PPID or Platform Manifest[cite: 42].
Subscription required[cite: 42].

* **Using PPID**:
    * Single-socket platforms: No prerequisites[cite: 43].
    * Multi-socket platforms: Requires prior registration via `Register Platform` API[cite: 44]. Keys must be
      persistently stored[cite: 45], and `Keys Caching Policy` must be `true`[cite: 47]. PCS uses stored keys[cite: 46].
* **Using Platform Manifest**:
    * Multi-socket platforms: Does not require prior registration[cite: 47]. Does not require persistent
      storage[cite: 48]. PCS uses manifest keys[cite: 49]. Caching policy determines storage[cite: 50].
        * **Direct Registration**: Always stores keys; `CachedKeys` is `true`[cite: 51, 52].
        * **Indirect Registration**: Never stores keys; `CachedKeys` is `false`[cite: 53].

#### GET `https://api.trustedservices.intel.com/sgx/certification/v3/pckcerts`

Retrieves certificates based on encrypted PPID and PCE-ID[cite: 53].

**Request**

| Name                      | Type   | Type   | Required | Pattern             | Description                                                   |
|:--------------------------|:-------|:-------|:---------|:--------------------|:--------------------------------------------------------------|
| Ocp-Apim-Subscription-Key | String | Header | True     |                     | Subscription key[cite: 54].                                   |
| PPID-Encryption-Key       | String | Header | False    |                     | Key type for PPID encryption (Default: `RSA-3072`)[cite: 54]. |
| encrypted\_ppid           | String | Query  | True     | `[0-9a-fA-F]{768}$` | Base16-encoded PPID[cite: 54].                                |
| pceid                     | String | Query  | True     | `[0-9a-fA-F]{4}$`   | Base16-encoded PCE-ID[cite: 54].                              |

**Example Request**

```bash
curl -X GET "[https://api.trustedservices.intel.com/sgx/certification/v3/pckcerts?encrypted_ppid=...&pceid=](https://api.trustedservices.intel.com/sgx/certification/v3/pckcerts?encrypted_ppid=...&pceid=)..." -H "Ocp-Apim-Subscription-Key: {subscription_key}"
```

**Response**: Response description can be
found [here](https://www.google.com/search?q=%23response-get-and-post-2)[cite: 55].

#### GET `https://api.trustedservices.intel.com/sgx/certification/v3/pckcerts/config`

Retrieves certificates for a specific CPUSVN (multi-package only)[cite: 55].

**Request**

| Name                      | Type   | Type   | Required | Pattern             | Description                             |
|:--------------------------|:-------|:-------|:---------|:--------------------|:----------------------------------------|
| Ocp-Apim-Subscription-Key | String | Header | True     |                     | Subscription key[cite: 56].             |
| PPID-Encryption-Key       | String | Header | False    |                     | Key type for PPID encryption[cite: 56]. |
| encrypted\_ppid           | String | Query  | True     | `[0-9a-fA-F]{768}$` | Base16-encoded PPID[cite: 56].          |
| pceid                     | String | Query  | True     | `[0-9a-fA-F]{4}$`   | Base16-encoded PCE-ID[cite: 56].        |
| cpusvn                    | String | Query  | True     | `[0-9a-fA-F]{32}$`  | Base16-encoded CPUSVN[cite: 56].        |

**Example Request**

```bash
curl -X GET "[https://api.trustedservices.intel.com/sgx/certification/v3/pckcerts/config?encrypted_ppid=...&pceid=...&cpusvn=](https://api.trustedservices.intel.com/sgx/certification/v3/pckcerts/config?encrypted_ppid=...&pceid=...&cpusvn=)..." -H "Ocp-Apim-Subscription-Key: {subscription_key}"
```

**Response**: Response description can be
found [here](https://www.google.com/search?q=%23response-get-and-post-2)[cite: 57].

#### POST `https://api.trustedservices.intel.com/sgx/certification/v3/pckcerts`

Retrieves certificates based on Platform Manifest and PCE-ID (multi-package only)[cite: 57].

**Request**

| Name                      | Type   | Request Type | Required | Pattern                      | Description                                 |
|:--------------------------|:-------|:-------------|:---------|:-----------------------------|:--------------------------------------------|
| Ocp-Apim-Subscription-Key | String | Header       | True     |                              | Subscription key[cite: 58].                 |
| Content-Type              | String | Header       | True     | `application/json`           | Content Type[cite: 58].                     |
| platformManifest          | String | Body Field   | True     | `[0-9a-fA-F]{16882,112884}$` | Base16-encoded Platform Manifest[cite: 58]. |
| pceid                     | String | Body Field   | True     | `[0-9a-fA-F]{4}$`            | Base16-encoded PCE-ID[cite: 58].            |

**Body**

```json
{
  "platformManifest": "...",
  "pceid": "..."
}
```

**Example Request**

```bash
curl -X POST -d '{"platformManifest": "...", "pceid": "..."}' -H "Content-Type: application/json" -H "Ocp-Apim-Subscription-Key: {subscription_key}" "[https://api.trustedservices.intel.com/sgx/certification/v3/pckcerts](https://api.trustedservices.intel.com/sgx/certification/v3/pckcerts)"
```

**Response**: Response description can be
found [here](https://www.google.com/search?q=%23response-get-and-post-2)[cite: 59].

#### POST `https://api.trustedservices.intel.com/sgx/certification/v3/pckcerts/config`

Retrieves certificates for a specific CPUSVN using Platform Manifest (multi-package only)[cite: 59].

**Request**

| Name                      | Type   | Request Type | Required | Pattern                      | Description                                 |
|:--------------------------|:-------|:-------------|:---------|:-----------------------------|:--------------------------------------------|
| Ocp-Apim-Subscription-Key | String | Header       | True     |                              | Subscription key[cite: 61].                 |
| Content-Type              | String | Header       | True     | `application/json`           | Content Type[cite: 61].                     |
| platformManifest          | String | Body Field   | True     | `[0-9a-fA-F]{16882,112884}$` | Base16-encoded Platform Manifest[cite: 61]. |
| cpusvn                    | String | Body Field   | True     | `[0-9a-fA-F]{32}$`           | Base16-encoded CPUSVN[cite: 61].            |
| pceid                     | String | Body Field   | True     | `[0-9a-fA-F]{4}$`            | Base16-encoded PCE-ID[cite: 61].            |

**Body**

```json
{
  "platformManifest": "...",
  "cpusvn": "...",
  "pceid": "..."
}
```

**Example Request**

```bash
curl -X POST -d '{"platformManifest": "...", "cpusvn": "...", "pceid": "..."}' -H "Content-Type: application/json" -H "Ocp-Apim-Subscription-Key: {subscription_key}" "[https://api.trustedservices.intel.com/sgx/certification/v3/pckcerts/config](https://api.trustedservices.intel.com/sgx/certification/v3/pckcerts/config)"
```

**Response (GET and POST)**

**Model**: PckCerts (JSON) - Array of data structures with `tcb`, `tcm`, and `certificate`[cite: 62].

**PckCerts Structure**

```json
[
  {
    "tcb": {
      "sgxtcbcomp01svn": 0,
      // Integer
      "sgxtcbcomp02svn": 0,
      // Integer
      // ... (03 to 16)
      "pcesvn": 0
      // Integer
    },
    "tcm": "...",
    // String, Hex-encoded TCBm [cite: 63, 64]
    "cert": "..."
    // String, PEM-encoded certificate or "Not available" [cite: 64]
  }
]
```

**Example Response**

```json
[
  {
    "tcb": {
      "sgxtcbcomp01svn": 0,
      "sgxtcbcomp02svn": 0,
      "sgxtcbcomp03svn": 0,
      "sgxtcbcomp04svn": 0,
      "sgxtcbcomp05svn": 0,
      "sgxtcbcomp06svn": 0,
      "sgxtcbcomp07svn": 0,
      "sgxtcbcomp08svn": 0,
      "sgxtcbcomp09svn": 0,
      "sgxtcbcomp10svn": 0,
      "sgxtcbcomp11svn": 0,
      "sgxtcbcomp12svn": 0,
      "sgxtcbcomp13svn": 0,
      "sgxtcbcomp14svn": 0,
      "sgxtcbcomp15svn": 0,
      "sgxtcbcomp16svn": 0,
      "pcesvn": 0
    },
    "tcm": "...",
    "cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
  }
]
```

**Status Codes**

| Code | Model    | Headers                                                                                                                                                                                                                                       | Description                                                                                                            |
|:-----|:---------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-----------------------------------------------------------------------------------------------------------------------|
| 200  | PckCerts | Content-Type: `application/json`[cite: 65]. \<br\> Request-ID[cite: 65]. \<br\> SGX-PCK-Certificate-Issuer-Chain: Issuer chain[cite: 66]. \<br\> SGX-FMSPC[cite: 66]. \<br\> SGX-PCK-Certificate-CA-Type[cite: 66]. \<br\> Warning[cite: 66]. | Operation successful[cite: 65].                                                                                        |
| 400  |          | Request-ID[cite: 67]. \<br\> Warning[cite: 67].                                                                                                                                                                                               | Invalid request parameters[cite: 67].                                                                                  |
| 401  |          | Request-ID[cite: 68]. \<br\> Warning[cite: 68].                                                                                                                                                                                               | Failed to authenticate or authorize the request[cite: 68].                                                             |
| 404  |          | Request-ID[cite: 69]. \<br\> Warning[cite: 69].                                                                                                                                                                                               | PCK Certificate not found[cite: 69]. Reasons: PPID/PCE-ID not supported or Platform Manifest not registered[cite: 70]. |
| 500  |          | Request-ID[cite: 70]. \<br\> Warning[cite: 70].                                                                                                                                                                                               | Internal server error occurred[cite: 70].                                                                              |
| 503  |          | Request-ID[cite: 70]. \<br\> Warning[cite: 70].                                                                                                                                                                                               | Server is currently unable to process the request[cite: 70].                                                           |

-----

### Get Revocation List V3

Retrieves the X.509 Certificate Revocation List (CRL) for revoked SGX PCK Certificates[cite: 71]. CRLs are issued by
Intel SGX Processor CA or Platform CA[cite: 71].

#### GET `https://api.trustedservices.intel.com/sgx/certification/v3/pckcrl`

**Request**

| Name     | Type   | Request Type | Required | Pattern     | Description |
|:---------|:-------|:-------------|:---------|:------------|:------------|
| ca       | String | Query        | True     | `(processor | platform)`  | CA that issued the CRL[cite: 71]. |
| encoding | String | Query        | False    | `(pem       | der)`       | Encoding (Default: PEM)[cite: 71]. |

**Example Request**

```bash
curl -X GET "[https://api.trustedservices.intel.com/sgx/certification/v3/pckcrl?ca=platform&encoding=der](https://api.trustedservices.intel.com/sgx/certification/v3/pckcrl?ca=platform&encoding=der)"
```

**Response**

**Model**: PckCrl (X-PEM-FILE or PKIX-CRL) - PEM or DER-encoded CRL[cite: 71].

**Example Response**

```
-----BEGIN X509 CRL-----
...
-----END X509 CRL-----
```

**Status Codes**

| Code | Model  | Headers                                                                                                                                                                                                 | Description                                      |
|:-----|:-------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-------------------------------------------------|
| 200  | PckCrl | Content-Type: `application/x-pem-file` (PEM) or `application/pkix-crl` (DER)[cite: 72]. \<br\> Request-ID[cite: 72]. \<br\> SGX-PCK-CRL-Issuer-Chain: Issuer chain[cite: 72]. \<br\> Warning[cite: 72]. | Operation successful[cite: 72].                  |
| 400  |        | Request-ID[cite: 72]. \<br\> Warning[cite: 73].                                                                                                                                                         | Invalid request parameters[cite: 72].            |
| 401  |        | Request-ID[cite: 73]. \<br\> Warning[cite: 73].                                                                                                                                                         | Failed to authenticate or authorize[cite: 73].   |
| 500  |        | Request-ID[cite: 73]. \<br\> Warning[cite: 73].                                                                                                                                                         | Internal server error occurred[cite: 73].        |
| 503  |        | Request-ID[cite: 73]. \<br\> Warning[cite: 73].                                                                                                                                                         | Server is currently unable to process[cite: 73]. |

-----

### Get TCB Info V3

Retrieves SGX TCB information for a given FMSPC[cite: 74].

**Algorithm for TCB Status:**

1. Retrieve FMSPC from the SGX PCK Certificate[cite: 74].
2. Retrieve TCB Info matching the FMSPC[cite: 75].
3. Iterate through the sorted TCB Levels[cite: 75]:
    * Compare all SGX TCB Comp SVNs (01-16) from the certificate with TCB Level values[cite: 76]. If all are \>=,
      proceed[cite: 76]. Otherwise, move to the next item[cite: 76].
    * Compare PCESVN from the certificate with the TCB Level value[cite: 77]. If \>=, read the status[cite: 77].
      Otherwise, move to the next item[cite: 78].
4. If no match is found, the TCB Level is not supported[cite: 78].

#### GET `https://api.trustedservices.intel.com/sgx/certification/v3/tcb`

**Request**

| Name                    | Type   | Request Type | Required | Pattern            | Description                                                                                                                                                    |
|:------------------------|:-------|:-------------|:---------|:-------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| fmspc                   | String | Query        | True     | `[0-9a-fA-F]{12}$` | Base16-encoded FMSPC (6 bytes)[cite: 81].                                                                                                                      |
| update                  | String | Query        | False    | `(early            | standard)`                                                                                                                                                     | Update type (Default: standard). 'early' provides early access, 'standard' provides standard access[cite: 81]. Cannot be used with `tcbEvaluationDataNumber`[cite: 81]. |
| tcbEvaluationDataNumber | Number | Query        | False    | `\d+$`             | Specifies a TCB Evaluation Data Number. Allows fetching specific versions; returns 410 if \< M, 404 if \> N[cite: 81]. Cannot be used with `update`[cite: 81]. |

**Example Requests**

```bash
curl -X GET "[https://api.trustedservices.intel.com/sgx/certification/v3/tcb?fmspc=...&update=early](https://api.trustedservices.intel.com/sgx/certification/v3/tcb?fmspc=...&update=early)"
curl -X GET "[https://api.trustedservices.intel.com/sgx/certification/v3/tcb?fmspc=...&tcbEvaluationDataNumber=](https://api.trustedservices.intel.com/sgx/certification/v3/tcb?fmspc=...&tcbEvaluationDataNumber=)..."
```

**Response**

**Model**: TcbInfoV2 (JSON) - SGX TCB Info[cite: 82].

**TcbInfoV2 Structure**

* `version`: Integer[cite: 83].
* `issueDate`: String (date-time, ISO 8601 UTC)[cite: 84].
* `nextUpdate`: String (date-time, ISO 8601 UTC)[cite: 85].
* `fmspc`: String (Base16-encoded FMSPC)[cite: 85].
* `pceId`: String (Base16-encoded PCE-ID)[cite: 85].
* `tcbType`: Integer[cite: 85].
* `tcbEvaluationDataNumber`: Integer, monotonically increasing sequence number for TCB evaluation data set
  updates[cite: 86]. Synchronized across TCB Info and Identities[cite: 86]. Helps determine which data supersedes
  another[cite: 87].
* `tcbLevels`: Array of TCB level objects[cite: 87].
    * `tcb`: Object with `sgxtcbcompXXsvn` (Integer) and `pcesvn` (Integer)[cite: 87].
    * `tcbDate`: String (date-time, ISO 8601 UTC)[cite: 89]. If advisories exist after this date with enforced
      mitigations, status won't be `UpToDate`[cite: 88].
    * `tcbStatus`: String (`UpToDate`, `HardeningNeeded`, `ConfigurationNeeded`, `ConfigurationAndHardeningNeeded`,
      `OutOfDate`, `OutOfDateConfigurationNeeded`, `Revoked`)[cite: 90, 91, 92].
    * `advisoryIDs`: Array of strings (e.g., `INTEL-SA-XXXXX`, `INTEL-DOC-XXXXX`)[cite: 93, 94].
* `signature`: String (Base16 encoded)[cite: 94].

**Example Response**

```json
{
  "tcbInfo": {
    "version": 2,
    "issueDate": "2018-07-30T12:00:00Z",
    "nextUpdate": "2018-08-30T12:00:00Z",
    "fmspc": "...",
    "pceId": "0000",
    "tcbType": 1,
    "tcbEvaluationDataNumber": 7,
    "tcbLevels": [
      {
        "tcb": {
          "sgxtcbcomp01svn": 0,
          /* ... */
          "pcesvn": 0
        },
        "tcbDate": "2018-07-11T12:00:00Z",
        "tcbStatus": "UpToDate",
        "advisoryIDs": [
          "INTEL-SA-00070",
          "INTEL-SA-00076"
        ]
      }
    ]
  },
  "signature": "..."
}
```

**Status Codes**

| Code | Model     | Headers                                                                                                                                                      | Description                                                                              |
|:-----|:----------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------|:-----------------------------------------------------------------------------------------|
| 200  | TcbInfoV2 | Content-Type: `application/json`[cite: 96]. \<br\> Request-ID[cite: 96]. \<br\> SGX-TCB-Info-Issuer-Chain: Issuer chain[cite: 96]. \<br\> Warning[cite: 96]. | Operation successful[cite: 96].                                                          |
| 400  |           | Request-ID[cite: 96]. \<br\> Warning[cite: 96].                                                                                                              | Invalid request (bad FMSPC or conflicting `update`/`tcbEvaluationDataNumber`)[cite: 96]. |
| 401  |           | Request-ID[cite: 96]. \<br\> Warning[cite: 96].                                                                                                              | Failed to authenticate or authorize[cite: 96].                                           |
| 404  |           | Request-ID[cite: 96]. \<br\> Warning[cite: 96].                                                                                                              | TCB info not found for FMSPC or `tcbEvaluationDataNumber`[cite: 96].                     |
| 410  |           | Request-ID[cite: 98]. \<br\> Warning[cite: 98].                                                                                                              | TCB Information for `tcbEvaluationDataNumber` no longer available[cite: 98].             |
| 500  |           | Request-ID[cite: 98]. \<br\> Warning[cite: 98].                                                                                                              | Internal server error[cite: 98].                                                         |
| 503  |           | Request-ID[cite: 98]. \<br\> Warning[cite: 98].                                                                                                              | Server unable to process[cite: 98].                                                      |

-----

### Get Quoting Enclave Identity V3

Verifies if an SGX Enclave Report matches a valid Quoting Enclave (QE) identity[cite: 99].

**Algorithm:**

1. Retrieve and validate QE Identity[cite: 99].
2. Compare SGX Enclave Report against QE Identity:
    * Verify `MRSIGNER` equals `mrsigner`[cite: 100].
    * Verify `ISVPRODID` equals `isvprodid`[cite: 101].
    * Verify `(miscselectMask & MISCSELECT)` equals `miscselect`[cite: 102].
    * Verify `(attributesMask & ATTRIBUTES)` equals `attributes`[cite: 103, 104].
3. If any check fails, identity doesn't match[cite: 105].
4. Determine TCB status:
    * Retrieve TCB Levels[cite: 106].
    * Find TCB Level with ISVSVN \<= Enclave Report ISVSVN (descending)[cite: 107].
    * Read `tcbStatus`; if not found, it's unsupported[cite: 108].

#### GET `https://api.trustedservices.intel.com/sgx/certification/v3/qe/identity`

**Request**

| Name                    | Type   | Type  | Required | Pattern | Description                                                                               |
|:------------------------|:-------|:------|:---------|:--------|:------------------------------------------------------------------------------------------|
| update                  | String | Query | False    | `(early | standard)`                                                                                | Update type (Default: standard)[cite: 110]. Cannot be used with `tcbEvaluationDataNumber`[cite: 110]. |
| tcbEvaluationDataNumber | Number | Query | False    | `\d+`   | Specifies TCB Evaluation Data Number[cite: 110]. Cannot be used with `update`[cite: 110]. |

**Example Requests**

```bash
curl -X GET "[https://api.trustedservices.intel.com/sgx/certification/v3/qe/identity?update=early](https://api.trustedservices.intel.com/sgx/certification/v3/qe/identity?update=early)"
curl -X GET "[https://api.trustedservices.intel.com/sgx/certification/v3/qe/identity?tcbEvaluationDataNumber=](https://api.trustedservices.intel.com/sgx/certification/v3/qe/identity?tcbEvaluationDataNumber=)..."
```

**Response**

**Model**: QEIdentityV2 (JSON) - QE Identity data[cite: 111].

**QEIdentityV2 Structure**

* `enclaveIdentity`:
    * `id`: String (`QE`, `QVE`, or `QAE`)[cite: 113].
    * `version`: Integer[cite: 113].
    * `issueDate`, `nextUpdate`: String (date-time, ISO 8601 UTC)[cite: 114].
    * `tcbEvaluationDataNumber`: Integer[cite: 115].
    * `miscselect`, `miscselectMask`: String (Base16-encoded)[cite: 115, 116].
    * `attributes`, `attributesMask`: String (Base16-encoded)[cite: 116].
    * `mrsigner`: String (Base16-encoded)[cite: 116].
    * `isvprodid`: Integer[cite: 116].
    * `tcbLevels`: Array of TCB level objects[cite: 116].
        * `tcb`: Object with `isvsvn` (Integer)[cite: 117].
        * `tcbDate`: String (date-time, ISO 8601 UTC)[cite: 117].
        * `tcbStatus`: String (`UpToDate`, `OutOfDate`, `Revoked`)[cite: 119].
        * `advisoryIDs`: Array of strings[cite: 119].
* `signature`: String (Hex-encoded)[cite: 119].

**Status Codes**

| Code | Model        | Headers                                                                                                                                                                  | Description                                                                                     |
|:-----|:-------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:------------------------------------------------------------------------------------------------|
| 200  | QEIdentityV2 | Content-Type: `application/json`[cite: 122]. \<br\> Request-ID[cite: 122]. \<br\> SGX-Enclave-Identity-Issuer-Chain: Issuer chain[cite: 122]. \<br\> Warning[cite: 122]. | Operation successful[cite: 122].                                                                |
| 400  |              | Request-ID[cite: 122]. \<br\> Warning[cite: 123].                                                                                                                        | Invalid request (bad params or conflicting `update`/`tcbEvaluationDataNumber`)[cite: 122, 124]. |
| 401  |              | Request-ID[cite: 123]. \<br\> Warning[cite: 123].                                                                                                                        | Failed to authenticate or authorize[cite: 123].                                                 |
| 404  |              | Request-ID[cite: 123]. \<br\> Warning[cite: 123].                                                                                                                        | QE identity not found for `tcbEvaluationDataNumber`[cite: 124].                                 |
| 410  |              | Request-ID[cite: 124]. \<br\> Warning[cite: 124].                                                                                                                        | QEIdentity for `tcbEvaluationDataNumber` no longer available[cite: 124].                        |
| 500  |              | Request-ID[cite: 125]. \<br\> Warning[cite: 125].                                                                                                                        | Internal server error[cite: 125].                                                               |
| 503  |              | Request-ID[cite: 125]. \<br\> Warning[cite: 125].                                                                                                                        | Server unable to process[cite: 125].                                                            |

-----

### Get Quote Verification Enclave Identity V3

Verifies if an SGX Enclave Report matches a valid QVE identity[cite: 126].

**Algorithm:**

1. Retrieve and validate QVE Identity[cite: 126].
2. Compare Enclave Report: `MRSIGNER`[cite: 127], `ISVPRODID`[cite: 128], `MISCSELECT` (with mask)[cite: 128],
   `ATTRIBUTES` (with mask)[cite: 128].
3. If any fails, no match[cite: 129].
4. Determine TCB status via ISVSVN comparison[cite: 129, 130].

#### GET `https://api.trustedservices.intel.com/sgx/certification/v3/qve/identity`

**Request**: Same parameters as `Get Quoting Enclave Identity V3` (`update` and `tcbEvaluationDataNumber`)[cite: 132].

**Response**: QVEIdentityV2 (JSON) - QVE Identity data[cite: 133]. Structure similar to QE
Identity[cite: 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144].

**Status Codes**: Similar to `Get Quoting Enclave Identity V3`[cite: 145].

-----

### Get Quote Appraisal Enclave Identity V3

Verifies if an SGX Enclave Report matches a valid QAE identity[cite: 149].

**Algorithm:**

1. Retrieve and validate QAE Identity[cite: 149].
2. Compare Enclave Report: `MRSIGNER`[cite: 151], `ISVPRODID`[cite: 151], `MISCSELECT` (with mask)[cite: 152, 153],
   `ATTRIBUTES` (with mask)[cite: 154, 155].
3. If any fails, no match[cite: 155].
4. Determine TCB status via ISVSVN comparison[cite: 157, 158].

#### GET `https://api.trustedservices.intel.com/sgx/certification/v3/qae/identity`

**Request**: Same parameters as `Get Quoting Enclave Identity V3` (`update` and `tcbEvaluationDataNumber`)[cite: 160].

**Response**: QAEIdentityV2 (JSON) - QAE Identity data[cite: 161]. Structure similar to QE
Identity[cite: 162, 163, 164, 165, 166, 167, 168, 169, 170].

**Status Codes**: Similar to `Get Quoting Enclave Identity V3`[cite: 171, 174].

-----

### PCK Certificate and CRL Specification

This document specifies the hierarchy and format of X.509 v3 certificates and v2 CRLs for Provisioning Certification
Keys[cite: 175].

Enforcement of a mitigation means the attestation process can detect its presence and the result will differ[cite: 175].
Intel offers `standard` (default) and `early` update parameters, affecting when enforcement occurs[cite: 176]. The
attestation result is an objective assessment[cite: 177]. Relying parties can use additional factors [cite: 178] and may
choose to trust an 'OutOfDate' platform, accepting risks[cite: 180]. Intel will strive to communicate schedule
deviations[cite: 181].

