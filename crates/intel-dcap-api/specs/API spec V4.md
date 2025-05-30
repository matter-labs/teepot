This document outlines the API for Intel® SGX and Intel® TDX services, focusing on platform registration and
provisioning certification using ECDSA attestation.

## Intel® SGX and Intel® TDX Registration Service for Scalable Platforms [cite: 1]

The Intel® SGX and Intel® TDX Registration Service API enables the registration of Intel® SGX platforms with multiple
processor packages as a unified platform instance[cite: 2]. This allows these platforms to be remotely attested as a
single entity[cite: 2]. It is important to note that the service enforces a minimum TLS protocol version of 1.2; any
attempts to connect with older TLS/SSL versions will be rejected[cite: 3].

### Register Platform

This API facilitates the registration of multi-package SGX platforms, encompassing both initial registration and TCB (
Trusted Computing Base) recovery[cite: 4]. During this process, the Registration Service authenticates the platform
manifest to confirm it originates from a genuine, non-revoked SGX platform[cite: 4]. If the platform configuration
passes verification, its provisioning root keys are securely stored[cite: 4]. These stored keys are subsequently used to
derive the public components of Provisioning Certification Keys (PCKs), which are then distributed as X.509 certificates
by the Provisioning Certification Service[cite: 5]. These PCK certificates are integral to the remote attestation
process for the platform[cite: 5].

**POST** `https://api.trustedservices.intel.com/sgx/registration/v1/platform`

**Request**

* **Headers**: In addition to standard HTTP headers (like `Content-Length`), the following is required[cite: 1]:

| Name         | Required | Value                    | Description                             |
|:-------------|:---------|:-------------------------|:----------------------------------------|
| Content-Type | True     | application/octet-stream | MIME type of the request body[cite: 1]. |

* **Body**: The request body must be a binary representation of the Platform Manifest structure[cite: 6]. This is an
  opaque blob containing the registration manifest for a multi-package platform[cite: 6]. It includes the platform
  provisioning root keys established by the platform instance and the necessary data to authenticate it as a genuine,
  non-revoked SGX platform[cite: 6].

* **Example Request**:
    ```bash
    curl -v -X POST "Content-Type: application/octet-stream" --data-binary @platform_manifest.bin "https://api.trustedservices.intel.com/sgx/registration/v1/platform" [cite: 1]
    ```

**Response**

* **Model**: The response body will contain the hex-encoded representation of the PPID (Platform Provisioning ID) for
  the registered platform instance, but only if the HTTP Status Code is 201[cite: 1]. Otherwise, the body will be
  empty[cite: 1].

* **Example Response**:
    ```
    00112233445566778899AABBCCDDEEFF [cite: 1]
    ```

* **Status Codes**:

| Code | Headers                                                                                                                                                                                                                                                                                                       | Body             | Description                                                                                       |
|:-----|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-----------------|:--------------------------------------------------------------------------------------------------|
| 201  | `Request-ID`: Randomly generated identifier for troubleshooting[cite: 7].                                                                                                                                                                                                                                     | Hex-encoded PPID | Operation successful; a new platform instance has been registered[cite: 7].                       |
| 400  | `Request-ID`: Randomly generated identifier[cite: 8]. `Error-Code` & `Error-Message`: Details on the error (e.g., `InvalidRequestSyntax`, `InvalidRegistrationServer`, `InvalidOrRevokedPackage`, `PackageNotFound`, `IncompatiblePackage`, `InvalidPlatformManifest`, `CachedKeysPolicyViolation`)[cite: 8]. |                  | Invalid Platform Manifest[cite: 10]. The client should not retry without modifications[cite: 10]. |
| 415  | `Request-ID`: Randomly generated identifier[cite: 8].                                                                                                                                                                                                                                                         |                  | The MIME type specified in the request is not supported[cite: 8].                                 |
| 500  | `Request-ID`: Randomly generated identifier[cite: 8].                                                                                                                                                                                                                                                         |                  | An internal server error occurred[cite: 8].                                                       |
| 503  | `Request-ID`: Randomly generated identifier[cite: 8].                                                                                                                                                                                                                                                         |                  | The server is currently unable to process the request; try again later[cite: 8].                  |

### Add Package

This API allows for adding new processor packages to an already registered platform instance[cite: 11]. Upon successful
execution, a Platform Membership Certificate is generated for each processor package included in the Add
Request[cite: 11]. This requires a subscription for registration[cite: 11].

**POST** `https://api.trustedservices.intel.com/sgx/registration/v1/package`

**Request**

* **Headers**: Besides standard headers like `Content-Length`[cite: 12], the following are needed:

| Name                      | Required | Value                    | Description                                                       |
|:--------------------------|:---------|:-------------------------|:------------------------------------------------------------------|
| Ocp-Apim-Subscription-Key | True     | *Your Subscription Key*  | Subscription key for API access, found in your profile[cite: 12]. |
| Content-Type              | True     | application/octet-stream | MIME type of the request body[cite: 12].                          |

* **Body**: A binary representation of the Add Request structure, an opaque blob for adding new packages to an existing
  platform[cite: 13].

* **Example Request**:
    ```bash
    curl -v -X POST "Content-Type: application/octet-stream" --data-binary @add_package_request.bin "https://api.trustedservices.intel.com/sgx/registration/v1/package" -H "Ocp-Apim-Subscription-Key: {subscription_key}" [cite: 14]
    ```

**Response**

* **Model**: For a 200 HTTP Status Code, the response is a fixed-size array (8 elements) containing binary Platform
  Membership Certificate structures appended together[cite: 14]. Certificates fill the array sequentially, starting from
  index 0, with remaining elements zeroed out[cite: 14].

* **Example Response (hex-encoded)**:
    ```
    E8BDBECFEF9040184488777267355084...00000000 [cite: 15]
    ```

* **Status Codes**:

| Code | Headers                                                                                                                                                                                                                                                | Body                                                                                      | Description                                                                          |
|:-----|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:------------------------------------------------------------------------------------------|:-------------------------------------------------------------------------------------|
| 200  | `Content-Type`: application/octet-stream[cite: 18]. `Request-ID`: Randomly generated identifier[cite: 18]. `Certificate-Count`: Number of certificates returned[cite: 18].                                                                             | Fixed-size array (8 elements) with binary Platform Membership Certificates[cite: 18, 19]. | Operation successful; packages added to the platform[cite: 18].                      |
| 400  | `Request-ID`: Randomly generated identifier[cite: 18]. `Error-Code` & `Error-Message`: Details on the error (e.g., `InvalidRequestSyntax`, `PlatformNotFound`, `InvalidOrRevokedPackage`, `PackageNotFound`[cite: 17], `InvalidAddRequest`)[cite: 18]. |                                                                                           | Invalid Add Request Payload[cite: 20]. Do not retry without modifications[cite: 20]. |
| 401  | `Request-ID`: Randomly generated identifier[cite: 18].                                                                                                                                                                                                 |                                                                                           | Failed to authenticate or authorize the request[cite: 18].                           |
| 415  | `Request-ID`: Randomly generated identifier[cite: 18].                                                                                                                                                                                                 |                                                                                           | The MIME type specified is not supported[cite: 18].                                  |
| 500  | `Request-ID`: Randomly generated identifier[cite: 18].                                                                                                                                                                                                 |                                                                                           | Internal server error occurred[cite: 18].                                            |
| 503  | `Request-ID`: Randomly generated identifier[cite: 18].                                                                                                                                                                                                 |                                                                                           | Server is currently unable to process the request[cite: 18].                         |

## Intel® SGX and Intel® TDX Provisioning Certification Service for ECDSA Attestation [cite: 21]

This service provides PCK certificates. You can download the Provisioning Certification Root CA Certificate (v4) in both
DER and PEM formats[cite: 21].

### Get/Post PCK Certificate V4

This API allows requesting a single PCK certificate. It offers two primary methods:

1. **Using PPID and SVNs**:
    * **Single-socket platforms**: No prerequisites[cite: 22].
    * **Multi-socket platforms**: Requires prior platform registration via the Register Platform API[cite: 22]. This
      flow necessitates that platform root keys are persistently stored in the backend[cite: 23], and the Keys Caching
      Policy must be `true`[cite: 23].
2. **Using Platform Manifest and SVNs**:
    * **Multi-socket platforms**: Does *not* require prior registration[cite: 24]. Platform root keys are *not* required
      to be persistently stored[cite: 24]. The Keys Caching Policy determines whether keys are stored or not[cite: 25].
        * **Direct Registration (via Register Platform API)**: Keys are always stored; `CachedKeys` flag in PCK
          certificates is `true`[cite: 26, 27].
        * **Indirect Registration (via Get PCK Certificate(s) API)**: Keys are never stored; `CachedKeys` flag is
          `false`[cite: 28, 30]. Register Platform API cannot be used afterward[cite: 29].

**Note**: The PCS returns the PCK Certificate representing the highest TCB security level based on the CPUSVN and PCE
ISVSVN inputs[cite: 31].

**GET** `https://api.trustedservices.intel.com/sgx/certification/v4/pckcert`

* **Request**:

| Name                      | Type   | Request Type | Required | Pattern            | Description                                                   |
|:--------------------------|:-------|:-------------|:---------|:-------------------|:--------------------------------------------------------------|
| Ocp-Apim-Subscription-Key | String | Header       | False    |                    | Subscription key[cite: 32].                                   |
| PPID-Encryption-Key       | String | Header       | False    |                    | Key type for PPID encryption (default: "RSA-3072")[cite: 32]. |
| encrypted_ppid            | String | Query        | True     | `[0-9a-fA-F]{768}` | Base16-encoded encrypted PPID[cite: 32].                      |
| cpusvn                    | String | Query        | True     | `[0-9a-fA-F]{32}`  | Base16-encoded CPUSVN[cite: 32].                              |
| pcesvn                    | String | Query        | True     | `[0-9a-fA-F]{4}`   | Base16-encoded PCESVN (little endian)[cite: 32].              |
| pceid                     | String | Query        | True     | `[0-9a-fA-F]{4}`   | Base16-encoded PCE-ID (little endian)[cite: 32].              |

* **Example Request**:
    ```bash
    curl -v -X GET "https://api.trustedservices.intel.com/sgx/certification/v4/pckcert?encrypted_ppid={encrypted_ppid}&cpusvn={cpusvn}&pcesvn={pcesvn}&pceid={pceid}" -H "Ocp-Apim-Subscription-Key: {subscription_key}" [cite: 33]
    ```

**POST** `https://api.trustedservices.intel.com/sgx/certification/v4/pckcert`

* **Request**:

| Name                      | Type   | Request Type | Required | Pattern                     | Description                                      |
|:--------------------------|:-------|:-------------|:---------|:----------------------------|:-------------------------------------------------|
| Ocp-Apim-Subscription-Key | String | Header       | False    |                             | Subscription key[cite: 33].                      |
| Content-Type              | String | Header       | True     | `application/json`          | Content type[cite: 35].                          |
| platformManifest          | String | Body Field   | True     | `[0-9a-fA-F]{16862,112884}` | Base16-encoded Platform Manifest[cite: 35].      |
| cpusvn                    | String | Body Field   | True     | `[0-9a-fA-F]{32}`           | Base16-encoded CPUSVN[cite: 35].                 |
| pcesvn                    | String | Body Field   | True     | `[0-9a-fA-F]{4}`            | Base16-encoded PCESVN (little endian)[cite: 35]. |
| pceid                     | String | Body Field   | True     | `[0-9a-fA-F]{4}`            | Base16-encoded PCE-ID (little endian)[cite: 35]. |

* **Body**:
    ```json
    {
        "platformManifest": "...", [cite: 36]
        "cpusvn": "...", [cite: 36]
        "pcesvn": "...", [cite: 36]
        "pceid": "..." [cite: 36]
    }
    ```

* **Example Request**:
    ```bash
    curl -v -X POST --data '{"platformManifest":"...","cpusvn":"...","pcesvn":"...","pceid":"..."}' "https://api.trustedservices.intel.com/sgx/certification/v4/pckcert" -H "Ocp-Apim-Subscription-Key: {subscription_key}" -H "Content-Type: application/json" [cite: 36]
    ```

**Response (Both GET & POST)**

* **Model**: `PckCert (X-PEM-FILE)` - PEM-encoded SGX PCK Certificate[cite: 36].
* **Example Response**:
    ```pem
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE----- [cite: 36]
    ```
* **Status Codes**:

| Code | Model   | Headers                                                                                                                                                                                                                                                                                                                                                        | Description                                                                                                                       |
|:-----|:--------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:----------------------------------------------------------------------------------------------------------------------------------|
| 200  | PckCert | `Content-Type`: application/x-pem-file[cite: 37]. `Request-ID`: Identifier[cite: 37]. `SGX-PCK-Certificate-Issuer-Chain`: PEM-encoded Issuer Chain[cite: 37]. `SGX-TCBm`: Hex-encoded CPUSVN & PCESVN[cite: 37]. `SGX-FMSPC`: Hex-encoded FMSPC[cite: 37]. `SGX-PCK-Certificate-CA-Type`: "processor" or "platform"[cite: 37]. `Warning` (Optional)[cite: 37]. | Operation successful[cite: 37].                                                                                                   |
| 400  |         | `Request-ID`: Identifier[cite: 37]. `Warning` (Optional)[cite: 37]. `Error-Code` & `Error-Message` (e.g., `InvalidRequestSyntax`, `InvalidRegistrationServer`, `InvalidOrRevokedPackage`, `PackageNotFound`, `IncompatiblePackage`, `InvalidPlatformManifest`)[cite: 37].                                                                                      | Invalid request parameters[cite: 37].                                                                                             |
| 401  |         | `Request-ID`: Identifier[cite: 37]. `Warning` (Optional)[cite: 37].                                                                                                                                                                                                                                                                                            | Failed to authenticate or authorize[cite: 37].                                                                                    |
| 404  |         | `Request-ID`: Identifier[cite: 37]. `Warning` (Optional)[cite: 37].                                                                                                                                                                                                                                                                                            | PCK Certificate not found (e.g., unsupported PPID/PCE-ID, TCB below minimum, Platform Manifest not registered/updated)[cite: 37]. |
| 429  |         | `Retry-After`: Wait time in seconds[cite: 37]. `Warning` (Optional)[cite: 37].                                                                                                                                                                                                                                                                                 | Too many requests[cite: 37].                                                                                                      |
| 500  |         | `Request-ID`: Identifier[cite: 37]. `Warning` (Optional)[cite: 37].                                                                                                                                                                                                                                                                                            | Internal server error[cite: 37].                                                                                                  |
| 503  |         | `Request-ID`: Identifier[cite: 39]. `Warning` (Optional)[cite: 39].                                                                                                                                                                                                                                                                                            | Server is currently unable to process[cite: 39].                                                                                  |

### Get PCK Certificates V4

This API retrieves PCK certificates for *all* configured TCB levels for a platform. The usage conditions (single-socket
vs. multi-socket, PPID vs. Platform Manifest, key caching) are similar to the single PCK certificate
API[cite: 40, 41, 42, 43, 44, 45, 46, 47, 48].

**GET** `https://api.trustedservices.intel.com/sgx/certification/v4/pckcerts` (Using PPID & PCE-ID)

* **Request**:

| Name                      | Type   | Request Type | Required | Pattern            | Description                               |
|:--------------------------|:-------|:-------------|:---------|:-------------------|:------------------------------------------|
| Ocp-Apim-Subscription-Key | String | Header       | False    |                    | Subscription key[cite: 49].               |
| PPID-Encryption-Key       | String | Header       | False    |                    | Key type (default: "RSA-3072")[cite: 49]. |
| encrypted_ppid            | String | Query        | True     | `[0-9a-fA-F]{768}` | Encrypted PPID[cite: 49].                 |
| pceid                     | String | Query        | True     | `[0-9a-fA-F]{4}`   | PCE-ID[cite: 49].                         |

* **Example Request**:
    ```bash
    curl -v -X GET "https://api.trustedservices.intel.com/sgx/certification/v4/pckcerts?encrypted_ppid={...}&pceid={...}" -H "Ocp-Apim-Subscription-Key: {subscription_key}" [cite: 50]
    ```

**GET** `https://api.trustedservices.intel.com/sgx/certification/v4/pckcerts/config` (Using PPID, PCE-ID &
CPUSVN) [cite: 51]

* **Request**:

| Name                      | Type   | Request Type | Required | Pattern            | Description                               |
|:--------------------------|:-------|:-------------|:---------|:-------------------|:------------------------------------------|
| Ocp-Apim-Subscription-Key | String | Header       | False    |                    | Subscription key[cite: 52].               |
| PPID-Encryption-Key       | String | Header       | False    |                    | Key type (default: "RSA-3072")[cite: 52]. |
| encrypted_ppid            | String | Query        | True     | `[0-9a-fA-F]{768}` | Encrypted PPID[cite: 52].                 |
| pceid                     | String | Query        | True     | `[0-9a-fA-F]{4}`   | PCE-ID[cite: 52].                         |
| cpusvn                    | String | Query        | True     | `[0-9a-fA-F]{32}`  | CPUSVN[cite: 52].                         |

* **Example Request**:
    ```bash
    curl -v -X GET "https://api.trustedservices.intel.com/sgx/certification/v4/pckcerts/config?encrypted_ppid={...}&pceid={...}&cpusvn={...}" -H "Ocp-Apim-Subscription-Key: {subscription_key}" [cite: 53]
    ```

**POST** `https://api.trustedservices.intel.com/sgx/certification/v4/pckcerts` (Using Platform Manifest & PCE-ID)

* **Request**:

| Name                      | Type   | Request Type | Required | Pattern                     | Description                  |
|:--------------------------|:-------|:-------------|:---------|:----------------------------|:-----------------------------|
| Ocp-Apim-Subscription-Key | String | Header       | False    |                             | Subscription key[cite: 54].  |
| Content-Type              | String | Header       | True     | `application/json`          | Content type[cite: 54].      |
| platformManifest          | String | Body Field   | True     | `[0-9a-fA-F]{16862,112884}` | Platform Manifest[cite: 54]. |
| pceid                     | String | Body Field   | True     | `[0-9a-fA-F]{4}`            | PCE-ID[cite: 54].            |

* **Body**:
    ```json
    {
        "platformManifest": "...", [cite: 55]
        "pceid": "..." [cite: 55]
    }
    ```
* **Example Request**:
    ```bash
    curl -v -X POST --data '{"platformManifest":"...","pceid":"..."}' "https://api.trustedservices.intel.com/sgx/certification/v4/pckcerts" -H "Ocp-Apim-Subscription-Key: {subscription_key}" -H "Content-Type: application/json" [cite: 55]
    ```

**POST** `https://api.trustedservices.intel.com/sgx/certification/v4/pckcerts/config` (Using Platform Manifest, PCE-ID &
CPUSVN)

* **Request**:

| Name                      | Type   | Request Type | Required | Pattern                     | Description                  |
|:--------------------------|:-------|:-------------|:---------|:----------------------------|:-----------------------------|
| Ocp-Apim-Subscription-Key | String | Header       | False    |                             | Subscription key[cite: 56].  |
| Content-Type              | String | Header       | True     | `application/json`          | Content type[cite: 57].      |
| platformManifest          | String | Body Field   | True     | `[0-9a-fA-F]{16862,112884}` | Platform Manifest[cite: 56]. |
| cpusvn                    | String | Body Field   | True     | `[0-9a-fA-F]{32}`           | CPUSVN[cite: 56].            |
| pceid                     | String | Body Field   | True     | `[0-9a-fA-F]{4}`            | PCE-ID[cite: 56].            |

* **Body**:
    ```json
    {
        "platformManifest": "...", [cite: 57]
        "cpusvn": "...", [cite: 57]
        "pceid": "..." [cite: 57]
    }
    ```
* **Example Request**:
    ```bash
    curl -v -X POST --data '{"platformManifest":"...","cpusvn":"...","pceid":"..."}' "https://api.trustedservices.intel.com/sgx/certification/v4/pckcerts/config" -H "Ocp-Apim-Subscription-Key: {subscription_key}" -H "Content-Type: application/json" [cite: 57]
    ```

**Response (All GET & POST for multiple certs)**

* **Model**: `PckCerts` (JSONArray of objects, each containing `tcb`, `tcbm`, and `cert`)[cite: 56].
    * `tcb`: Object with 16 `sgxtcbcompXXsvn` fields (integer 0-255) and `pcesvn` (integer 0-65535)[cite: 59].
    * `tcbm`: Hex-encoded string of CPUSVN (16 bytes) and PCESVN (2 bytes)[cite: 7].
    * `cert`: URL-encoded PEM PCK Certificate, or "Not available" string[cite: 60].
* **Example Response**:
    ```json
    [
        {
            "tcb": {
                "sgxtcbcomp01svn": 3,
                "sgxtcbcomp02svn": 1,
                ...
                "pcesvn": 11
            },
            "tcbm": "...",
            "cert": "-----BEGIN%20CERTIFICATE-----%0A...%0A-----END%20CERTIFICATE-----" [cite: 61]
        },
        ...
    ]
    ```
* **Status Codes**:

| Code | Model    | Headers                                                                                                                                                                                                                                                                                                                   | Description                                                                                            |
|:-----|:---------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-------------------------------------------------------------------------------------------------------|
| 200  | PckCerts | `Content-Type`: application/json[cite: 8]. `Request-ID`: Identifier[cite: 8]. `SGX-PCK-Certificate-Issuer-Chain`: Issuer Chain[cite: 62]. `SGX-FMSPC`: FMSPC[cite: 8]. `SGX-PCK-Certificate-CA-Type`: "processor" or "platform"[cite: 63]. `Warning` (Optional)[cite: 8].                                                 | Operation successful[cite: 8].                                                                         |
| 400  |          | `Request-ID`: Identifier[cite: 8]. `Warning` (Optional)[cite: 8]. `Error-Code` & `Error-Message` (e.g., `InvalidRequestSyntax`[cite: 65], `InvalidRegistrationServer`[cite: 65], `InvalidOrRevokedPackage`[cite: 65], `PackageNotFound`[cite: 65], `IncompatiblePackage`[cite: 65], `InvalidPlatformManifest` [cite: 66]) | Invalid request parameters[cite: 8].                                                                   |
| 401  |          | `Request-ID`: Identifier[cite: 68]. `Warning` (Optional)[cite: 68].                                                                                                                                                                                                                                                       | Failed to authenticate or authorize[cite: 68].                                                         |
| 404  |          | `Request-ID`: Identifier[cite: 68]. `Warning` (Optional)[cite: 68].                                                                                                                                                                                                                                                       | PCK Certificate not found (e.g., unsupported PPID/PCE-ID, Platform Manifest not registered)[cite: 68]. |
| 429  |          | `Retry-After`: Wait time[cite: 68]. `Warning` (Optional)[cite: 68].                                                                                                                                                                                                                                                       | Too many requests[cite: 68].                                                                           |
| 500  |          | `Request-ID`: Identifier[cite: 68]. `Warning` (Optional)[cite: 68].                                                                                                                                                                                                                                                       | Internal server error[cite: 68].                                                                       |
| 503  |          | `Request-ID`: Identifier[cite: 68]. `Warning` (Optional)[cite: 68].                                                                                                                                                                                                                                                       | Server is currently unable to process[cite: 68].                                                       |

### Get Revocation List V4

This API retrieves the X.509 Certificate Revocation List (CRL) for revoked SGX PCK Certificates, issued by either the
Intel SGX Processor CA or Platform CA[cite: 69, 70].

**GET** `https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl` [cite: 71]

* **Request**:

| Name     | Type   | Request Type | Required | Pattern     | Description |
|:---------|:-------|:-------------|:---------|:------------|:------------|
| ca       | String | Query        | True     | `(processor | platform)`  | CA identifier ("processor" or "platform")[cite: 71, 72]. |
| encoding | String | Query        | False    | `(pem       | der)`       | CRL encoding (default: PEM)[cite: 71]. |

* **Example Request**:
    ```bash
    curl -v -X GET "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=pem" [cite: 71]
    ```

**Response**

* **Model**: `PckCrl` (X-PEM-FILE or PKIX-CRL) - PEM or DER encoded CRL[cite: 71].
* **Example Response**:
    ```pem
    -----BEGIN X509 CRL-----
    ...
    -----END X509 CRL----- [cite: 71]
    ```
* **Status Codes**:

| Code | Model  | Headers                                                                                                                                                                                               | Description                                      |
|:-----|:-------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-------------------------------------------------|
| 200  | PckCrl | `Content-Type`: "application/x-pem-file" or "application/pkix-crl"[cite: 71]. `Request-ID`: Identifier[cite: 71]. `SGX-PCK-CRL-Issuer-Chain`: Issuer Chain[cite: 73]. `Warning` (Optional)[cite: 71]. | Operation successful[cite: 71].                  |
| 400  |        | `Request-ID`: Identifier[cite: 71]. `Warning` (Optional)[cite: 71].                                                                                                                                   | Invalid request parameters[cite: 71].            |
| 401  |        | `Request-ID`: Identifier[cite: 74]. `Warning` (Optional)[cite: 74].                                                                                                                                   | Failed to authenticate or authorize[cite: 74].   |
| 500  |        | `Request-ID`: Identifier[cite: 74]. `Warning` (Optional)[cite: 74].                                                                                                                                   | Internal server error[cite: 74].                 |
| 503  |        | `Request-ID`: Identifier[cite: 74]. `Warning` (Optional)[cite: 74].                                                                                                                                   | Server is currently unable to process[cite: 74]. |

### Get SGX TCB Info V4

This API retrieves SGX TCB information for a specific FMSPC, which is crucial for determining the TCB status of a
platform[cite: 75]. The process involves:

1. Retrieving the FMSPC from the SGX PCK Certificate[cite: 75].
2. Fetching the corresponding SGX TCB info[cite: 76].
3. Iterating through the TCB Levels:
    * Comparing all 16 SGX TCB Comp SVNs from the certificate against the TCB Level; they must be >=[cite: 77, 78].
    * Comparing the PCESVN from the certificate against the TCB Level; it must be >=[cite: 79, 80]. If both match, the
      TCB level's status is found[cite: 80].
4. If no match is found, the TCB level is unsupported[cite: 82].

**GET** `https://api.trustedservices.intel.com/sgx/certification/v4/tcb` [cite: 82]

* **Request**:

| Name                    | Type   | Request Type | Required | Pattern           | Description                                                                                            |
|:------------------------|:-------|:-------------|:---------|:------------------|:-------------------------------------------------------------------------------------------------------|
| fmspc                   | String | Query        | True     | `[0-9a-fA-F]{12}` | Base16-encoded FMSPC[cite: 83].                                                                        |
| update                  | String | Query        | False    | `(early           | standard)`                                                                                             | TCB Info update type (default: standard). `early` provides access sooner than `standard`[cite: 83]. Cannot be used with `tcbEvaluationDataNumber`[cite: 83]. |
| tcbEvaluationDataNumber | Number | Query        | False    | `\d+`             | Retrieves TCB info for a specific evaluation number[cite: 83]. Cannot be used with `update`[cite: 83]. |

* **Example Requests**:
    ```bash
    curl -v -X GET "https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc={fmspc_value}&update=early" [cite: 84]
    curl -v -X GET "https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc={fmspc_value}&tcbEvaluationDataNumber={number}" [cite: 84]
    ```

**Response**

* **Model**: `Appendix A: TCB info V3`[cite: 86]. (See Appendix A below).
* **Example Response**: (JSON structure as shown in the document)[cite: 85].
* **Status Codes**:

| Code | Model     | Headers                                                                                                                                                          | Description                                                                                                     |
|:-----|:----------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------|:----------------------------------------------------------------------------------------------------------------|
| 200  | TcbInfoV3 | `Content-Type`: application/json[cite: 86]. `Request-ID`: Identifier[cite: 86]. `TCB-Info-Issuer-Chain`: Issuer Chain[cite: 86]. `Warning` (Optional)[cite: 86]. | Operation successful[cite: 86].                                                                                 |
| 400  |           | `Request-ID`: Identifier[cite: 86]. `Warning` (Optional)[cite: 86].                                                                                              | Invalid request (bad `fmspc`, invalid params, or `update` & `tcbEvaluationDataNumber` used together)[cite: 86]. |
| 401  |           | `Request-ID`: Identifier[cite: 86]. `Warning` (Optional)[cite: 87].                                                                                              | Failed to authenticate or authorize[cite: 86].                                                                  |
| 404  |           | `Request-ID`: Identifier[cite: 86]. `Warning` (Optional)[cite: 87].                                                                                              | TCB info not found for the given `fmspc` or `tcbEvaluationDataNumber`[cite: 86].                                |
| 410  |           | `Request-ID`: Identifier[cite: 88]. `Warning` (Optional)[cite: 88].                                                                                              | TCB info for the provided `tcbEvaluationDataNumber` is no longer available[cite: 88].                           |
| 500  |           | `Request-ID`: Identifier[cite: 88]. `Warning` (Optional)[cite: 88].                                                                                              | Internal server error[cite: 88].                                                                                |
| 503  |           | `Request-ID`: Identifier[cite: 88]. `Warning` (Optional)[cite: 88].                                                                                              | Server currently unable to process[cite: 88].                                                                   |

### Get TDX TCB Info V4

This API retrieves TDX TCB information[cite: 89]. The TCB status determination follows a similar process to SGX but
includes additional steps for TDX TEE TCB SVNs and TDX Module
Identity[cite: 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102].

**GET** `https://api.trustedservices.intel.com/tdx/certification/v4/tcb` [cite: 102]

* **Request**:

| Name                    | Type   | Request Type | Required | Pattern           | Description                                                                                              |
|:------------------------|:-------|:-------------|:---------|:------------------|:---------------------------------------------------------------------------------------------------------|
| fmspc                   | String | Query        | True     | `[0-9a-fA-F]{12}` | Base16-encoded FMSPC[cite: 103].                                                                         |
| update                  | String | Query        | False    | `(early           | standard)`                                                                                               | TCB Info update type (default: standard)[cite: 103]. Cannot be used with `tcbEvaluationDataNumber`[cite: 103]. |
| tcbEvaluationDataNumber | Number | Query        | False    | `\d+`             | Retrieves TCB info for a specific evaluation number[cite: 103]. Cannot be used with `update`[cite: 103]. |

* **Example Requests**:
    ```bash
    curl -v -X GET "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc={fmspc_value}&update=early" [cite: 104]
    curl -v -X GET "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc={fmspc_value}&tcbEvaluationDataNumber={number}" [cite: 104]
    ```

**Response**

* **Model**: `Appendix A: TCB info V3`[cite: 107]. (See Appendix A below).
* **Example Response**: (JSON structure including `tdxModule` and `tdxtcbcomponents` as shown in the
  document)[cite: 105, 106].
* **Status Codes**: Similar to Get SGX TCB Info V4[cite: 108].

### Enclave Identity V4

This set of APIs allows for determining if an SGX Enclave's identity matches Intel's published identity[cite: 109]. The
process involves:

1. Retrieving the Enclave Identity (SGX QE, TDX QE, QVE, or QAE)[cite: 109].
2. Comparing `MRSIGNER` and `ISVPRODID` fields[cite: 109].
3. Applying `miscselectMask` and `attributesMask` and comparing the results[cite: 111, 112, 113, 114].
4. If checks pass, determining the TCB status by finding the highest TCB Level (sorted by ISVSVN) whose ISVSVN is <= the
   Enclave Report's ISVSVN[cite: 116, 117].

**GET** `https://api.trustedservices.intel.com/sgx/certification/v4/qe/identity` [cite: 118]
**GET** `https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity` [cite: 128]
**GET** `https://api.trustedservices.intel.com/sgx/certification/v4/qve/identity` [cite: 133]
**GET** `https://api.trustedservices.intel.com/sgx/certification/v4/qae/identity` [cite: 138]

* **Request**:

| Name                    | Type   | Request Type | Required | Pattern | Description                                                                                                                                 |
|:------------------------|:-------|:-------------|:---------|:--------|:--------------------------------------------------------------------------------------------------------------------------------------------|
| update                  | String | Query        | False    | `(early | standard)`                                                                                                                                  | Identity update type (default: standard)[cite: 118, 127, 132, 137]. Cannot be used with `tcbEvaluationDataNumber`[cite: 118, 121, 127, 132, 137]. |
| tcbEvaluationDataNumber | Number | Query        | False    | `\d+`   | Retrieves Identity for a specific evaluation number[cite: 119, 120, 127, 132, 137]. Cannot be used with `update`[cite: 121, 127, 132, 137]. |

* **Example Requests** (SGX QE shown):
    ```bash
    curl -v -X GET "https://api.trustedservices.intel.com/sgx/certification/v4/qe/identity?update=early" [cite: 122]
    curl -v -X GET "https://api.trustedservices.intel.com/sgx/certification/v4/qe/identity?tcbEvaluationDataNumber={number}" [cite: 122]
    ```

**Response**

* **Model**: `Appendix B: Enclave Identity V2`[cite: 122, 128, 134, 139]. (See Appendix B below).
* **Example Response**: (JSON structure as shown in the document for QE[cite: 125], TDX QE[cite: 131], QVE[cite: 136],
  and QAE [cite: 141]).
* **Status Codes** (SGX QE shown, others are similar):

| Code | Model       | Headers                                                                                                                                                                          | Description                                                                           |
|:-----|:------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--------------------------------------------------------------------------------------|
| 200  | EIdentityV2 | `Content-Type`: application/json[cite: 122]. `Request-ID`: Identifier[cite: 122]. `SGX-Enclave-Identity-Issuer-Chain`: Issuer Chain[cite: 122]. `Warning` (Optional)[cite: 122]. | Operation successful[cite: 122].                                                      |
| 400  |             | `Request-ID`: Identifier[cite: 122]. `Warning` (Optional)[cite: 122].                                                                                                            | Invalid request (params or `update` & `tcbEvaluationDataNumber` conflict)[cite: 122]. |
| 401  |             | `Request-ID`: Identifier[cite: 123]. `Warning` (Optional)[cite: 123].                                                                                                            | Failed to authenticate or authorize[cite: 122].                                       |
| 404  |             | `Request-ID`: Identifier[cite: 123]. `Warning` (Optional)[cite: 123].                                                                                                            | Identity info not found[cite: 122].                                                   |
| 410  |             | `Request-ID`: Identifier[cite: 124]. `Warning` (Optional)[cite: 124].                                                                                                            | Identity info no longer available[cite: 124].                                         |
| 500  |             | `Request-ID`: Identifier[cite: 124]. `Warning` (Optional)[cite: 124].                                                                                                            | Internal server error[cite: 124].                                                     |
| 503  |             | `Request-ID`: Identifier[cite: 124]. `Warning` (Optional)[cite: 124].                                                                                                            | Server currently unable to process[cite: 124].                                        |

### Retrieve FMSPCs V4

Retrieves a list of FMSPC values for SGX and TDX platforms that support DCAP attestation[cite: 141].

**GET** `https://api.trustedservices.intel.com/sgx/certification/v4/fmspcs` [cite: 141]

* **Request**:

| Name     | Type   | Request Type | Required | Description                                                                 |
|:---------|:-------|:-------------|:---------|:----------------------------------------------------------------------------|
| platform | String | Query        | False    | Optional platform filter: `all` (default), `client`, `E3`, `E5`[cite: 141]. |

* **Example Request**:
    ```bash
    curl -v -X GET "https://api.trustedservices.intel.com/sgx/certification/v4/fmspcs?platform=E5" [cite: 141]
    ```

**Response**

* **Example Response**:
    ```json
    [
        {"platform": "E3", "fmspc": "123456789000"}, [cite: 142]
        {"platform": "E5", "fmspc": "987654321000"}, [cite: 142]
        {"platform": "client", "fmspc": "ABCDEF123456"} [cite: 142]
    ]
    ```
* **Status Codes**:

| Code | Headers                                                                                                            | Description                                    |
|:-----|:-------------------------------------------------------------------------------------------------------------------|:-----------------------------------------------|
| 200  | `Content-Type`: application/json[cite: 142]. `Request-ID`: Identifier[cite: 142]. `Warning` (Optional)[cite: 142]. | Operation successful[cite: 142].               |
| 400  | `Request-ID`: Identifier[cite: 142]. `Warning` (Optional)[cite: 143].                                              | Invalid request parameters[cite: 142].         |
| 500  | `Request-ID`: Identifier[cite: 142]. `Warning` (Optional)[cite: 142].                                              | Internal server error[cite: 142].              |
| 503  | `Request-ID`: Identifier[cite: 142]. `Warning` (Optional)[cite: 142].                                              | Server currently unable to process[cite: 142]. |

### Retrieve TCB Evaluation Data Numbers V4

Retrieves the list of currently supported TCB Evaluation Data Numbers and their associated TCB-R event
states[cite: 142].

**GET** `https://api.trustedservices.intel.com/{sgx|tdx}/certification/v4/tcbevaluationdatanumbers` [cite: 142]

* **Example Requests**:
    ```bash
    curl -v -X GET "https://api.trustedservices.intel.com/sgx/certification/v4/tcbevaluationdatanumbers" [cite: 142]
    curl -v -X GET "https://api.trustedservices.intel.com/tdx/certification/v4/tcbevaluationdatanumbers" [cite: 142]
    ```

**Response**

* **Model**: `Appendix C: TCB Evaluation Data Numbers V1`[cite: 144]. (See Appendix C below).
* **Example Response**:
    ```json
    {
        "tcbEvaluationDataNumbers": {
            "version": 1,
            "issueDate": "2023-04-13T09:38:17Z",
            "nextUpdate": "2023-05-13T09:38:17Z",
            "tcbNumbers": [
                {"tcbEvaluationDataNumber": 12, "tcbRecoveryEventDate": "2023-04-13T00:00:00Z", "tcbDate": "2023-04-13T00:00:00Z"},
                {"tcbEvaluationDataNumber": 11, "tcbRecoveryEventDate": "2023-01-14T00:00:00Z", "tcbDate": "2023-01-14T00:00:00Z"}
            ],
            "signature": "..." [cite: 142]
        }
    }
    ```
* **Status Codes**:

| Code | Headers                                                                                                                                                                                 | Description                                    |
|:-----|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-----------------------------------------------|
| 200  | `Content-Type`: application/json[cite: 144]. `Request-ID`: Identifier[cite: 144]. `TCB-Evaluation-Data-Numbers-Issuer-Chain`: Issuer Chain[cite: 145]. `Warning` (Optional)[cite: 144]. | Operation successful[cite: 144].               |
| 500  | `Request-ID`: Identifier[cite: 144]. `Warning` (Optional)[cite: 144].                                                                                                                   | Internal server error[cite: 144].              |
| 503  | `Request-ID`: Identifier[cite: 144]. `Warning` (Optional)[cite: 144].                                                                                                                   | Server currently unable to process[cite: 146]. |

---

## Appendix A: TCB Info V3 [cite: 147]

This defines the structure of the TCB Info V3 JSON response[cite: 147].

* `tcbInfo`: (Object)
    * `id`: (String) Identifier (e.g., "SGX", "TDX")[cite: 148].
    * `version`: (Integer) Structure version[cite: 148].
    * `issueDate`: (String - datetime) Creation timestamp (ISO 8601 UTC)[cite: 148].
    * `nextUpdate`: (String - datetime) Next update timestamp (ISO 8601 UTC)[cite: 149].
    * `fmspc`: (String) Base16-encoded FMSPC[cite: 149].
    * `pceId`: (String) Base16-encoded PCE ID[cite: 149].
    * `tcbType`: (Integer) TCB level composition type[cite: 149].
    * `tcbEvaluationDataNumber`: (Integer) Monotonically increasing sequence number, synchronized across TCB Info and
      Enclave Identities, indicating updates[cite: 150, 151, 152].
    * `tdxModule`: (Object - Optional, only for TDX TCB Info)[cite: 153].
        * `mrsigner`: (String) Base16-encoded TDX SEAM module's signer measurement[cite: 154].
        * `attributes`: (String) Base16-encoded "golden" attributes[cite: 154].
        * `attributesMask`: (String) Base16-encoded attributes mask[cite: 154].
        * `tdxModuleIdentities`: (Array - Optional, for multiple TDX SEAM Modules)[cite: 154].
            * `id`: (String) Module identifier[cite: 154].
            * `mrsigner`: (String) Base16-encoded signer measurement[cite: 155].
            * `attributes`: (String) Base16-encoded "golden" attributes[cite: 155].
            * `attributesMask`: (String) Base16-encoded attributes mask[cite: 156].
            * `tcbLevels`: (Array) Sorted list of TCB levels for this module[cite: 157].
                * `tcb`: (Object)
                    * `isvsvn`: (Integer) ISV SVN[cite: 157].
                    * `tcbDate`: (String - datetime) TCB date (ISO 8601 UTC)[cite: 158].
                    * `tcbStatus`: (String) "UpToDate", "OutOfDate", or "Revoked"[cite: 158].
                    * `advisoryIDs`: (Array - Optional) List of relevant `INTEL-SA-XXXXX` or `INTEL-DOC-XXXXX`
                      identifiers[cite: 159, 160].
    * `tcbLevels`: (Array) Sorted list of TCB levels for the FMSPC[cite: 160].
        * `tcb`: (Object)
            * `sgxtcbcomponents`: (Array - Optional) 16 SGX TCB Components (SVN, Category, Type)[cite: 161].
            * `tdxtcbcomponents`: (Array - Optional, only for TDX TCB Info) 16 TDX TCB Components (SVN, Category,
              Type)[cite: 161, 162, 164].
            * `pcesvn`: (Integer) PCE SVN[cite: 161].
            * `tcbDate`: (String - datetime) TCB date (ISO 8601 UTC)[cite: 165].
            * `tcbStatus`: (String) "UpToDate", "HardeningNeeded", "ConfigurationNeeded", "
              ConfigurationAndHardeningNeeded", "OutOfDate", "OutOfDateConfigurationNeeded", "Revoked"[cite: 165, 166].
            * `advisoryIDs`: (Array - Optional) List of relevant `INTEL-SA-XXXXX` or `INTEL-DOC-XXXXX`
              identifiers[cite: 167, 168].
    * `signature`: (String) Base16-encoded signature over the `tcbInfo` body[cite: 163].

---

## Appendix B: Enclave Identity V2 [cite: 168]

This defines the structure of the Enclave Identity V2 JSON response[cite: 168].

* `enclaveIdentity`: (Object)
    * `id`: (String) Identifier ("QE", "QVE", "QAE", "TD_QE")[cite: 169].
    * `version`: (Integer) Structure version[cite: 169].
    * `issueDate`: (String - datetime) Creation timestamp (ISO 8601 UTC)[cite: 170].
    * `nextUpdate`: (String - datetime) Next update timestamp (ISO 8601 UTC)[cite: 170].
    * `tcbEvaluationDataNumber`: (Integer) Monotonically increasing sequence number, synchronized across TCB Info and
      Enclave Identities[cite: 171, 172].
    * `miscselect`: (String) Base16-encoded "golden" miscselect value[cite: 172].
    * `miscselectMask`: (String) Base16-encoded miscselect mask[cite: 172].
    * `attributes`: (String) Base16-encoded "golden" attributes value[cite: 172].
    * `attributesMask`: (String) Base16-encoded attributes mask[cite: 173].
    * `mrsigner`: (String) Base16-encoded mrsigner hash[cite: 173].
    * `isvprodid`: (Integer) Enclave Product ID[cite: 173].
    * `tcbLevels`: (Array) Sorted list of Enclave TCB levels[cite: 173].
        * `tcb`: (Object)
            * `isvsvn`: (Integer) Enclave's ISV SVN[cite: 173].
            * `tcbDate`: (String - datetime) TCB date (ISO 8601 UTC)[cite: 174].
            * `tcbStatus`: (String) "UpToDate", "OutOfDate", or "Revoked"[cite: 174, 176].
            * `advisoryIDs`: (Array - Optional) List of relevant `INTEL-SA-XXXXX` or `INTEL-DOC-XXXXX`
              identifiers[cite: 177].
    * `signature`: (String) Base16-encoded signature over the `enclaveIdentity` body[cite: 175].

---

## Appendix C: TCB Evaluation Data Numbers V1 [cite: 177]

This defines the structure of the TCB Evaluation Data Numbers V1 JSON response[cite: 177].

* `tcbEvaluationDataNumbers`: (Object)
    * `id`: (String) Identifier ("SGX" or "TDX")[cite: 178].
    * `version`: (Integer) Structure version[cite: 178].
    * `issueDate`: (String - datetime) Creation timestamp (ISO 8601 UTC)[cite: 178].
    * `nextUpdate`: (String - datetime) Suggested next call timestamp (ISO 8601 UTC)[cite: 179].
    * `tcbNumbers`: (Array) List of TCB Evaluation Data Number objects[cite: 179].
        * `tcbEvaluationDataNumber`: (Integer) The number itself[cite: 179].
        * `tcbRecoveryEventDate`: (String - datetime) The date Intel first publishes related collateral (ISO 8601
          UTC)[cite: 179].
        * `tcbDate`: (String - datetime) TCB date (ISO 8601 UTC)[cite: 180, 181].
    * `signature`: (String) Base16-encoded signature over the structure's body[cite: 181].

---

## Appendix D: PCK Certificate and CRL Specification

This section refers to an external document that specifies the hierarchy and format of X.509 v3 certificates and X.509
v2 CRLs issued by Intel for Provisioning Certification Keys[cite: 181].

---

**Notes on TCB Status and Enforcement:**

* **Enforcement Grace Periods**: Intel provides "early" and "standard" update parameters, offering different enforcement
  grace periods[cite: 182]. The attestation result depends on which parameter is used[cite: 182].
* **Relying Party Trust Decisions**: Relying parties can use additional factors beyond the attestation result to make
  trust decisions[cite: 183]. They might accept risks even if a platform is technically "OutOfDate" due to low-severity
  issues[cite: 184].
* **Communication**: Intel aims to communicate planned deviations via email to registered API subscribers[cite: 185].
