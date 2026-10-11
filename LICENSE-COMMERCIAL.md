# Commercial License for IronKeys

Copyright (C) 2026 NERVOSYS. All rights reserved.

## Dual licensing

IronKeys (the crate `ironkeys` and the crates under `crates/`) is available under two licences.

### 1. GNU Affero General Public License v3 (AGPL-3.0-or-later)

The default licence is the **GNU Affero General Public License v3**. Under it:

- You may use, copy, modify and distribute the software.
- If you modify it and make it available over a network, for example as a
  service, you **must** make the complete source of your modified version
  available to that service's users.
- Derivative works must also be licensed under the AGPL v3.
- Full text: [LICENSE](LICENSE).

Linking IronKeys into a service that signs or agrees with keys through it
makes that service a derivative work, and the AGPL's source-disclosure
obligation applies to it.

### 2. Commercial licence

A **commercial licence** is available from NERVOSYS if the AGPL does not fit
your use. For example, if you want to:

- integrate IronKeys into proprietary or closed-source software;
- embed it in a shipped product, firmware image or device;
- distribute it without disclosing your source code;
- run it in a hosted service without AGPL obligations;
- receive dedicated support, warranty or indemnification.

**The rest of the stack is licensed separately.** IronKeys signs, verifies
and hashes through [IronCrypto](https://github.com/nervosys/IronCrypto), and
its AWS KMS provider connects through
[IronSocketLayer](https://github.com/nervosys/IronSocketLayer). Both are also
AGPL-3.0-or-later with their own commercial options, so proprietary use of
IronKeys also needs a commercial IronCrypto licence and, with the `kms`
feature, an IronSocketLayer one. Ask for them together.

**Third-party material.** A PKCS#11 vendor module loaded at run time has its
own licence. The TLS trust-anchor data in `crates/ironkeys-kms/data` is
distributed under CDLA-Permissive-2.0, under either licence.

## Obtaining a commercial licence

- **Email**: licensing@nervosys.ai
- **GitHub**: [github.com/nervosys](https://github.com/nervosys)

## What a licence does not cover

Neither licence makes a claim about assurance:

- **No FIPS validation.** Neither IronKeys nor IronCrypto holds a CMVP
  certificate, and a commercial licence does not confer one.
- **No independent review.** See [SECURITY.md](SECURITY.md).
- **Warranty.** The AGPL version comes without warranty, as the licence
  states. Any warranty or indemnification is set out in the commercial
  agreement, not here.

**Export.** IronKeys calls cryptography and is subject to export controls.
Commercial distribution, as object code or as source that is not publicly
available, is not covered by a public-source notification under
15 CFR §742.15(b). It needs its own classification before any such
distribution.

## Contributor Licence Agreement

Contributors agree to the [Contributor License Agreement](CLA.md) before
their contributions are accepted. It lets contributions be distributed under
both the AGPL v3 and the commercial licence. See [CONTRIBUTING.md](CONTRIBUTING.md).
