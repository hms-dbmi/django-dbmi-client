## [2.4.1](https://github.com/hms-dbmi/django-dbmi-client/compare/v2.4.0...v2.4.1) (2025-07-26)


### Bug Fixes

* **authn:** Fixed issue where user syncing was not removing staff/superuser status if those permissions were removed from the authorization server ([0ce1ba6](https://github.com/hms-dbmi/django-dbmi-client/commit/0ce1ba6113e28e1a311f0598648356ec0dc02a54))

# [2.4.0](https://github.com/hms-dbmi/django-dbmi-client/compare/v2.3.1...v2.4.0) (2024-08-30)


### Features

* **logging:** Setup a filter to hide Sentry trace/profile transactions ([7004f7f](https://github.com/hms-dbmi/django-dbmi-client/commit/7004f7ff968871a9eaa95a2d73d3771b665bdb85))

## [2.3.1](https://github.com/hms-dbmi/django-dbmi-client/compare/v2.3.0...v2.3.1) (2024-08-19)


### Bug Fixes

* **provider:** Fixed an issue where client IDs would sometimes lose case and could not be fetched from auth providers dictionary correctly ([c3ab1e3](https://github.com/hms-dbmi/django-dbmi-client/commit/c3ab1e3e89bd0df33258f6557f7f18f64e364f94))

# [2.3.0](https://github.com/hms-dbmi/django-dbmi-client/compare/v2.2.0...v2.3.0) (2024-08-06)


### Features

* **logging:** Added option to configure other loggers' log levels; improved logging on some authentication errors ([8c4b40e](https://github.com/hms-dbmi/django-dbmi-client/commit/8c4b40e5a364c2574172ff1711604e16a32f7f47))

# [2.2.0](https://github.com/hms-dbmi/django-dbmi-client/compare/v2.1.0...v2.2.0) (2024-07-18)


### Features

* **reporting:** Refactored method signature to allow passing environment ([91fb2b9](https://github.com/hms-dbmi/django-dbmi-client/commit/91fb2b9a583f53a9beaa9900b640a50f6f9bbc48))

# [2.1.0](https://github.com/hms-dbmi/django-dbmi-client/compare/v2.0.0...v2.1.0) (2024-07-18)


### Features

* **reporting:** Added release version to Sentry initialization; sets environment ([82adc67](https://github.com/hms-dbmi/django-dbmi-client/commit/82adc67534b7a0af6a2064eba73d965cfbc3c28f))

# [2.0.0](https://github.com/hms-dbmi/django-dbmi-client/compare/v1.1.2...v2.0.0) (2024-07-15)


* chore(reporting)!: Removed old Sentry and associated configurations ([f5fcb6b](https://github.com/hms-dbmi/django-dbmi-client/commit/f5fcb6be497e4b3eeb995393ad879b4cc447eab2))


### BREAKING CHANGES

* Sentry configurations have been moved

## [1.1.2](https://github.com/hms-dbmi/django-dbmi-client/compare/v1.1.1...v1.1.2) (2024-07-15)


### Bug Fixes

* **environment:** Added a method to fetch a float from environment ([c69f5a8](https://github.com/hms-dbmi/django-dbmi-client/commit/c69f5a823650c2e6e7c25afc841fedeb41e8d187))

## [1.1.1](https://github.com/hms-dbmi/django-dbmi-client/compare/v1.1.0...v1.1.1) (2024-07-15)


### Bug Fixes

* **reporting:** Refactored Sentry configuration method ([88033da](https://github.com/hms-dbmi/django-dbmi-client/commit/88033daaa9d667e9165b695cd8128abcd4115c81))

# [1.1.0](https://github.com/hms-dbmi/django-dbmi-client/compare/v1.0.8...v1.1.0) (2024-07-15)


### Features

* **reporting:** Added a module for configuring reporting via Sentry ([b16338e](https://github.com/hms-dbmi/django-dbmi-client/commit/b16338eab8859bd5c14b6685626506fbe9e064d0))

## [1.0.8](https://github.com/hms-dbmi/django-dbmi-client/compare/v1.0.7...v1.0.8) (2024-03-18)


### Bug Fixes

* **dependencies:** Added 'pytz' to required dependencies ([1960cb5](https://github.com/hms-dbmi/django-dbmi-client/commit/1960cb5d5cbef42d6428747e93a1327acc74c4c6))

## [1.0.7](https://github.com/hms-dbmi/django-dbmi-client/compare/v1.0.6...v1.0.7) (2023-05-25)


### Bug Fixes

* **login:** Fixed again for missing state ([f265ccb](https://github.com/hms-dbmi/django-dbmi-client/commit/f265ccb40b1d3d28340cc421755989d32205a3a6))

## [1.0.6](https://github.com/hms-dbmi/django-dbmi-client/compare/v1.0.5...v1.0.6) (2023-05-24)


### Bug Fixes

* **login:** Fixed bug in accessing query parameters of request ([67f09b1](https://github.com/hms-dbmi/django-dbmi-client/commit/67f09b1dd710b7b8cac2098274d5d2f69449aef3))

## [1.0.5](https://github.com/hms-dbmi/django-dbmi-client/compare/v1.0.4...v1.0.5) (2023-05-24)


### Bug Fixes

* **login:** Fixed issue where no state broke client ID retrieval ([35a3e7a](https://github.com/hms-dbmi/django-dbmi-client/commit/35a3e7a4eacbc4be6983d596bc1f79998e873509))

## [1.0.4](https://github.com/hms-dbmi/django-dbmi-client/compare/v1.0.3...v1.0.4) (2023-05-24)


### Bug Fixes

* **login:** Removed state check when not used for refreshes and impersonations ([5b22163](https://github.com/hms-dbmi/django-dbmi-client/commit/5b22163421f1f17fa932fe84a68362c542f904f6))

## [1.0.3](https://github.com/hms-dbmi/django-dbmi-client/compare/v1.0.2...v1.0.3) (2023-02-08)


### Bug Fixes

* **authn:** Fixed failure to check JWTs signed by invalid client IDs ([a230862](https://github.com/hms-dbmi/django-dbmi-client/commit/a230862b8582a71df81083d8093236aff29aa97c))

## [1.0.2](https://github.com/hms-dbmi/django-dbmi-client/compare/v1.0.1...v1.0.2) (2022-11-30)


### Bug Fixes

* **authn/auth/login:** Minor tweaks; added methods for extracting groups from JWT, if enabled ([0c4b894](https://github.com/hms-dbmi/django-dbmi-client/commit/0c4b8945c37b1c78ebfdfdf6c5542c78a25868e2))

## [1.0.1](https://github.com/hms-dbmi/django-dbmi-client/compare/v1.0.0...v1.0.1) (2022-10-05)


### Bug Fixes

* **authn:** Fixed RS256 verification ([edb4166](https://github.com/hms-dbmi/django-dbmi-client/commit/edb416622b77da2d3fb659393b35a1d44b4bd1da))
* **login:** Fixed state check; fixed logout ([d031315](https://github.com/hms-dbmi/django-dbmi-client/commit/d031315f9f1769b7cfaf8ae966b2b94c0a020a5d))

# [1.0.0](https://github.com/hms-dbmi/django-dbmi-client/compare/v0.5.4...v1.0.0) (2022-10-05)


### Bug Fixes

* **requirements:** Updated requirements ([d844104](https://github.com/hms-dbmi/django-dbmi-client/commit/d844104f3844bef5020bf93ac3701feaab178acf))


### Features

* **login:** Improved login app; updated for different auth providers ([64c4957](https://github.com/hms-dbmi/django-dbmi-client/commit/64c49579b70af3caf4684b6f6d940a94d2659f68))
* **settings:** Improved settings to remove auth provider specific settings ([9a2000a](https://github.com/hms-dbmi/django-dbmi-client/commit/9a2000a7ac77a891020757fea5f424afb443ad8c))


### BREAKING CHANGES

* **login:** Changed login URLs

Login app was updated for improved auth routines. URLs were changed to reflect convention on OAuth2 endpoints.
* **settings:** Settings changes

All Auth0 settings have been removed and replaced with a generic setting AUTH_CLIENTS that contains dictionaries of auth provider configurations.

## [0.5.4](https://github.com/hms-dbmi/django-dbmi-client/compare/v0.5.3...v0.5.4) (2022-09-28)


### Bug Fixes

* **middleware:** DBMISVC-101 - Improved middleware compatibility with other auth middlewares/backends ([c07f14f](https://github.com/hms-dbmi/django-dbmi-client/commit/c07f14f2cead14b4bf2a6e11d6df7893ba6b229d))

## [0.5.3](https://github.com/hms-dbmi/django-dbmi-client/compare/v0.5.2...v0.5.3) (2022-09-28)


### Bug Fixes

* **django:** Fixed to support Django 4.x ([fac5575](https://github.com/hms-dbmi/django-dbmi-client/commit/fac5575c5cc323625cc95d0d642dc00238444475))

## [0.5.2](https://github.com/hms-dbmi/django-dbmi-client/compare/v0.5.1...v0.5.2) (2022-08-04)


### Bug Fixes

* **authn:** Fixed method to get JWT payload without verifying aud ([aad5cae](https://github.com/hms-dbmi/django-dbmi-client/commit/aad5caee8717c09bba5699d05df10a53f11db970))

## [0.5.1](https://github.com/hms-dbmi/django-dbmi-client/compare/v0.5.0...v0.5.1) (2022-06-01)


### Bug Fixes

* **authn:** DBMISVC-118 - Fixed decode usage ([e90bcc8](https://github.com/hms-dbmi/django-dbmi-client/commit/e90bcc899acf8cc0040869c3d812d5fdf3223a20))

# [0.5.0](https://github.com/hms-dbmi/django-dbmi-client/compare/v0.4.7...v0.5.0) (2022-06-01)


### Bug Fixes

* **authn:** DBMISVC-118 - Updated HS256 decoding process ([4d7da02](https://github.com/hms-dbmi/django-dbmi-client/commit/4d7da029403987ed18fd400b9af0161cd451b5df))


### Features

* **authn:** DBMISVC-118 - Updated to current version of PyJWT ([ee68f79](https://github.com/hms-dbmi/django-dbmi-client/commit/ee68f794695e42e99ff50c8f0f076002768a5c9b))

## [0.4.7](https://github.com/hms-dbmi/django-dbmi-client/compare/v0.4.6...v0.4.7) (2022-05-09)


### Bug Fixes

* **authn:** Resolved issue with decoding non-existent JWTs ([cbb84c2](https://github.com/hms-dbmi/django-dbmi-client/commit/cbb84c24da4814d376bab10ebec0f9221379d251))

## [0.4.6](https://github.com/hms-dbmi/django-dbmi-client/compare/v0.4.5...v0.4.6) (2021-10-17)


### Bug Fixes

* **authn:** PPM-729 - Fixed issue where session users were being logged in with every request, constantly resetting the CSRF tokens; minor logging tweaks ([25f3778](https://github.com/hms-dbmi/django-dbmi-client/commit/25f3778bf2455028cdac186742ac928276233fb0))

## [0.4.5](https://github.com/hms-dbmi/django-dbmi-client/compare/v0.4.4...v0.4.5) (2021-07-02)


### Bug Fixes

* **requirements:** Set to only install pyJWT up to v2.x due to breaking changes introduced in v2 ([0dd4043](https://github.com/hms-dbmi/django-dbmi-client/commit/0dd4043aba8a620b475b0ae308b6b7e785169412))

# Changelog

<!--next-version-placeholder-->

## [0.4.4](https://github.com/hms-dbmi/django-dbmi-client/compare/v0.4.3...v0.4.4) (2021-02-26)


### Bug Fixes

* **auth:** PPM-690 - Fixed managin AJAX 401s/403s based on method ([4234f67](https://github.com/hms-dbmi/django-dbmi-client/commit/4234f6749102b23640419a4bc8c52e06283d97b2))

## [0.4.3](https://github.com/hms-dbmi/django-dbmi-client/compare/v0.4.2...v0.4.3) (2021-02-21)


### Bug Fixes

* **authn/support:** PPM-690 - Fixed 401s for AJAX; fixed Support email send ([a8e46bb](https://github.com/hms-dbmi/django-dbmi-client/commit/a8e46bb0e424e91b28b3c83a09a04c669d517885))

chore(release): 0.4.2 [skip ci]

## [0.4.2](https://github.com/hms-dbmi/django-dbmi-client/compare/v0.4.1...v0.4.2) (2021-02-13)


### Bug Fixes

* **support:** DBMISVC-94 - Added improved error reporting on support methods ([c854fb6](https://github.com/hms-dbmi/django-dbmi-client/commit/c854fb6e3e0edb4cae1d6a648851c4a50ce8e6c5))

## [0.4.1](https://github.com/hms-dbmi/django-dbmi-client/compare/v0.4.0...v0.4.1) (2021-02-13)
### Bug Fixes

* **support:** DBMISVC-94 - Added Jira Service Desk integration ([`1d37d16`](https://github.com/hms-dbmi/django-dbmi-client/commit/1d37d165dbf1b36e956d09d226350e81d2906e25))

# [0.4.0](https://github.com/hms-dbmi/django-dbmi-client/compare/v0.3.17...v0.4.0) (2021-01-27)


### Features

* **authn:** DBMISVC-92 - Updated to use Auth0 Universal login ([96f84e4](https://github.com/hms-dbmi/django-dbmi-client/commit/96f84e4b7dfed3bceae1611eca6dbf0430ee69ae))

## [0.3.17](https://github.com/hms-dbmi/django-dbmi-client/compare/v0.3.16...v0.3.17) (2020-10-30)


### Bug Fixes

* **authn/authz:** Fixed some Auth backends; fixed middleware method call; improved flexibility of authentication backends ([87df955](https://github.com/hms-dbmi/django-dbmi-client/commit/87df9558225475527b4c906fe2fb71221b88a9d6))

## [0.3.16](https://github.com/hms-dbmi/django-dbmi-client/compare/v0.3.15...v0.3.16) (2020-10-15)


### Bug Fixes

* **authz:** Removed unecessary logging statements ([2007551](https://github.com/hms-dbmi/django-dbmi-client/commit/2007551af43342d5b526f5ba71c7c771e239c688))

## [0.3.15](https://github.com/hms-dbmi/django-dbmi-client/compare/v0.3.14...v0.3.15) (2020-10-05)


### Bug Fixes

* **reg:** Fixed the get_dbmi_user method; CI/CD rework ([0cb1842](https://github.com/hms-dbmi/django-dbmi-client/commit/0cb184271b15a7edc7b1dd01f6713475b2e5d865))

## [0.3.15-rc.1](https://github.com/hms-dbmi/django-dbmi-client/compare/v0.3.14...v0.3.15-rc.1) (2020-10-05)


### Bug Fixes

* **reg:** Fixed the get_dbmi_user method; CI/CD rework ([0cb1842](https://github.com/hms-dbmi/django-dbmi-client/commit/0cb184271b15a7edc7b1dd01f6713475b2e5d865))
