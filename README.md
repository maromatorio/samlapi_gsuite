# samlapi_gsuite  

Simple Python script to get temporary AWS CLI role creds via STS, using Google (G Suite) as the SAML IdP.  Based off the [generic script provided by AWS](https://aws.amazon.com/blogs/security/how-to-implement-a-general-solution-for-federated-apicli-access-using-saml-2-0/), with additional credit to [Alky](https://github.com/jspc/alky) and [@ChrisRut for providing the proper auth workflow](https://github.com/jspc/alky/issues/1#issuecomment-288125555) since Google doesn't implement simple forms-based authentication.

## TODO
+ Investigate using [yubikey U2F](https://github.com/Yubico) instead of TOTP (not sure if possible yet)
+ Better error handling
+ Maybe move to something like [hologram](https://github.com/AdRoll/hologram), typing my gsuite password and TOTP code every hour is not ideal
