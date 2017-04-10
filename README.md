# samlapi_gsuite  

Simple Python script to get temporary AWS CLI role creds via STS, using Google (G Suite) as the SAML IdP.  Based off the [generic script provided by AWS](https://aws.amazon.com/blogs/security/how-to-implement-a-general-solution-for-federated-apicli-access-using-saml-2-0/), with additional credit to [@ChrisRut for figuring out the proper workflow](https://github.com/jspc/alky/issues/1#issuecomment-288125555) since Google doesn't implement simple forms-based auth.

## TODO
+ Investigate using yubikey U2F instead of TOTP (not sure if possible yet)
+ Additional validation, better error handling
