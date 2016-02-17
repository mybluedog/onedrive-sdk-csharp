// ------------------------------------------------------------------------------
//  Copyright (c) 2015 Microsoft Corporation
// 
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
// 
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
// 
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
// ------------------------------------------------------------------------------

namespace Microsoft.OneDrive.Sdk
{
    using System;
    using System.Threading.Tasks;

    using IdentityModel.Clients.ActiveDirectory;

    /// <summary>
    /// Authenticates an application by retrieving an access token using a provided refresh token.
    /// </summary>
    public class AdalAuthenticationByRefreshTokenAuthenticationProvider : AdalAuthenticationProviderBase
    {
        internal string refreshToken;

        /// <summary>
        /// Constructs an <see cref="AdalAuthenticationByRefreshTokenAuthenticationProvider"/> for use with web apps that perform their own initial login
        /// and already have a refresh token for receiving an access token.
        /// </summary>
        /// <param name="serviceInfo">The information for authenticating against the service.</param>
        /// <param name="refreshToken">The refresh token for retrieving the access token.</param>
        public AdalAuthenticationByRefreshTokenAuthenticationProvider(
            ServiceInfo serviceInfo,
            string refreshToken)
            : base(serviceInfo, currentAccountSession: null)
        {
            if (string.IsNullOrEmpty(refreshToken))
            {
                throw new OneDriveException(
                    new Error
                    {
                        Code = OneDriveErrorCode.AuthenticationFailure.ToString(),
                        Message = "Refresh token is required for authentication by refresh token.",
                    });
            }

            this.allowDiscoveryService = false;
            this.refreshToken = refreshToken;
        }

        /// <summary>
        /// Retrieves an authentication result for the specified resource.
        /// </summary>
        /// <param name="resource">The resource to authenticate.</param>
        /// <returns>The <see cref="IAuthenticationResult"/> returned for the resource.</returns>
        protected override async Task<IAuthenticationResult> AuthenticateResourceAsync(string resource)
        {
            IAuthenticationResult authenticationResult = null;

            try
            {
                var adalServiceInfo = this.ServiceInfo as AdalServiceInfo;

                // If we have a client certificate authenticate using it. Use client secret authentication if not.
                if (adalServiceInfo != null && adalServiceInfo.ClientCertificate != null)
                {
                    authenticationResult = await this.AuthenticateUsingCertificate(adalServiceInfo, resource);
                }
                else if (!string.IsNullOrEmpty(serviceInfo.ClientSecret))
                {
                    authenticationResult = await this.AuthenticateUsingClientSecret(resource);
                }
                else
                {
                    authenticationResult = await this.authenticationContextWrapper.AcquireTokenByRefreshTokenAsync(
                        this.refreshToken,
                        this.serviceInfo.AppId,
                        resource);
                }
            }
            catch (AdalException adalException)
            {
                throw this.GetAuthenticationException(string.Equals(adalException.ErrorCode, Constants.Authentication.AuthenticationCancelled), adalException);
            }
            catch (OneDriveException)
            {
                // If authentication threw a OneDriveException assume we already handled it and let it bubble up.
                throw;
            }
            catch (Exception exception)
            {
                throw this.GetAuthenticationException(false, exception);
            }

            if (authenticationResult == null)
            {
                throw this.GetAuthenticationException();
            }

            return authenticationResult;
        }

        private Task<IAuthenticationResult> AuthenticateUsingCertificate(AdalServiceInfo adalServiceInfo, string resource)
        {
            var clientAssertionCertificate = new ClientAssertionCertificate(adalServiceInfo.AppId, adalServiceInfo.ClientCertificate);

            return this.authenticationContextWrapper.AcquireTokenByRefreshTokenAsync(
                this.refreshToken,
                clientAssertionCertificate,
                resource);
        }

        private Task<IAuthenticationResult> AuthenticateUsingClientSecret(string resource)
        {
            var clientCredential = this.GetClientCredentialForAuthentication();
            
            return this.authenticationContextWrapper.AcquireTokenByRefreshTokenAsync(
                    this.refreshToken,
                    clientCredential,
                    resource);
        }
    }
}
