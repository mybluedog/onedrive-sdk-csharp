﻿// ------------------------------------------------------------------------------
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

    using Microsoft.IdentityModel.Clients.ActiveDirectory;

    public class AuthenticationContextWrapper : IAuthenticationContextWrapper
    {
        private AuthenticationContext authenticationContext;

        public AuthenticationContextWrapper(string serviceUrl)
        {
            this.authenticationContext = new AuthenticationContext(serviceUrl);
        }

        public AuthenticationContextWrapper(string serviceUrl, bool validateAuthority, TokenCache tokenCache)
        {
            this.authenticationContext = new AuthenticationContext(serviceUrl, validateAuthority, tokenCache);
        }

        public async Task<IAuthenticationResult> AcquireTokenSilentAsync(string resource, string clientId)
        {
            var result = await this.authenticationContext.AcquireTokenSilentAsync(resource, clientId);

            return result == null ? null : new AuthenticationResultWrapper(result);
        }

        public async Task<IAuthenticationResult> AcquireTokenAsync(string resource, string clientId, Uri redirectUri)
        {
            var result = await this.authenticationContext.AcquireTokenAsync(resource, clientId, redirectUri);

            return result == null ? null : new AuthenticationResultWrapper(result);
        }
    }
}