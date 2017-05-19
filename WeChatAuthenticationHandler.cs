using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.WeChat.Provider;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Microsoft.Owin.Security.WeChat
{
    internal class WeChatAuthenticationHandler : AuthenticationHandler<WeChatAuthenticationOptions>
    {
        private const string AuthorizationUrlFormater = "https://open.weixin.qq.com/connect/oauth2/authorize";//"https://open.weixin.qq.com/connect/qrconnect?appid={0}&redirect_uri={1}&scope={2}&state={3}&response_type=code";
        private const string TokenUrl = "https://api.weixin.qq.com/sns/oauth2/access_token";
        private const string UserInfoUrlFormater = "https://api.weixin.qq.com/sns/userinfo?access_token={0}&openid={1}";
        private const string OpenIdUrl = "https://api.weixin.qq.com/sns/oauth2";
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;
        private static ConcurrentDictionary<string, string> States = new ConcurrentDictionary<string, string>();
        public WeChatAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            this._httpClient = httpClient;
            this._logger = logger;
        }

        public override async Task<bool> InvokeAsync()
        {
            if (Options.CallbackPath != null && string.Equals(Options.CallbackPath, Request.Path.Value, StringComparison.OrdinalIgnoreCase))
            {
                return await InvokeReturnPathAsync();
            }
            return false;
        }

        private async Task<bool> InvokeReturnPathAsync()
        {
            _logger.WriteVerbose("InvokeReturnPath");
            var model = await AuthenticateAsync();
            var context = new WeChatReturnEndpointContext(Context, model)
            {
                SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
                RedirectUri = model.Properties.RedirectUri
            };
            model.Properties.RedirectUri = null;
            await Options.Provider.ReturnEndpoint(context);
            if (context.SignInAsAuthenticationType != null && context.Identity != null)
            {
                ClaimsIdentity signInIdentity = context.Identity;
                if (!string.Equals(signInIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                {
                    signInIdentity = new ClaimsIdentity(signInIdentity.Claims, context.SignInAsAuthenticationType, signInIdentity.NameClaimType, signInIdentity.RoleClaimType);
                }
                Context.Authentication.SignIn(context.Properties, signInIdentity);
            }
            if (!context.IsRequestCompleted && context.RedirectUri != null)
            {
                Response.Redirect(context.RedirectUri);
                context.RequestCompleted();
            }
            return context.IsRequestCompleted;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            _logger.WriteVerbose("AuthenticateCore");
            AuthenticationProperties properties = null;
            try
            {
                string code = null;
                string state = null;
                string oauthState = null;
                IReadableStringCollection query = Request.Query;
                IList<string> values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }
                if (string.IsNullOrEmpty(code))
                {
                    // 用户未同意进行授权，不会返回 code
                    return null;
                }
                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    state = values[0];
                }
                if (string.IsNullOrEmpty(state))
                {
                    return null;
                }
                States.TryGetValue(state, out oauthState);
                properties = Options.StateDataFormat.Unprotect(oauthState);
                if (properties == null)
                {
                    return null;
                }
                if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }
                var tokenRequestParameters = new List<KeyValuePair<string, string>>()
                {
                    new KeyValuePair<string, string>("appid", Options.AppId),
                    new KeyValuePair<string, string>("secret", Options.AppSecret),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                };
                FormUrlEncodedContent requestContent = new FormUrlEncodedContent(tokenRequestParameters);
                HttpResponseMessage response = await _httpClient.PostAsync(TokenUrl, requestContent, Request.CallCancelled);
                response.EnsureSuccessStatusCode();
                var oauthTokenResponse = await response.Content.ReadAsStringAsync();
                var js = new JsonSerializer();
                AccessTokenResult tokenResult = js.Deserialize<AccessTokenResult>(new JsonTextReader(new System.IO.StringReader(oauthTokenResponse)));
                if (tokenResult == null || tokenResult.access_token == null)
                {
                    _logger.WriteWarning("Access token was not found");
                    return new AuthenticationTicket(null, properties);
                }
                var userInfoUri = string.Format(UserInfoUrlFormater, Uri.EscapeDataString(tokenResult.access_token), Uri.EscapeDataString(tokenResult.openid));
                HttpResponseMessage userInfoResponse = await _httpClient.GetAsync(userInfoUri, Request.CallCancelled);
                userInfoResponse.EnsureSuccessStatusCode();
                var userInfoString = await userInfoResponse.Content.ReadAsStringAsync();
                var userInfo = JObject.Parse(userInfoString);
                var context = new WeChatAuthenticatedContext(Context, tokenResult.openid, userInfo, tokenResult.access_token);
                context.Identity = new ClaimsIdentity(new[]{
                    new Claim(ClaimTypes.NameIdentifier, context.Id,XmlSchemaString,Options.AuthenticationType),
                    new Claim(ClaimsIdentity.DefaultNameClaimType, context.Name,XmlSchemaString,Options.AuthenticationType),
                    new Claim("urn:wechatconnect:id", context.Id,XmlSchemaString,Options.AuthenticationType),
                    new Claim("urn:wechatconnect:name", context.Name,XmlSchemaString,Options.AuthenticationType),
                });
                await Options.Provider.Authenticated(context);
                context.Properties = properties;
                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError(ex.Message);
            }
            return new AuthenticationTicket(null, properties);
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            _logger.WriteVerbose("ApplyResponseChallenge");
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }
            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
            if (challenge != null)
            {
                var requestPrefix = Request.Scheme + "://" + Request.Host;
                var currentQueryString = Request.QueryString.Value;
                var currentUri = string.IsNullOrEmpty(currentQueryString)? requestPrefix + Request.PathBase + Request.Path: requestPrefix + Request.PathBase + Request.Path + "?" + currentQueryString;
                var redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;
                AuthenticationProperties properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = currentUri;
                }
                GenerateCorrelationId(properties);
                var scope = string.Join(",", Options.Scope);
                //加密OAuth状态-因为微信State限制长度为128  所以这里采用 特别的方式 将 加密后的Oauth状态存储起来 正式环境 考虑用分布式缓存
                var state = Guid.NewGuid().ToString();
                States.TryAdd(state, Options.StateDataFormat.Protect(properties));
                var authorizationUrl = $"{AuthorizationUrlFormater}?appid={Options.AppId}&redirect_uri={redirectUri}&scope={scope}&state={state}&response_type=code";
                Response.Redirect(authorizationUrl);
            }
            return Task.FromResult<object>(null);
        }

        private string GenerateRedirectUri()
        {
            var requestPrefix = Request.Scheme + "://" + Request.Host;
            var redirectUri = requestPrefix + RequestPathBase + Options.CallbackPath;
            return redirectUri;
        }

        [Serializable]
        public class AccessTokenResult
        {
            public string errcode { get; set; }

            public string errmsg { get; set; }

            public string access_token { get; set; }

            public string expires_in { get; set; }

            public string refresh_token { get; set; }

            public string openid { get; set; }

            public string scope { get; set; }
        }
    }
}
