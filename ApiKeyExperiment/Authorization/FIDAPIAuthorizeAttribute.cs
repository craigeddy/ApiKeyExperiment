using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;

namespace ApiKeyExperiment.Authorization
{
    public class FIDAPIAuthorizeAttribute : AuthorizeAttribute
    {
        public override void OnAuthorization(System.Web.Http.Controllers.HttpActionContext actionContext)
        {
            if (Authorize(actionContext))
            {
                return;
            }
            HandleUnauthorizedRequest(actionContext);
        }

        protected override void HandleUnauthorizedRequest(System.Web.Http.Controllers.HttpActionContext actionContext)
        {
            var challengeMessage = new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.Unauthorized);
            challengeMessage.Headers.Add("WWW-Authenticate", "Basic");
            throw new HttpResponseException(challengeMessage);
        }

        private bool Authorize(System.Web.Http.Controllers.HttpActionContext actionContext)
        {
            try
            {
                if (actionContext.Request.Headers.TryGetValues("X-Api-Key", out var apiKeyHeaderValues))
                {
                    var apiKeyHeaderValue = apiKeyHeaderValues.First();

                    // ... your authentication logic here ...
                    var username = (apiKeyHeaderValue == "12345" ? "Maarten" : "OtherUser");
                    var scopeClaim = new Claim("scope", "dis_read dis_write","String", "craig");
                    var usernameClaim = new Claim(ClaimTypes.Name, username);
                    var identity = new ClaimsIdentity(new[] { usernameClaim, scopeClaim }, "ApiKey");
                    var principal = new ClaimsPrincipal(identity);

                    Thread.CurrentPrincipal = principal;
                    actionContext.ControllerContext.RequestContext.Principal = principal;
                    return true;
                }
            }
            catch (Exception)
            {
            }
            return false;

        }
    }
}